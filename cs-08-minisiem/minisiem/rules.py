"""Sigma-like detection rules: load YAML, validate, compile to SQL.

A rule file looks like:

    id: ssh-brute-force
    title: ...
    severity: high            # low | medium | high | critical
    detection:
      selection:              # field[|modifier]: value or [values]  (AND across fields)
        action: login
        outcome: failure
      filter:
        src_ip|startswith: "10."
      condition: selection and not filter
      threshold:              # optional: aggregate matching events
        group_by: src_ip
        count: 8
        window: 5m
        distinct: user        # optional: count distinct values instead of events
    tests: [...]              # sample log lines the rule must / must not fire on
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

from .db import EVENT_FIELDS, SEVERITIES

MODIFIERS = {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte"}
NUMERIC_OPS = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
RESERVED = {"condition", "threshold", "and", "or", "not", "of", "all", "1"}
TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")
WINDOW_RE = re.compile(r"^(\d+)([smhd])$")
UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class RuleError(ValueError):
    """A rule file is invalid. The message names the file and the problem."""


@dataclass(frozen=True)
class Threshold:
    group_by: tuple[str, ...]
    count: int
    window: timedelta
    distinct: str | None = None


@dataclass
class RuleTest:
    name: str
    source: str
    lines: list[str]
    alerts: int


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str
    tags: list[str]
    where: str
    params: list
    threshold: Threshold | None
    tests: list[RuleTest] = field(default_factory=list)
    path: str = ""


def parse_window(text: str) -> timedelta:
    m = WINDOW_RE.match(str(text).strip())
    if not m or int(m[1]) == 0:
        raise RuleError(f"bad window {text!r}; use e.g. 30s, 5m, 1h, 1d")
    return timedelta(**{UNITS[m[2]]: int(m[1])})


def _one_value(name: str, mod: str, value) -> tuple[str, list]:
    """SQL for a single field/modifier/value. NULL results are coerced to false so
    that `not` over a NULL column behaves like a plain negation."""
    col = name
    if mod in ("contains", "startswith", "endswith", "re"):
        if not isinstance(value, str) or value == "":
            raise RuleError(f"{name}|{mod} needs a non-empty string, got {value!r}")
        if mod == "contains":
            return f"COALESCE(instr(lower({col}), lower(?)) > 0, 0)", [value]
        if mod == "startswith":
            return (
                f"COALESCE(lower(substr({col}, 1, ?)) = lower(?), 0)",
                [len(value), value],
            )
        if mod == "endswith":
            return (
                f"COALESCE(lower(substr({col}, ?)) = lower(?), 0)",
                [-len(value), value],
            )
        try:
            re.compile(value)
        except re.error as exc:
            raise RuleError(f"{name}|re: invalid regex {value!r}: {exc}") from exc
        return f"COALESCE(regexp(?, {col}), 0)", [value]
    if mod in NUMERIC_OPS:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RuleError(f"{name}|{mod} needs a number, got {value!r}")
        return f"COALESCE({col} {NUMERIC_OPS[mod]} ?, 0)", [value]
    if value is None:
        return f"{col} IS NULL", []
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise RuleError(f"{name}: unsupported value {value!r}")
    if isinstance(value, str):
        return f"COALESCE({col} = ? COLLATE NOCASE, 0)", [value]
    return f"COALESCE({col} = ?, 0)", [value]


def _compile_field(spec: str, value) -> tuple[str, list]:
    name, _, mod = str(spec).partition("|")
    if name not in EVENT_FIELDS:
        raise RuleError(
            f"unknown field {name!r}; valid fields: {', '.join(EVENT_FIELDS)}"
        )
    if mod and mod not in MODIFIERS:
        raise RuleError(f"unknown modifier {mod!r}; valid: {sorted(MODIFIERS)}")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise RuleError(f"{spec}: empty value list")
    parts, params = [], []
    for v in values:
        sql, p = _one_value(name, mod, v)
        parts.append(sql)
        params += p
    return "(" + " OR ".join(parts) + ")", params


def _compile_selection(name: str, body) -> tuple[str, list]:
    maps = body if isinstance(body, list) else [body]
    ors, params = [], []
    for m in maps:
        if not isinstance(m, dict) or not m:
            raise RuleError(f"selection {name!r} must be a mapping of field: value")
        ands = []
        for spec, value in m.items():
            sql, p = _compile_field(spec, value)
            ands.append(sql)
            params += p
        ors.append("(" + " AND ".join(ands) + ")")
    return "(" + " OR ".join(ors) + ")", params


class _Cond:
    """Recursive-descent parser: or > and > not > atom, plus `1 of x*` / `all of x*`."""

    def __init__(self, text: str, sels: dict[str, tuple[str, list]]):
        self.tokens = TOKEN_RE.findall(text)
        self.pos = 0
        self.sels = sels
        self.text = text

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise RuleError(f"condition {self.text!r} ended unexpectedly")
        self.pos += 1
        return tok

    def parse(self) -> tuple[str, list]:
        out = self.or_expr()
        if self.peek() is not None:
            raise RuleError(f"condition {self.text!r}: unexpected {self.peek()!r}")
        return out

    def or_expr(self):
        left = self.and_expr()
        while (self.peek() or "").lower() == "or":
            self.take()
            right = self.and_expr()
            left = (f"({left[0]} OR {right[0]})", left[1] + right[1])
        return left

    def and_expr(self):
        left = self.not_expr()
        while (self.peek() or "").lower() == "and":
            self.take()
            right = self.not_expr()
            left = (f"({left[0]} AND {right[0]})", left[1] + right[1])
        return left

    def not_expr(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            sql, params = self.not_expr()
            return f"(NOT {sql})", params
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok == "(":
            out = self.or_expr()
            if self.take() != ")":
                raise RuleError(f"condition {self.text!r}: missing ')'")
            return out
        if tok.lower() in ("1", "all") and (self.peek() or "").lower() == "of":
            self.take()
            pattern = self.take()
            names = [n for n in self.sels if fnmatch.fnmatch(n, pattern)]
            if not names:
                raise RuleError(f"condition: no selection matches {pattern!r}")
            glue = " OR " if tok == "1" else " AND "
            sql = "(" + glue.join(self.sels[n][0] for n in names) + ")"
            return sql, [p for n in names for p in self.sels[n][1]]
        if tok not in self.sels:
            raise RuleError(
                f"condition uses unknown selection {tok!r}; defined: {list(self.sels)}"
            )
        return self.sels[tok]


def _parse_threshold(body: dict) -> Threshold:
    if not isinstance(body, dict):
        raise RuleError("threshold must be a mapping")
    group = body.get("group_by")
    groups = [group] if isinstance(group, str) else group
    if not groups or not all(isinstance(g, str) for g in groups):
        raise RuleError("threshold.group_by must be a field name or list of names")
    for g in groups:
        if g not in EVENT_FIELDS:
            raise RuleError(f"threshold.group_by: unknown field {g!r}")
    count = body.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise RuleError("threshold.count must be an integer >= 1")
    distinct = body.get("distinct")
    if distinct is not None and distinct not in EVENT_FIELDS:
        raise RuleError(f"threshold.distinct: unknown field {distinct!r}")
    return Threshold(
        tuple(groups), count, parse_window(body.get("window", "")), distinct
    )


def _parse_tests(raw) -> list[RuleTest]:
    tests = []
    for i, t in enumerate(raw or []):
        if not isinstance(t, dict):
            raise RuleError(f"tests[{i}] must be a mapping")
        lines, alerts = t.get("lines"), t.get("alerts")
        if t.get("source") not in ("auth", "syslog", "nginx"):
            raise RuleError(f"tests[{i}].source must be auth, syslog or nginx")
        if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
            raise RuleError(f"tests[{i}].lines must be a list of strings")
        if isinstance(alerts, bool) or not isinstance(alerts, int) or alerts < 0:
            raise RuleError(f"tests[{i}].alerts must be an integer >= 0")
        tests.append(
            RuleTest(str(t.get("name", f"test {i}")), t["source"], lines, alerts)
        )
    return tests


def parse_rule(text: str, path: str = "<string>") -> Rule:
    try:
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict):
            raise RuleError("rule must be a YAML mapping")
        for key in ("id", "title", "severity", "detection"):
            if key not in doc:
                raise RuleError(f"missing required key {key!r}")
        rid = str(doc["id"])
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", rid):
            raise RuleError(f"id {rid!r} must be lowercase letters, digits, dashes")
        if doc["severity"] not in SEVERITIES:
            raise RuleError(f"severity must be one of {SEVERITIES}")
        det = doc["detection"]
        if not isinstance(det, dict) or "condition" not in det:
            raise RuleError("detection needs selections and a 'condition'")
        sels = {}
        for name, body in det.items():
            if name in RESERVED:
                continue
            sels[name] = _compile_selection(name, body)
        if not sels:
            raise RuleError("detection defines no selections")
        where, params = _Cond(str(det["condition"]), sels).parse()
        threshold = _parse_threshold(det["threshold"]) if "threshold" in det else None
        tags = doc.get("tags") or []
        return Rule(
            id=rid,
            title=str(doc["title"]),
            severity=doc["severity"],
            description=str(doc.get("description", "")).strip(),
            tags=[str(t) for t in tags],
            where=where,
            params=params,
            threshold=threshold,
            tests=_parse_tests(doc.get("tests")),
            path=path,
        )
    except RuleError as exc:
        raise RuleError(f"{path}: {exc}") from None
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from None


def load_rules(directory: str | Path) -> list[Rule]:
    """Load every *.yml in a directory; ids must be unique."""
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for p in sorted(Path(directory).glob("*.yml")):
        rule = parse_rule(p.read_text(encoding="utf-8"), str(p))
        if rule.id in seen:
            raise RuleError(
                f"{p}: duplicate rule id {rule.id!r} (also in {seen[rule.id]})"
            )
        seen[rule.id] = str(p)
        rules.append(rule)
    return rules

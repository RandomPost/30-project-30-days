"""Lockfile parsers: text in, `Dep`s out. Pure, no I/O."""

from __future__ import annotations

import json
import re
import tomllib

from .models import Dep

REQ_LINE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#\\]+)"
)


def parse_requirements(text: str, source: str = "") -> list[Dep]:
    """Only exact `name==version` pins can be checked; ranges are skipped."""
    deps = []
    for line in text.splitlines():
        m = REQ_LINE.match(line.strip())
        if m:
            deps.append(Dep(m.group(1), m.group(2), "PyPI", source))
    return deps


def parse_poetry_lock(text: str, source: str = "") -> list[Dep]:
    data = tomllib.loads(text)
    return [
        Dep(p["name"], p["version"], "PyPI", source)
        for p in data.get("package", [])
        if "name" in p and "version" in p
    ]


def parse_package_lock(text: str, source: str = "") -> list[Dep]:
    data = json.loads(text)
    deps: dict[tuple[str, str], Dep] = {}
    for path, info in data.get("packages", {}).items():  # lockfile v2/v3
        if not path:
            continue  # the root project itself
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        if info.get("version") and not info.get("link"):
            deps[(name, info["version"])] = Dep(name, info["version"], "npm", source)
    if not deps:  # lockfile v1 nests "dependencies"
        _walk_v1(data.get("dependencies", {}), deps, source)
    return list(deps.values())


def _walk_v1(tree: dict, out: dict[tuple[str, str], Dep], source: str) -> None:
    for name, info in tree.items():
        if info.get("version"):
            out[(name, info["version"])] = Dep(name, info["version"], "npm", source)
        _walk_v1(info.get("dependencies", {}), out, source)


def parse_lockfile(filename: str, text: str) -> list[Dep]:
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if base == "poetry.lock":
        return parse_poetry_lock(text, filename)
    if base == "package-lock.json":
        return parse_package_lock(text, filename)
    if base.endswith(".txt"):
        return parse_requirements(text, filename)
    raise ValueError(f"unsupported lockfile: {filename}")

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from netgen.models import Inventory


class SourceError(Exception):
    """Raised with a readable, multi-line message when the YAML is unusable."""


def format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        msg = err["msg"].removeprefix("Value error, ")
        lines.append(f"{loc}: {msg}")
    return "\n".join(lines)


def parse(text: str) -> Inventory:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SourceError(f"YAML syntax error: {exc}") from exc
    if not isinstance(raw, dict):
        raise SourceError("source of truth must be a mapping with a 'sites' key")
    try:
        return Inventory.model_validate(raw)
    except ValidationError as exc:
        raise SourceError(format_validation_error(exc)) from exc


def load(path: Path) -> Inventory:
    return parse(Path(path).read_text())

"""devices.yml and credentials.

Credentials come from the environment only. The file schema has no field for them
and rejects any key that looks like one, so a password cannot be committed by
accident."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

USER_VAR = "CONFDRIFT_USER"
PASSWORD_VAR = "CONFDRIFT_PASSWORD"
SECRET_KEYS = ("password", "passwd", "secret", "token", "key", "credential")


class ConfigError(Exception):
    pass


class Device(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    host: str
    device_type: str = "linux"  # any Netmiko device_type
    command: str = "vtysh -c 'show running-config'"
    port: int = Field(default=22, ge=1, le=65535)


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intended: Path  # a netgen source-of-truth YAML; device names must match
    backups: Path = Path("backups")
    devices: list[Device]

    @model_validator(mode="after")
    def _unique(self) -> "Config":
        names = [d.name for d in self.devices]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"duplicate device names {dupes}")
        return self


def _reject_secrets(node, where="devices file") -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if any(word in str(k).lower() for word in SECRET_KEYS):
                raise ConfigError(
                    f"{where}: key {k!r} looks like a credential. Credentials are "
                    f"read from {USER_VAR} and {PASSWORD_VAR}, never from files."
                )
            _reject_secrets(v, where)
    elif isinstance(node, list):
        for v in node:
            _reject_secrets(v, where)


def load_config(path: Path) -> Config:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text())
    except FileNotFoundError:
        raise ConfigError(f"{path} not found") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: YAML syntax error: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping")
    _reject_secrets(raw, str(path))
    try:
        cfg = Config.model_validate(raw)
    except ValidationError as exc:
        lines = [
            f"{'.'.join(map(str, e['loc']))}: {e['msg'].removeprefix('Value error, ')}"
            for e in exc.errors()
        ]
        raise ConfigError(f"{path}:\n  " + "\n  ".join(lines)) from exc
    base = path.parent
    if not cfg.intended.is_absolute():
        cfg.intended = base / cfg.intended
    if not cfg.backups.is_absolute():
        cfg.backups = base / cfg.backups
    return cfg


def credentials(env: Optional[dict] = None) -> tuple[str, str]:
    env = os.environ if env is None else env
    user, password = env.get(USER_VAR), env.get(PASSWORD_VAR)
    missing = [v for v, x in ((USER_VAR, user), (PASSWORD_VAR, password)) if not x]
    if missing:
        raise ConfigError(f"set {' and '.join(missing)} in the environment")
    return user, password

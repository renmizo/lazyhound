"""Configuration management for LazyHound."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


_WELL_KNOWN = ("lazyhound.yml", "lazyhound.yaml", ".lazyhound.yml")

_DEFAULTS: dict[str, Any] = {
    "connection": {
        "dc": "",
        "domain": "",
        "username": "",
        "password": "",
        "port": 389,
        "use_ssl": False,
        "auth_method": "ntlm",
        "nthash": "",
        "validate_cert": True,
        "timeout": 30,
        "use_start_tls": True,
        "nameserver": "",
    },
    "paths": {
        "base_dir": ".",
        "logs_dir": "logs",
        "reports_dir": "reports",
        "history_db": "lazyhound_history.db",
    },
    "display": {
        "style": 2,
        "page_size": 50,
    },
    "logging": {
        "enabled": True,
        "log_level": "INFO",
        "console_capture": True,
    },
    "history": {
        "enabled": True,
    },
    "scoring": {
        "profile": "balanced",
    },
}


# Appended (as comments) to a generated lazyhound.yml so operators can discover
# and uncomment the optional scoring overrides. yaml.dump can't emit comments.
_SCORING_HELP = """\

# Optional scan-scoring overrides (uncomment to tune; omit = the profile's
# value). 'profile' picks the baseline (strict | balanced | lenient); any
# field below overrides that baseline. Grades: A/B/C/D by threshold, else F.
# scoring:
#   profile: balanced
#   grade_thresholds: {A: 90, B: 75, C: 60, D: 40}
#   curve: sqrt              # linear | sqrt | log
#   coefficient: 5.5
#   health_weight: 0.4       # 0.0-1.0 blend with environment health
#   severity_points: {critical: 40, high: 20, medium: 8, low: 2, info: 0}
#   category_weights: {kerberos: 1.5, adcs: 1.4}
"""


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into a copy of *base*."""
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


class Config:
    """YAML-based configuration with profile support."""

    def __init__(self, data: dict[str, Any] | None = None,
                 source_path: str | Path | None = None):
        self._data = _deep_merge(_DEFAULTS, data or {})
        self._data = _expand_env(self._data)
        # Path of the YAML file this config was loaded from, or None when the
        # config is all-defaults (no file found).  Used to detect first-run.
        self._source_path = Path(source_path).resolve() if source_path else None

    # -- accessors -----------------------------------------------------------

    @property
    def source_path(self) -> Path | None:
        """The config file this was loaded from, or None if using defaults."""
        return self._source_path

    @property
    def connection(self) -> dict[str, Any]:
        return self._data.get("connection", {})

    @property
    def paths(self) -> dict[str, Any]:
        return self._data.get("paths", {})

    @property
    def display(self) -> dict[str, Any]:
        return self._data.get("display", {})

    @property
    def logging_cfg(self) -> dict[str, Any]:
        return self._data.get("logging", {})

    @property
    def scoring(self) -> dict[str, Any]:
        return self._data.get("scoring", {})

    @property
    def raw(self) -> dict[str, Any]:
        return dict(self._data)

    # -- path resolution -----------------------------------------------------

    def resolve_path(self, key: str) -> Path:
        """Resolve a paths.* value relative to base_dir."""
        base = Path(self.paths.get("base_dir", ".")).expanduser().resolve()
        raw = self.paths.get(key, "")
        p = Path(raw)
        if p.is_absolute():
            return p
        return base / p

    # -- loading -------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None, profile: str | None = None) -> "Config":
        """Load configuration from a YAML file, with optional profile overlay."""
        if path is None:
            path = cls._find_config()
        if path is None:
            return cls()
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        data = {k: v for k, v in raw.items() if k != "profiles"}
        if profile and "profiles" in raw:
            overlay = raw["profiles"].get(profile, {})
            data = _deep_merge(data, overlay)
        return cls(data, source_path=path)

    @classmethod
    def _find_config(cls) -> Path | None:
        cwd = Path.cwd()
        for name in _WELL_KNOWN:
            p = cwd / name
            if p.is_file():
                return p
        return None

    # -- template generation -------------------------------------------------

    @staticmethod
    def generate_template(base_dir: str | Path = ".") -> str:
        """Return a YAML config template string.

        *base_dir* is written into ``paths.base_dir`` so that every relative
        path (databases, logs, reports) resolves to the project
        folder rather than to whatever directory the tool is launched from.
        Pass an absolute path to pin artifacts to a fixed project location.
        """
        import copy

        data = copy.deepcopy(_DEFAULTS)
        data["paths"]["base_dir"] = str(base_dir)
        return (yaml.dump(data, default_flow_style=False, sort_keys=False)
                + _SCORING_HELP)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Retrieve a value by dotted path, e.g. 'connection.dc'."""
        parts = dotted_key.split(".")
        node: Any = self._data
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return default
            if node is None:
                return default
        return node

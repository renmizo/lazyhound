"""Vendored MITRE ATT&CK Enterprise matrix (pinned v16.1), for the heatmap.

The compact taxonomy (14 tactics x parent techniques) is bundled as
``assets/attack_matrix.json`` so the report renders fully offline.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_PATH = Path(__file__).resolve().parent / "assets" / "attack_matrix.json"


@lru_cache(maxsize=1)
def load_attack_matrix() -> dict:
    """Return {"version", "tactics":[{"id","name","shortname","techniques":[...]}]}.
    Returns an empty matrix if the vendored asset is unavailable."""
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": "", "tactics": []}

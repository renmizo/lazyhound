"""Vendored Chart.js, inlined so HTML reports render charts fully offline.

The library (``assets/chart.umd.min.js``, Chart.js v4 UMD minified) is bundled
with the package and embedded directly in the report's ``<script>`` — no CDN, no
network request. Falls back to the CDN only if the vendored file is missing.
"""
from __future__ import annotations

from pathlib import Path

_CHARTJS_PATH = Path(__file__).resolve().parent / "assets" / "chart.umd.min.js"
_CDN_FALLBACK = '<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>'


def chartjs_script_tag() -> str:
    """Return a ``<script>`` tag with Chart.js inlined (offline). Falls back to
    the CDN tag only if the vendored asset cannot be read."""
    try:
        js = _CHARTJS_PATH.read_text(encoding="utf-8")
    except OSError:
        return _CDN_FALLBACK
    return f"<script>{js}</script>"

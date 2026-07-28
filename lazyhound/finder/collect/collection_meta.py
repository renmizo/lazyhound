"""Collection-method label composition.

A collection accumulates capabilities over separate commands:
  - ``collect run``        → base "DCOnly" (or AzureHound / bloodhound-import)
  - ``collect crawl --adcs`` → adds "+ADCS"    (CA-host enrichment)
  - ``collect crawl``      → adds "+Network"  (session / local-admin)

The displayed ``collection_method`` is COMPOSED from meta markers in a canonical
order (``base[+ADCS][+Network]``) so it reads consistently regardless of which
enrichment ran first. This replaces ad-hoc string appends.
"""

from __future__ import annotations

from typing import Any

# Suffixes we compose/strip. Order here defines display order.
_SUFFIXES = ("+ADCS", "+Network")


def base_method(meta: dict[str, Any]) -> str:
    """Return the bare base method (no +ADCS / +Network suffixes).

    Prefers an explicit ``meta['base_method']``; for collections created before
    that field existed, derive it by stripping known suffixes off the stored
    ``collection_method``.
    """
    explicit = meta.get("base_method")
    if explicit:
        return explicit
    cm = meta.get("collection_method") or "DCOnly"
    for suf in _SUFFIXES:
        cm = cm.replace(suf, "")
    return cm or "DCOnly"


def compose_collection_method(meta: dict[str, Any]) -> str:
    """Build the composed method label from structured meta markers.

    Relies on the structured markers (``network_stats``, ``adcs_enrichment``)
    rather than the label string, so recomputing after a ``collect clear``
    correctly drops a capability. Real network crawls always set
    ``network_stats`` alongside the label, so no string fallback is needed;
    ``base_method`` still strips legacy suffixes to recover the base.
    """
    label = base_method(meta)
    if (meta.get("adcs_enrichment") or {}).get("collected"):
        label += "+ADCS"
    if meta.get("network_stats"):
        label += "+Network"
    return label

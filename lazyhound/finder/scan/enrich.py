"""Enrich live scan findings with attack-path reachability from a collection.

When a collection is loaded, a finding whose affected principal can reach Tier
Zero is annotated and its priority elevated — fusing the Assess (findings) and
Map (attack paths) tracks. Live-state findings (no principal) pass through
unchanged. Severity is only ever raised, never lowered.
"""
from __future__ import annotations

from lazyhound.finder.finder_models import Finding, Severity
from lazyhound.finder.collect.analyzer import tier_zero_reach, name_to_sid_index

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _elevate(sev: Severity) -> Severity:
    i = _SEV_ORDER.index(sev)
    return _SEV_ORDER[min(i + 1, len(_SEV_ORDER) - 1)]


def enrich_findings(findings: list[Finding], collection: dict | None) -> int:
    """Annotate findings whose affected principal can reach Tier Zero and raise
    their priority. Returns the number of findings enriched."""
    if not collection:
        return 0
    reach = tier_zero_reach(collection)
    if not reach:
        return 0
    idx = name_to_sid_index(collection)
    enriched = 0
    for f in findings:
        hops = None
        principals: list[str] = []
        for obj in f.affected_objects or []:
            sid = idx.get(str(obj).lower())
            if sid and sid in reach:
                principals.append(obj)
                h = reach[sid]
                hops = h if hops is None else min(hops, h)
        if hops is None:
            continue
        f.details["reaches_tier_zero"] = True
        f.details["tier_zero_hops"] = hops
        f.details["tier_zero_principals"] = principals
        if hops <= 2:
            f.severity = _elevate(f.severity)
            f.risk_points = (f.risk_points or 0) + 100
        elif hops <= 5:
            f.risk_points = (f.risk_points or 0) + 50
        enriched += 1
    return enriched

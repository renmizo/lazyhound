"""Single source of truth for BloodHound-aligned Tier Zero classification.

Used by both the attack-path analyzer (pathfinding targets) and the
BloodHound exporter (``highvalue`` property) so the two never disagree.
"""
from __future__ import annotations

from .security import UAC

# Domain-relative RIDs that are Tier Zero in BloodHound CE's default model.
TIER_ZERO_RIDS: set[int] = {
    500,  # Administrator
    502,  # krbtgt
    512,  # Domain Admins
    516,  # Domain Controllers
    518,  # Schema Admins
    519,  # Enterprise Admins
    498,  # Enterprise Read-only Domain Controllers
    521,  # Read-only Domain Controllers
    526,  # Key Admins
    527,  # Enterprise Key Admins
}

# Well-known (domain-independent) SIDs that are Tier Zero.
TIER_ZERO_SIDS: set[str] = {
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-32-548",  # BUILTIN\Account Operators
    "S-1-5-32-549",  # BUILTIN\Server Operators
    "S-1-5-32-550",  # BUILTIN\Print Operators
    "S-1-5-32-551",  # BUILTIN\Backup Operators
}


def is_tier_zero_sid(sid: str | None, extra_rids: set[int] | None = None) -> bool:
    """True if ``sid`` is a Tier Zero principal by well-known SID or trailing RID."""
    if not sid:
        return False
    if sid in TIER_ZERO_SIDS:
        return True
    # BloodHound CE prefixes well-known SIDs with the domain
    # (e.g. "CORP.LOCAL-S-1-5-32-544"); match those by suffix.
    for wk in TIER_ZERO_SIDS:
        if sid.endswith("-" + wk):
            return True
    parts = sid.rsplit("-", 1)
    if len(parts) == 2:
        try:
            rid = int(parts[1])
        except ValueError:
            return False
        if rid in TIER_ZERO_RIDS:
            return True
        if extra_rids and rid in extra_rids:
            return True
    return False


def is_tier_zero_object(obj: dict, extra_rids: set[int] | None = None) -> bool:
    """True if ``obj`` is Tier Zero by SID, or as a computed member.

    Computed members: the domain object itself, and domain controller
    computer accounts (``userAccountControl`` has SERVER_TRUST set).
    """
    sid = obj.get("object_sid") or ""
    if is_tier_zero_sid(sid, extra_rids):
        return True
    if obj.get("object_class") == "domain" and sid:
        return True
    # Cloud Tier Zero / high-value resource control: an Entra tenant (full
    # tenant compromise), an Azure subscription (Owner/Contributor = control of
    # all its resources), or a key vault (read all secrets/keys).
    if obj.get("object_class") in ("azure_tenant", "azure_sub", "azure_kv") and sid:
        return True
    props = obj.get("properties", {}) or {}
    try:
        uac = int(props.get("userAccountControl", 0))
    except (ValueError, TypeError):
        uac = 0
    return bool(uac & UAC.SERVER_TRUST)

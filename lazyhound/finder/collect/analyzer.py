"""Post-collection attack path analyzer.

Loads JSON files produced by the collector and runs multiple BloodHound-style
checks to identify privilege escalation paths, dangerous configurations, and
Kerberos attack surfaces.

Checks implemented (see CHECK_REGISTRY for the full list):
  1.  acl           — WriteDACL, WriteOwner, GenericAll/Write, dangerous
                       extended rights, targeted WriteProperty
  2.  kerberoast    — Kerberoastable users (SPN set)
  3.  asrep         — AS-REP roastable users (pre-auth disabled)
  4.  unconstrained — Unconstrained delegation
  5.  constrained   — Constrained delegation (with protocol-transition)
  6.  rbcd          — Resource-based constrained delegation
  7.  membership    — Domain Admin nested group membership paths
  8.  config        — Dangerous configurations (PASSWD_NOTREQD, adminCount,
                       DONT_EXPIRE_PASSWORD, reversible encryption, DES-only)
  9.  ownership     — Object ownership abuse
 10.  gpo           — GPO abuse paths
 11.  ou            — OU control and AdminSDHolder
 12.  dcsync        — DCSync / replication rights
 13.  laps          — LAPS password read (ms-Mcs-AdmPwd, ms-LAPS-Password)
 14.  gmsa          — gMSA password read (msDS-ManagedPassword)
 15.  adcs          — ADCS certificate abuse (ESC1-ESC4, ESC6a/b, ESC7,
                       ESC9a, ESC10a/b, ESC13, GoldenCert, WritePKI flags)
 16.  trust         — Trust and forest trust abuse
 17.  shortest-path — Shortest attack paths to high-value targets
 18.  blast-radius  — Blast radius from owned/compromised principals
 19.  correlation   — Cross-correlation of compound risks
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from ..security import (
    AccessMask,
    UAC,
    GUID_DS_REPL_GET_CHANGES,
    GUID_DS_REPL_GET_CHANGES_ALL,
    GUID_DS_REPL_GET_CHANGES_FILTERED,
    GUID_FORCE_CHANGE_PASSWORD,
    GUID_MEMBER,
    GUID_SPN,
    GUID_MSDS_ALLOWED_TO_ACT,
    GUID_MSDS_KEY_CREDENTIAL_LINK,
    GUID_GPLINK,
    GUID_ACCOUNT_RESTRICTIONS,
    GUID_ENROLL,
    GUID_AUTOENROLL,
    GUID_LABELS,
    GUID_LAPS_LEGACY,
    GUID_LAPS_PASSWORD,
    GUID_LAPS_ENCRYPTED_PASSWORD,
    GUID_GMSA_MANAGED_PASSWORD,
    GUID_PKI_NAME_FLAG,
    GUID_PKI_ENROLLMENT_FLAG,
)
from ..tier_zero import (
    TIER_ZERO_RIDS,
    TIER_ZERO_SIDS,
    is_tier_zero_object,
)

# ---------------------------------------------------------------------------
# Well-known SIDs / RIDs
# ---------------------------------------------------------------------------
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-9": "ENTERPRISE DOMAIN CONTROLLERS",
    "S-1-5-10": "NT AUTHORITY\\SELF",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

PRIVILEGED_RIDS = {
    498: "Enterprise Read-only Domain Controllers",
    500: "Administrator",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
    571: "Allowed RODC Password Replication Group",
    572: "Denied RODC Password Replication Group",
}

# RIDs considered high-value targets (DA-level).
# Can be extended at runtime via ``extend_high_value_rids()``.
HIGH_VALUE_RIDS: set[int] = set(TIER_ZERO_RIDS)

# Maximum BFS depth for shortest-path and blast-radius checks.
# These can be overridden via ``set_graph_depth_limits()``.
SHORTEST_PATH_MAX_DEPTH: int = 8
BLAST_RADIUS_MAX_DEPTH: int = 10

# ---------------------------------------------------------------------------
# Edge weights for Dijkstra-based path analysis
# ---------------------------------------------------------------------------
# Lower weight = easier to exploit.  Weights reflect real-world difficulty:
#   1.0 — Trivially exploitable (GenericAll, MemberOf, Owns)
#   2.0 — Easy exploitation with standard tools (WriteDACL, ForceChangePassword)
#   3.0 — Requires specific conditions (constrained delegation, RBCD)
#   4.0 — Requires network access or credentials (HasSession, AdminTo)
#   5.0 — Structural/informational edges (Contains, GPLink)
EDGE_WEIGHTS: dict[str, float] = {
    "MemberOf": 1.0,
    "GenericAll": 1.0,
    "Owns": 1.0,
    "WriteDACL": 1.5,
    "WriteOwner": 1.5,
    "GenericWrite": 1.5,
    "WriteAllProperties": 1.5,
    "AllExtendedRights": 1.5,
    "ForceChangePassword": 2.0,
    "DS-Replication-Get-Changes": 2.0,
    "DS-Replication-Get-Changes-All": 2.0,
    "WriteShadowCredentials": 2.0,
    "ADCSESC1": 2.0,
    "ADCSESC2": 2.0,
    "ADCSESC3": 2.0,
    "ADCSESC4": 2.0,
    "ADCSESC7": 2.0,
    "ADCSGoldenCert": 2.0,
    "CoerceToTGT": 3.0,
    "AllowedToDelegate": 3.0,
    "AllowedToDelegate+S4U": 2.5,
    "AllowedToAct": 3.0,
    "HasSIDHistory": 2.0,
    "HasSession": 4.0,
    "AdminTo": 3.0,
    "CanRDP": 4.0,
    "ExecuteDCOM": 4.0,
    "CanPSRemote": 4.0,
    "GPLink": 5.0,
    "Contains": 5.0,
    "TrustedBy": 3.5,
}
DEFAULT_EDGE_WEIGHT = 3.0


def get_edge_weight(label: str) -> float:
    """Return the exploitation difficulty weight for an edge label.

    Handles WriteProperty:* variants and TrustedBy (SID-filtered) variants.
    """
    if label in EDGE_WEIGHTS:
        return EDGE_WEIGHTS[label]
    # WriteProperty:<attr> edges
    if label.startswith("WriteProperty:"):
        return 2.0
    # TrustedBy variants (with SID-filtered suffix)
    if label.startswith("TrustedBy"):
        if "SID-filtered" in label:
            return 5.0  # Much harder with SID filtering
        return 3.5
    # Any ADCS ESC edge (ADCSESC6/9/10/13 etc.) — easy with Certipy/Certify
    if label.startswith("ADCS"):
        return 2.0
    # Hybrid sync bridge — trivial to traverse if you own the synced account
    if label.startswith("SyncedTo"):
        return 1.0
    # Azure/Entra edges (AZMemberOf, AZHasRole, AZOwns, AZRoleAssignment, ...)
    if label.startswith("AZ"):
        return 2.0
    return DEFAULT_EDGE_WEIGHT

# Well-known SIDs that are high-value (seeded from the shared Tier Zero set)
HIGH_VALUE_SIDS: set[str] = set(TIER_ZERO_SIDS)


# ---------------------------------------------------------------------------
# Severity & categories
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"


class Category(str, Enum):
    ACL_ABUSE = "ACL Abuse"
    KERBEROAST = "Kerberoasting"
    ASREP_ROAST = "AS-REP Roasting"
    UNCONSTRAINED_DELEG = "Unconstrained Delegation"
    CONSTRAINED_DELEG = "Constrained Delegation"
    RBCD = "Resource-Based Constrained Delegation"
    GROUP_MEMBERSHIP = "Nested DA Group Membership"
    DANGEROUS_CONFIG = "Dangerous Configuration"
    OWNERSHIP = "Object Ownership"
    GPO_ABUSE = "GPO Abuse"
    OU_CONTROL = "OU Control"
    DCSYNC = "DCSync / Replication"
    LAPS_READ = "LAPS Password Read"
    GMSA_READ = "gMSA Password Read"
    ADCS_ABUSE = "ADCS Certificate Abuse"
    TRUST_ABUSE = "Trust Abuse"
    SESSION_ABUSE = "Session Abuse (Credential Theft)"
    LOCAL_ACCESS = "Local Group Access"
    SHORTEST_PATH = "Shortest Path to DA"
    BLAST_RADIUS = "Blast Radius (Owned)"
    CROSS_CORRELATION = "Cross-Correlated Risk"
    HYBRID_SYNC = "Hybrid Sync Risk"
    AZURE_PRIVILEGE = "Azure/Entra Privilege"
    DMSA_ABUSE = "dMSA / BadSuccessor"

    @property
    def slug(self) -> str:
        """Space-free, copy-pasteable identifier (e.g. 'shortest_path').

        This is the canonical token for ``paths --category <slug>`` and for
        tab-completion; the enum *value* stays human-readable for display."""
        return self.name.lower()

    @classmethod
    def from_token(cls, token: str) -> "Category | None":
        """Resolve a user-supplied token to a Category by slug (exact or
        unique prefix) or substring of the human name. None if ambiguous/none."""
        t = token.strip().lower().replace("-", "_")
        if not t:
            return None
        for c in cls:
            if c.slug == t:
                return c
        matches = [c for c in cls if c.slug.startswith(t)]
        if len(matches) == 1:
            return matches[0]
        return None


# ---------------------------------------------------------------------------
# Finding & result dataclasses
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """A single attack path finding."""

    category: Category
    severity: Severity
    principal_sid: str          # SID of the affected principal
    principal_name: str         # Resolved name
    target_dn: str              # DN of the target object (or "" for config findings)
    target_name: str            # Name of target
    target_class: str           # Object class
    description: str            # Human-readable description of the finding
    rights: list[str] = field(default_factory=list)
    inherited: bool = False
    is_builtin: bool = False
    details: dict = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Container for all findings from a single analysis run."""

    domain: str
    source_file: str
    findings: list[Finding] = field(default_factory=list)
    owned_sids: set[str] = field(default_factory=set)
    total_objects: int = 0
    tier_zero_suppressed: int = 0  # actor findings hidden (already Tier Zero)
    expansion_rolled_up: bool = False   # expansion exceeded cap -> per-class rollup
    expansion_projected: int = 0        # projected effective-finding count
    expansion_cap: int = 0              # cap in effect for this run

    @property
    def actionable(self) -> list[Finding]:
        """Findings where the principal is NOT a built-in privileged principal."""
        return [f for f in self.findings if not f.is_builtin]

    @property
    def builtin(self) -> list[Finding]:
        return [f for f in self.findings if f.is_builtin]

    def by_category(self) -> dict[Category, list[Finding]]:
        groups: dict[Category, list[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.category, []).append(f)
        return groups

    def by_severity(self) -> dict[Severity, list[Finding]]:
        groups: dict[Severity, list[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups


# ---------------------------------------------------------------------------
# Check registry infrastructure
# ---------------------------------------------------------------------------
@dataclass
class CheckDef:
    """Definition of a single analysis check."""

    name: str
    description: str
    func: Callable[..., list[Finding]]
    is_meta: bool = False  # Meta checks operate on findings, not objects
    category: str = ""  # category tag for filtering (e.g. "acl", "kerberos")


# Map check names to category tags for --categories filtering.
_CHECK_CATEGORIES: dict[str, str] = {
    "acl": "acl",
    "kerberoast": "kerberos",
    "asrep": "kerberos",
    "unconstrained": "delegation",
    "constrained": "delegation",
    "rbcd": "delegation",
    "membership": "membership",
    "config": "config",
    "ownership": "acl",
    "gpo": "gpo",
    "ou": "ou",
    "dcsync": "dcsync",
    "laps": "laps",
    "gmsa": "gmsa",
    "adcs": "adcs",
    "certifried": "adcs",
    "dmsa": "dmsa",
    "trust": "trust",
    "sessions": "sessions",
    "local-access": "local-access",
    "shortest-path": "paths",
    "blast-radius": "paths",
    "correlation": "meta",
    "hybrid-sync": "hybrid",
    "azure-globaladmin": "azure",
    "azure-app-abuse": "azure",
    "azure-managed-identity": "azure",
    "azure-dynamic-group": "azure",
    "azure-conditional-access": "azure",
    "azure-federation": "azure",
    "seamless-sso": "hybrid",
    "azure-cross-tenant-sync": "azure",
    "azure-admin-units": "azure",
}


# The finding Category each check emits — the slug shown in the 'paths' /
# 'export --category' views. This is the bridge between a check's *id* (used by
# 'run --checks <id>') and the finding *category slug* (used by
# 'paths --category <slug>'), so 'checks' can show both vocabularies. Kept in
# sync with the registry by test_checks_registry (asserts full coverage, no
# drift). The two azure checks both surface under 'azure_privilege'.
_CHECK_FINDING_CATEGORY: dict[str, str] = {
    "acl": "acl_abuse",
    "kerberoast": "kerberoast",
    "asrep": "asrep_roast",
    "unconstrained": "unconstrained_deleg",
    "constrained": "constrained_deleg",
    "rbcd": "rbcd",
    "membership": "group_membership",
    "config": "dangerous_config",
    "ownership": "ownership",
    "gpo": "gpo_abuse",
    "ou": "ou_control",
    "dcsync": "dcsync",
    "laps": "laps_read",
    "gmsa": "gmsa_read",
    "adcs": "adcs_abuse",
    "certifried": "adcs_abuse",
    "dmsa": "dmsa_abuse",
    "trust": "trust_abuse",
    "sessions": "session_abuse",
    "local-access": "local_access",
    "shortest-path": "shortest_path",
    "blast-radius": "blast_radius",
    "correlation": "cross_correlation",
    "hybrid-sync": "hybrid_sync",
    "azure-globaladmin": "azure_privilege",
    "azure-app-abuse": "azure_privilege",
    "azure-managed-identity": "azure_privilege",
    "azure-dynamic-group": "azure_privilege",
    "azure-conditional-access": "azure_privilege",
    "azure-federation": "azure_privilege",
    "seamless-sso": "hybrid_sync",
    "azure-cross-tenant-sync": "azure_privilege",
    "azure-admin-units": "azure_privilege",
}


def finding_category_slug(check_name: str) -> str:
    """The finding-category slug a check surfaces under (for 'paths --category').
    '' if the check has no fixed category (meta/graph checks may vary)."""
    return _CHECK_FINDING_CATEGORY.get(check_name, "")


# ---------------------------------------------------------------------------
# Name resolution helpers
# ---------------------------------------------------------------------------
def _resolve_name(sid: str | None, sid_map: dict[str, str], domain: str = "") -> str:
    if not sid:
        return sid or ""
    if sid in sid_map:
        return sid_map[sid]
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    parts = sid.rsplit("-", 1)
    if len(parts) == 2:
        try:
            rid = int(parts[1])
            if rid in PRIVILEGED_RIDS:
                prefix = f"{domain}\\" if domain else ""
                return f"{prefix}{PRIVILEGED_RIDS[rid]}"
        except ValueError:
            pass
    return sid


def _is_builtin(sid: str | None) -> bool:
    if not sid:
        return False
    if sid in WELL_KNOWN_SIDS:
        return True
    parts = sid.rsplit("-", 1)
    if len(parts) == 2:
        try:
            rid = int(parts[1])
            if rid in PRIVILEGED_RIDS:
                return True
        except ValueError:
            pass
    return False


def _is_high_value(sid: str | None) -> bool:
    """Check if a SID represents a high-value target (DA-equivalent)."""
    if not sid:
        return False
    if sid in HIGH_VALUE_SIDS:
        return True
    # BloodHound CE prefixes well-known SIDs with the domain
    # (e.g. "CORP.LOCAL-S-1-5-32-544"); match those by suffix.
    for wk in HIGH_VALUE_SIDS:
        if sid.endswith("-" + wk):
            return True
    parts = sid.rsplit("-", 1)
    if len(parts) == 2:
        try:
            rid = int(parts[1])
            return rid in HIGH_VALUE_RIDS
        except ValueError:
            pass
    return False


def _adcs_enroller_privileged(sid: str | None) -> bool:
    """Whether an ADCS enroll/write grant to *sid* is NOT an escalation.

    ESC1/2/3/4 are dangerous precisely because a BROAD, low-privilege principal
    (Domain Users 513, Domain Computers 515, Authenticated Users S-1-5-11) can
    enroll in / write to a vulnerable template. ``_is_builtin`` treats those
    groups as privileged and would suppress the finding — hiding the whole
    point of the attack. A finding is only uninteresting when the principal is
    ALREADY Tier Zero (Domain/Enterprise Admins, Administrators), so gate on
    high-value membership instead of "builtin".
    """
    return _is_high_value(sid)


def _get_uac(obj: dict) -> int:
    """Extract userAccountControl as int from an object."""
    raw = obj.get("properties", {}).get("userAccountControl", 0)
    if isinstance(raw, int):
        return raw
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Group membership graph
# ---------------------------------------------------------------------------
def _build_group_graph(objects: list[dict]) -> tuple[
    dict[str, set[str]],   # sid -> set of group SIDs this sid is a direct member of
    dict[str, str],        # sid -> name
    dict[str, str],        # dn_lower -> sid
]:
    """Build membership graph from collected objects.

    Returns:
        member_of: maps principal SID -> set of group SIDs it directly belongs to
        sid_names: maps SID -> display name
        dn_to_sid: maps lowercased DN -> SID

    Cached by objects identity — callers only read the result.
    """
    _gk = id(objects)
    _gh = _GROUP_GRAPH_CACHE.get(_gk)
    if _gh is not None and _gh[0] is objects:
        _GROUP_GRAPH_CACHE.move_to_end(_gk)
        return _gh[1]

    dn_to_sid: dict[str, str] = {}
    sid_names: dict[str, str] = {}
    group_members: dict[str, list[str]] = {}  # group SID -> list of member DNs

    for obj in objects:
        sid = obj.get("object_sid") or ""
        dn = obj.get("dn", "")
        name = obj.get("name", dn)
        if sid:
            sid_names[sid] = name
            if dn:
                dn_to_sid[dn.lower()] = sid

        if obj.get("object_class") == "group":
            raw_members = obj.get("properties", {}).get("member", [])
            if isinstance(raw_members, str):
                raw_members = [raw_members]
            if sid:
                group_members[sid] = [m.lower() for m in raw_members if m]

    # Build member_of: for each member DN found in a group, record the group SID
    # Also handle member lists containing SIDs directly (e.g. from BH import)
    member_of: dict[str, set[str]] = defaultdict(set)
    for group_sid, member_dns in group_members.items():
        for mdn in member_dns:
            msid = dn_to_sid.get(mdn)
            if msid:
                member_of[msid].add(group_sid)
            elif mdn.startswith("s-1-") or mdn.startswith("S-1-"):
                # Member value is already a SID (e.g. from BloodHound import)
                # SIDs are stored uppercased in sid_names, but lowercased here
                sid_upper = mdn.upper()
                if sid_upper in sid_names:
                    member_of[sid_upper].add(group_sid)

    # Handle primaryGroupID: users/computers have an implicit membership in
    # their primary group (typically Domain Users RID 513 or Domain Computers
    # RID 515).  The primary group does NOT list them in its "member" attribute.
    # For collections that predate primaryGroupID collection, fall back to the
    # AD defaults: RID 513 for users, RID 515 for computers.
    _DEFAULT_PRIMARY_GROUP: dict[str, int] = {"user": 513, "computer": 515}
    for obj in objects:
        sid = obj.get("object_sid") or ""
        if not sid:
            continue
        pgid = obj.get("properties", {}).get("primaryGroupID")
        if pgid is not None:
            try:
                rid = int(pgid)
            except (ValueError, TypeError):
                continue
        else:
            # Fall back to AD default for the object class
            cls = obj.get("object_class", "")
            rid = _DEFAULT_PRIMARY_GROUP.get(cls)  # type: ignore[arg-type]
            if rid is None:
                continue
        # Derive domain SID from the object SID (everything before the last RID)
        parts = sid.rsplit("-", 1)
        if len(parts) == 2:
            primary_group_sid = f"{parts[0]}-{rid}"
            if primary_group_sid in sid_names:
                member_of[sid].add(primary_group_sid)

    _res = (dict(member_of), sid_names, dn_to_sid)
    _GROUP_GRAPH_CACHE[_gk] = (objects, _res)
    _GROUP_GRAPH_CACHE.move_to_end(_gk)
    while len(_GROUP_GRAPH_CACHE) > _GRAPH_CACHE_MAX:
        _GROUP_GRAPH_CACHE.popitem(last=False)
    return _res


def _resolve_nested_groups(
    start_sid: str,
    member_of: dict[str, set[str]],
    target_sids: set[str],
    max_depth: int = 20,
) -> list[list[str]] | None:
    """Find all paths from start_sid to any target_sid through nested group membership.

    Returns a list of paths (each path is a list of SIDs from start to target),
    or None if no path exists.
    """
    paths: list[list[str]] = []

    def _dfs(current: str, path: list[str], visited: set[str]) -> None:
        if len(path) > max_depth:
            return
        if current in target_sids:
            paths.append(list(path))
            return
        for group_sid in member_of.get(current, set()):
            if group_sid not in visited:
                visited.add(group_sid)
                path.append(group_sid)
                _dfs(group_sid, path, visited)
                path.pop()
                visited.discard(group_sid)

    _dfs(start_sid, [start_sid], {start_sid})
    return paths if paths else None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Shared helpers used by multiple checks
# ---------------------------------------------------------------------------

def _can_enroll(ace: dict) -> bool:
    """Return True if *ace* grants enrollment rights on a certificate template."""
    if "ALLOWED" not in ace.get("ace_type", ""):
        return False
    mask = ace.get("access_mask", 0)
    if mask & AccessMask.GENERIC_ALL:
        return True
    if mask & AccessMask.DS_CONTROL_ACCESS:
        object_type = ace.get("object_type")
        if object_type in (GUID_ENROLL, GUID_AUTOENROLL, None):
            return True
    return False


def _extract_acl_rights(ace: dict) -> list[str]:
    """Extract meaningful attack-relevant rights from an ACE.

    Returns a list of right labels (e.g. ``["GenericAll", "WriteDACL"]``).
    Used by GPO abuse, OU control, ADCS ESC4, and attack-graph checks.
    """
    mask = ace.get("access_mask", 0)
    rights: list[str] = []
    if mask & AccessMask.GENERIC_ALL:
        rights.append("GenericAll")
    if mask & AccessMask.GENERIC_WRITE:
        rights.append("GenericWrite")
    if mask & AccessMask.WRITE_DAC:
        rights.append("WriteDACL")
    if mask & AccessMask.WRITE_OWNER:
        rights.append("WriteOwner")
    if mask & AccessMask.DS_WRITE_PROPERTY:
        obj_type = ace.get("object_type")
        if obj_type is None and "GenericWrite" not in rights:
            rights.append("WriteAllProperties")
    return rights


# Masks that grant meaningful attack-relevant control
_DANGEROUS_MASKS = (
    AccessMask.GENERIC_ALL
    | AccessMask.GENERIC_WRITE
    | AccessMask.WRITE_DAC
    | AccessMask.WRITE_OWNER
    | AccessMask.DS_CONTROL_ACCESS
    | AccessMask.DS_WRITE_PROPERTY
    | AccessMask.DS_SELF
)

# Extended right GUIDs that are dangerous when granted via DS_CONTROL_ACCESS
_DANGEROUS_EXTENDED_RIGHTS = {
    GUID_DS_REPL_GET_CHANGES,
    GUID_DS_REPL_GET_CHANGES_ALL,
    GUID_DS_REPL_GET_CHANGES_FILTERED,
    GUID_FORCE_CHANGE_PASSWORD,
}

# WriteProperty GUIDs that are dangerous
_DANGEROUS_WRITE_PROPS = {
    GUID_MEMBER,
    GUID_SPN,
    GUID_MSDS_ALLOWED_TO_ACT,
    GUID_MSDS_KEY_CREDENTIAL_LINK,
    GUID_ACCOUNT_RESTRICTIONS,
    GUID_GPLINK,
}


def _check_acl_abuse(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
    *,
    aggregate: set[str] | None = None,
) -> list[Finding]:
    """Check 1: Comprehensive ACL abuse detection.

    Detects GenericAll, GenericWrite, WriteDACL, WriteOwner, dangerous extended
    rights (DCSync, ForceChangePassword), and targeted WriteProperty on
    sensitive attributes.

    When ``acl_abuse`` is in ``aggregate``, findings are collapsed *inline* by
    (trustee, rights, target-class) — the check accumulates counts instead of
    emitting one Finding per ACE, so peak memory is the aggregated count (a few
    thousand) rather than the raw ACE count (millions on large collections).
    """
    findings: list[Finding] = []
    _agg_acl = "acl_abuse" in aggregate if aggregate else False
    _acc: dict[tuple, dict] = {}   # (trustee_sid, sorted-rights, target_class) -> rollup

    for obj in objects:
        target_dn = obj.get("dn", "")
        target_name = obj.get("name", target_dn)
        target_class = obj.get("object_class", "unknown")
        target_sid = obj.get("object_sid") or ""
        target_is_hv = _is_high_value(target_sid) if target_sid else False

        for ace in obj.get("dacl", []):
            ace_type = ace.get("ace_type", "")
            if "ALLOWED" not in ace_type:
                continue

            mask = ace.get("access_mask", 0)
            if not (mask & _DANGEROUS_MASKS):
                continue

            trustee_sid = ace.get("trustee_sid", "")
            inherited = ace.get("inherited", False)
            object_type = ace.get("object_type")
            builtin = _is_builtin(trustee_sid)

            # Determine rights granted
            rights: list[str] = []
            descriptions: list[str] = []

            if mask & AccessMask.GENERIC_ALL:
                rights.append("GenericAll")
                descriptions.append("Full control")

            if mask & AccessMask.GENERIC_WRITE:
                rights.append("GenericWrite")
                descriptions.append("Write any property")

            if mask & AccessMask.WRITE_DAC:
                rights.append("WriteDACL")
                descriptions.append("Modify permissions")

            if mask & AccessMask.WRITE_OWNER:
                rights.append("WriteOwner")
                descriptions.append("Take ownership")

            # Extended rights (DS_CONTROL_ACCESS)
            if mask & AccessMask.DS_CONTROL_ACCESS:
                if object_type is None:
                    # No object_type = ALL extended rights
                    rights.append("AllExtendedRights")
                    descriptions.append("All extended rights (includes ForceChangePassword, DCSync)")
                elif object_type in _DANGEROUS_EXTENDED_RIGHTS:
                    label = GUID_LABELS.get(object_type, object_type)
                    rights.append(label)
                    descriptions.append(f"Extended right: {label}")
                else:
                    pass  # Non-dangerous extended right, but don't skip — ACE may have other flags

            # WriteProperty on specific dangerous attributes
            if mask & AccessMask.DS_WRITE_PROPERTY:
                if object_type is None:
                    # No object_type constraint = write ALL properties
                    if "GenericWrite" not in rights:
                        rights.append("WriteAllProperties")
                        descriptions.append("Write all properties")
                elif object_type in _DANGEROUS_WRITE_PROPS:
                    label = GUID_LABELS.get(object_type, object_type)
                    rights.append(f"WriteProperty:{label}")
                    descriptions.append(f"Write {label}")
                # else: non-dangerous WriteProperty — don't skip, DS_SELF may follow

            # Self / validated write (add-self to group)
            if mask & AccessMask.DS_SELF:
                if object_type == GUID_MEMBER or object_type is None:
                    rights.append("AddSelf")
                    descriptions.append("Add self to group")

            if not rights:
                continue

            # Determine severity
            severity = Severity.MEDIUM
            if "GenericAll" in rights or "AllExtendedRights" in rights:
                severity = Severity.CRITICAL if target_is_hv else Severity.HIGH
            elif "WriteDACL" in rights or "WriteOwner" in rights:
                severity = Severity.HIGH if target_is_hv else Severity.MEDIUM
            elif any(r.startswith("DS-Replication") for r in rights):
                severity = Severity.CRITICAL
            elif "User-Force-Change-Password" in rights:
                severity = Severity.HIGH

            trustee_name = _resolve_name(trustee_sid, sid_map, domain)

            if _agg_acl:
                # Inline rollup: accumulate counts, never materialise per-ACE Findings.
                akey = (trustee_sid, tuple(sorted(rights)), target_class)
                roll = _acc.get(akey)
                if roll is None:
                    _acc[akey] = roll = {"count": 0, "sev": severity, "name": trustee_name,
                                         "targets": [], "builtin": builtin}
                roll["count"] += 1
                if len(roll["targets"]) < 25:
                    roll["targets"].append(target_name)
                if _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index(roll["sev"]):
                    roll["sev"] = severity
                continue

            desc = f"{trustee_name} has {', '.join(rights)} on {target_name} ({target_class})"
            findings.append(Finding(
                category=Category.ACL_ABUSE,
                severity=severity,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=target_dn,
                target_name=target_name,
                target_class=target_class,
                description=desc,
                rights=rights,
                inherited=inherited,
                is_builtin=builtin,
            ))

    if _agg_acl:
        for (tsid, rights_t, tclass), roll in _acc.items():
            noun = tclass or "object"
            sample = ", ".join(roll["targets"][:5]) + ("…" if roll["count"] > 5 else "")
            rlabel = "/".join(rights_t) if rights_t else Category.ACL_ABUSE.value
            findings.append(Finding(
                category=Category.ACL_ABUSE, severity=roll["sev"],
                principal_sid=tsid, principal_name=roll["name"],
                target_dn="", target_name=f"{roll['count']} {noun}s", target_class=tclass,
                description=(f"{roll['name']} has {rlabel} on {roll['count']} "
                             f"{noun}(s)" + (f" (e.g. {sample})" if sample else "")),
                rights=list(rights_t), is_builtin=roll["builtin"],
                details={"aggregated": True, "count": roll["count"],
                         "targets_sample": roll["targets"][:25]},
            ))

    return findings


def _check_kerberoastable(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 2: Kerberoastable users -- user accounts with SPNs set."""
    findings: list[Finding] = []

    for obj in objects:
        if obj.get("object_class") != "user":
            continue

        props = obj.get("properties", {})
        spns = props.get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        if not spns:
            continue

        uac = _get_uac(obj)
        if uac & UAC.ACCOUNT_DISABLE:
            continue

        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))
        admin_count = props.get("adminCount", 0)
        try:
            admin_count = int(admin_count)
        except (ValueError, TypeError):
            admin_count = 0

        is_hv = _is_high_value(sid)
        severity = Severity.CRITICAL if is_hv else (Severity.HIGH if admin_count else Severity.MEDIUM)

        desc_parts = [f"{name} has SPN(s): {', '.join(spns[:3])}"]
        if len(spns) > 3:
            desc_parts[0] += f" (+{len(spns) - 3} more)"
        if admin_count:
            desc_parts.append("adminCount=1 (privileged)")
        if is_hv:
            desc_parts.append("HIGH-VALUE TARGET")

        findings.append(Finding(
            category=Category.KERBEROAST,
            severity=severity,
            principal_sid=sid,
            principal_name=name,
            target_dn=obj.get("dn", ""),
            target_name=name,
            target_class="user",
            description="; ".join(desc_parts),
            details={"spns": spns, "admin_count": admin_count},
        ))

    return findings


def _check_asrep_roastable(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 3: AS-REP roastable users -- Kerberos pre-auth not required."""
    findings: list[Finding] = []

    for obj in objects:
        if obj.get("object_class") != "user":
            continue

        uac = _get_uac(obj)
        if not (uac & UAC.DONT_REQ_PREAUTH):
            continue
        if uac & UAC.ACCOUNT_DISABLE:
            continue

        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))
        is_hv = _is_high_value(sid)
        severity = Severity.CRITICAL if is_hv else Severity.HIGH

        findings.append(Finding(
            category=Category.ASREP_ROAST,
            severity=severity,
            principal_sid=sid,
            principal_name=name,
            target_dn=obj.get("dn", ""),
            target_name=name,
            target_class="user",
            description=f"{name} does not require Kerberos pre-authentication (AS-REP roastable)",
        ))

    return findings


def _check_unconstrained_delegation(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 4: Unconstrained delegation (excluding domain controllers)."""
    findings: list[Finding] = []

    for obj in objects:
        obj_class = obj.get("object_class", "")
        if obj_class not in ("user", "computer"):
            continue

        uac = _get_uac(obj)
        if not (uac & UAC.TRUSTED_FOR_DELEGATION):
            continue
        # Domain controllers (SERVER_TRUST) are expected to have this
        if uac & UAC.SERVER_TRUST:
            continue
        if uac & UAC.ACCOUNT_DISABLE:
            continue

        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))

        findings.append(Finding(
            category=Category.UNCONSTRAINED_DELEG,
            severity=Severity.CRITICAL,
            principal_sid=sid,
            principal_name=name,
            target_dn=obj.get("dn", ""),
            target_name=name,
            target_class=obj_class,
            description=f"{name} ({obj_class}) has unconstrained delegation — can capture TGTs",
        ))

    return findings


def _check_constrained_delegation(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 5: Constrained delegation (msDS-AllowedToDelegateTo)."""
    findings: list[Finding] = []

    for obj in objects:
        obj_class = obj.get("object_class", "")
        if obj_class not in ("user", "computer"):
            continue

        props = obj.get("properties", {})
        delegate_to = props.get("msDS-AllowedToDelegateTo", [])
        if isinstance(delegate_to, str):
            delegate_to = [delegate_to]
        if not delegate_to:
            continue

        uac = _get_uac(obj)
        if uac & UAC.ACCOUNT_DISABLE:
            continue

        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))
        protocol_transition = bool(uac & UAC.TRUSTED_TO_AUTH_FOR_DELEGATION)

        severity = Severity.HIGH if protocol_transition else Severity.MEDIUM

        desc_parts = [f"{name} can delegate to: {', '.join(delegate_to[:3])}"]
        if len(delegate_to) > 3:
            desc_parts[0] += f" (+{len(delegate_to) - 3} more)"
        if protocol_transition:
            desc_parts.append("PROTOCOL TRANSITION enabled (T2A4D) — more dangerous")

        findings.append(Finding(
            category=Category.CONSTRAINED_DELEG,
            severity=severity,
            principal_sid=sid,
            principal_name=name,
            target_dn=obj.get("dn", ""),
            target_name=name,
            target_class=obj_class,
            description="; ".join(desc_parts),
            details={
                "delegate_to": delegate_to,
                "protocol_transition": protocol_transition,
            },
        ))

    return findings


def _check_rbcd(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 6: Resource-based constrained delegation.

    Objects with msDS-AllowedToActOnBehalfOfOtherIdentity set allow the
    principals listed in that SD to impersonate any user to this object.
    """
    findings: list[Finding] = []

    for obj in objects:
        props = obj.get("properties", {})
        rbcd_raw = props.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not rbcd_raw:
            continue

        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))
        obj_class = obj.get("object_class", "")

        findings.append(Finding(
            category=Category.RBCD,
            severity=Severity.HIGH,
            principal_sid=sid,
            principal_name=name,
            target_dn=obj.get("dn", ""),
            target_name=name,
            target_class=obj_class,
            description=(
                f"{name} has msDS-AllowedToActOnBehalfOfOtherIdentity set — "
                "resource-based constrained delegation configured"
            ),
        ))

    return findings


# Groups whose membership confers full domain/forest admin — being a member
# (directly or nested) is effectively "you have DA", i.e. CRITICAL impact.
# (Domain Controllers/RODCs and the operator groups are high-value but NOT
# full-DA-by-membership, so they keep the info/nested-medium weighting.)
_FULL_ADMIN_RIDS = {512, 518, 519, 526, 527}   # Domain / Schema / Enterprise / Key / Ent-Key Admins
_FULL_ADMIN_SIDS = {"S-1-5-32-544"}            # BUILTIN\\Administrators


def _check_nested_da_membership(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 7: All users that are members (directly or nested) of DA-equivalent groups."""
    member_of, sid_names, dn_to_sid = _build_group_graph(objects)

    # Identify the target group SIDs (DA, EA, SA, Administrators). Track which
    # of those are full-admin groups (membership == full DA) separately so we
    # can rate that membership CRITICAL.
    target_sids: set[str] = set()
    full_admin_sids: set[str] = set()
    for obj in objects:
        sid = obj.get("object_sid") or ""
        if not sid:
            continue
        parts = sid.rsplit("-", 1)
        if len(parts) == 2:
            try:
                rid = int(parts[1])
                if rid in HIGH_VALUE_RIDS:
                    target_sids.add(sid)
                    if rid in _FULL_ADMIN_RIDS:
                        full_admin_sids.add(sid)
            except ValueError:
                pass
        if sid in HIGH_VALUE_SIDS:
            target_sids.add(sid)
            if sid in _FULL_ADMIN_SIDS:
                full_admin_sids.add(sid)

    if not target_sids:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()

    for obj in objects:
        if obj.get("object_class") not in ("user", "computer"):
            continue
        sid = obj.get("object_sid") or ""
        if not sid or sid in target_sids or sid in seen:
            continue

        paths = _resolve_nested_groups(sid, member_of, target_sids)
        if not paths:
            continue
        seen.add(sid)

        name = obj.get("name", obj.get("dn", ""))

        for path in paths:
            chain_names = [sid_names.get(s, s) for s in path]
            # The path head is this object; show its own name so the path stays
            # consistent with principal_name even when a SID is shared by
            # multiple objects (last-writer-wins sid_names would disagree).
            if chain_names:
                chain_names[0] = name
            chain_str = " → ".join(chain_names)
            target_sid = path[-1]
            target_name = sid_names.get(target_sid, target_sid)

            # Membership in a full-admin group (direct OR nested) is full
            # domain/forest compromise -> CRITICAL. Other high-value groups
            # (DCs, RODCs, operators) keep the info/nested-medium weighting.
            if target_sid in full_admin_sids:
                severity = Severity.CRITICAL
            elif len(path) > 2:
                severity = Severity.MEDIUM  # nested membership in a high-value group
            else:
                severity = Severity.INFO    # direct member of a non-full-admin HV group

            findings.append(Finding(
                category=Category.GROUP_MEMBERSHIP,
                severity=severity,
                principal_sid=sid,
                principal_name=name,
                target_dn="",
                target_name=target_name,
                target_class="group",
                description=f"Member of {target_name} via: {chain_str}",
                details={
                    "path": path,
                    "path_names": chain_names,
                    "depth": len(path) - 1,
                },
            ))

    return findings


def _check_dangerous_config(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 8: Dangerous account configurations."""
    findings: list[Finding] = []

    for obj in objects:
        obj_class = obj.get("object_class", "")
        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))
        props = obj.get("properties", {})

        # Domain-level: MachineAccountQuota > 0
        if obj_class == "domain":
            maq = props.get("ms-DS-MachineAccountQuota", 0)
            try:
                maq = int(maq)
            except (ValueError, TypeError):
                maq = 0
            if maq > 0:
                findings.append(Finding(
                    category=Category.DANGEROUS_CONFIG,
                    severity=Severity.MEDIUM,
                    principal_sid=sid,
                    principal_name=name,
                    target_dn=obj.get("dn", ""),
                    target_name=name,
                    target_class="domain",
                    description=(
                        f"ms-DS-MachineAccountQuota = {maq} — any authenticated user can "
                        "create machine accounts, enabling RBCD, noPac / sAMAccountName "
                        "spoofing (CVE-2021-42278/42287) and Certifried (CVE-2022-26923)"
                    ),
                    details={"machine_account_quota": maq,
                             "attack_vectors": ["RBCD", "noPac", "Certifried"]},
                ))
            continue

        if obj_class not in ("user", "computer"):
            continue

        uac = _get_uac(obj)
        if uac & UAC.ACCOUNT_DISABLE:
            continue

        # PASSWORD_NOT_REQUIRED
        if uac & UAC.PASSWD_NOTREQD:
            findings.append(Finding(
                category=Category.DANGEROUS_CONFIG,
                severity=Severity.HIGH,
                principal_sid=sid,
                principal_name=name,
                target_dn=obj.get("dn", ""),
                target_name=name,
                target_class=obj_class,
                description=f"{name} has PASSWORD_NOT_REQUIRED flag set",
            ))

        # Orphaned adminCount -- adminCount=1 on non-privileged accounts
        admin_count = props.get("adminCount", 0)
        try:
            admin_count = int(admin_count)
        except (ValueError, TypeError):
            admin_count = 0
        if admin_count and not _is_high_value(sid):
            findings.append(Finding(
                category=Category.DANGEROUS_CONFIG,
                severity=Severity.INFO,
                principal_sid=sid,
                principal_name=name,
                target_dn=obj.get("dn", ""),
                target_name=name,
                target_class=obj_class,
                description=f"{name} has adminCount=1 but is not a known privileged principal (orphaned AdminSDHolder)",
            ))

        # DONT_EXPIRE_PASSWORD
        if uac & UAC.DONT_EXPIRE_PASSWORD:
            findings.append(Finding(
                category=Category.DANGEROUS_CONFIG,
                severity=Severity.MEDIUM if not _is_high_value(sid) else Severity.HIGH,
                principal_sid=sid,
                principal_name=name,
                target_dn=obj.get("dn", ""),
                target_name=name,
                target_class=obj_class,
                description=f"{name} has DONT_EXPIRE_PASSWORD flag — password never rotates",
            ))

        # Reversible encryption (ENCRYPTED_TEXT_PWD_ALLOWED)
        if uac & UAC.ENCRYPTED_TEXT_PWD_ALLOWED:
            findings.append(Finding(
                category=Category.DANGEROUS_CONFIG,
                severity=Severity.HIGH,
                principal_sid=sid,
                principal_name=name,
                target_dn=obj.get("dn", ""),
                target_name=name,
                target_class=obj_class,
                description=f"{name} stores password with reversible encryption — password recoverable from NTDS.dit",
            ))

        # USE_DES_KEY_ONLY — weak Kerberos encryption
        if uac & UAC.USE_DES_KEY_ONLY:
            findings.append(Finding(
                category=Category.DANGEROUS_CONFIG,
                severity=Severity.MEDIUM,
                principal_sid=sid,
                principal_name=name,
                target_dn=obj.get("dn", ""),
                target_name=name,
                target_class=obj_class,
                description=f"{name} has USE_DES_KEY_ONLY flag — restricted to weak DES Kerberos encryption",
            ))

    return findings


def _check_ownership(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 9: Objects owned by non-privileged principals.

    The owner of an object can grant themselves WriteDACL, making ownership
    of sensitive objects a privilege escalation vector.
    """
    findings: list[Finding] = []

    for obj in objects:
        owner_sid = obj.get("owner_sid")
        if not owner_sid:
            continue

        target_sid = obj.get("object_sid") or ""
        target_name = obj.get("name", obj.get("dn", ""))
        target_class = obj.get("object_class", "")

        # Only flag non-builtin owners on high-value targets
        if _is_builtin(owner_sid):
            continue
        if not (target_class in ("user", "group", "computer", "domain") and _is_high_value(target_sid)):
            continue

        owner_name = _resolve_name(owner_sid, sid_map, domain)

        findings.append(Finding(
            category=Category.OWNERSHIP,
            severity=Severity.HIGH,
            principal_sid=owner_sid,
            principal_name=owner_name,
            target_dn=obj.get("dn", ""),
            target_name=target_name,
            target_class=target_class,
            description=f"{owner_name} owns {target_name} ({target_class}) — owner can grant self WriteDACL",
        ))

    return findings


# ---------------------------------------------------------------------------
# New checks: GPO abuse, OU control, DCSync, ADCS, Trust, Shortest paths
# ---------------------------------------------------------------------------

def _check_gpo_abuse(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 10: GPO abuse paths — modification rights, linking rights, and inheritance."""
    findings: list[Finding] = []

    # Parse gPLink on OUs/domain to find which GPOs are linked where
    ou_gpo_links: dict[str, list[str]] = {}  # ou_dn_lower -> [gpo_dn_lower, ...]
    for obj in objects:
        if obj.get("object_class") not in ("ou", "domain"):
            continue
        gplink = obj.get("properties", {}).get("gPLink", "")
        if not gplink:
            continue
        linked_dns = []
        for m in re.finditer(r"\[LDAP://([^;]+);(\d+)\]", str(gplink), re.IGNORECASE):
            if not (int(m.group(2)) & 1):  # skip disabled links (flag bit 0)
                linked_dns.append(m.group(1))
        obj_dn = obj.get("dn", "")
        if obj_dn:
            ou_gpo_links[obj_dn.lower()] = [dn.lower() for dn in linked_dns]

    # Check ACLs on GPO objects for modification rights
    for obj in objects:
        if obj.get("object_class") != "gpo":
            continue

        target_dn = obj.get("dn", "")
        target_name = obj.get("name", target_dn)

        # Which OUs link this GPO?
        linked_ous = [
            ou_dn for ou_dn, gpo_dns in ou_gpo_links.items()
            if target_dn.lower() in gpo_dns
        ]

        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue

            trustee_sid = ace.get("trustee_sid", "")
            inherited = ace.get("inherited", False)
            if not trustee_sid:
                continue

            rights = _extract_acl_rights(ace)
            if not rights:
                continue

            builtin = _is_builtin(trustee_sid)
            trustee_name = _resolve_name(trustee_sid, sid_map, domain)
            desc_parts = [f"{trustee_name} can modify GPO '{target_name}' ({', '.join(rights)})"]
            if linked_ous:
                desc_parts.append(f"GPO linked to {len(linked_ous)} OU(s)")

            severity = Severity.HIGH if linked_ous else Severity.MEDIUM

            findings.append(Finding(
                category=Category.GPO_ABUSE,
                severity=severity,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=target_dn,
                target_name=target_name,
                target_class="gpo",
                description="; ".join(desc_parts),
                rights=rights,
                inherited=inherited,
                is_builtin=builtin,
                details={"linked_ous": linked_ous},
            ))

    # Check for gPLink write rights on OUs (can link arbitrary GPOs)
    for obj in objects:
        if obj.get("object_class") not in ("ou", "domain"):
            continue

        target_dn = obj.get("dn", "")
        target_name = obj.get("name", target_dn)
        target_class = obj.get("object_class", "")

        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue

            mask = ace.get("access_mask", 0)
            trustee_sid = ace.get("trustee_sid", "")
            inherited = ace.get("inherited", False)
            object_type = ace.get("object_type")
            if not trustee_sid:
                continue

            builtin = _is_builtin(trustee_sid)

            # Check for gPLink write capability
            can_link = False
            if mask & (AccessMask.GENERIC_ALL | AccessMask.GENERIC_WRITE):
                can_link = True
            elif mask & AccessMask.DS_WRITE_PROPERTY:
                if object_type == GUID_GPLINK or object_type is None:
                    can_link = True

            if not can_link:
                continue

            trustee_name = _resolve_name(trustee_sid, sid_map, domain)

            findings.append(Finding(
                category=Category.GPO_ABUSE,
                severity=Severity.HIGH,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=target_dn,
                target_name=target_name,
                target_class=target_class,
                description=f"{trustee_name} can link GPOs to {target_name} ({target_class}) — GPO abuse vector",
                rights=["WriteProperty:gPLink"],
                inherited=inherited,
                is_builtin=builtin,
            ))

    return findings


def _check_ou_control(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 11: OU/container control and AdminSDHolder abuse.

    Detects non-builtin principals with dangerous rights on OUs (affects child
    objects) and control over the AdminSDHolder container (propagates DACL to
    all adminCount=1 objects).
    """
    findings: list[Finding] = []

    # Identify AdminSDHolder DN pattern
    adminsdholder_dn_suffix = "cn=adminsdholder,cn=system,"

    for obj in objects:
        obj_class = obj.get("object_class", "")
        target_dn = obj.get("dn", "")
        is_adminsdholder = adminsdholder_dn_suffix in target_dn.lower()

        # Include OUs and domain objects, plus containers that match AdminSDHolder
        if obj_class not in ("ou", "domain") and not (obj_class == "container" and is_adminsdholder):
            continue

        target_name = obj.get("name", target_dn)
        target_class = obj_class

        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue

            trustee_sid = ace.get("trustee_sid", "")
            inherited = ace.get("inherited", False)
            if not trustee_sid:
                continue

            rights = _extract_acl_rights(ace)
            if not rights:
                continue

            builtin = _is_builtin(trustee_sid)
            trustee_name = _resolve_name(trustee_sid, sid_map, domain)

            if is_adminsdholder:
                severity = Severity.CRITICAL
                desc = (
                    f"{trustee_name} has {', '.join(rights)} on AdminSDHolder — "
                    "DACL propagates to all adminCount=1 objects"
                )
            else:
                severity = Severity.HIGH
                desc = (
                    f"{trustee_name} has {', '.join(rights)} on OU '{target_name}' — "
                    "affects all child objects"
                )

            findings.append(Finding(
                category=Category.OU_CONTROL,
                severity=severity,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=target_dn,
                target_name=target_name,
                target_class=target_class,
                description=desc,
                rights=rights,
                inherited=inherited,
                is_builtin=builtin,
                details={"is_adminsdholder": is_adminsdholder},
            ))

    return findings


# Safety guard: don't expand a pathologically large group (e.g. a misconfigured
# 'Domain Users' with DCSync) into thousands of member findings.
_GROUP_MEMBER_CAP = 200
# Default projected effective-finding count above which expansion rolls up to
# per-(member, right, class) counts instead of one finding per member/target.
# Keeps peak memory bounded on very large forests. Override via analyze(
# expand_cap=...) / `analyze run --expand-cap N` / LAZYHOUND_EXPAND_CAP.
_DEFAULT_EXPAND_CAP = 250_000


def _transitive_leaf_members(
    top_group: str,
    group_to_members: dict[str, set[str]],
    obj_class: dict[str, str],
    cap: int,
) -> dict[str, list[str]]:
    """Transitive non-group members of ``top_group``.

    Returns ``{leaf_sid: [group_sid chain from the leaf's direct parent group up
    to top_group]}``. Follows nested groups, is cycle-safe, and stops after
    ``cap`` leaves.
    """
    leaves: dict[str, list[str]] = {}
    seen = {top_group}
    queue: deque[tuple[str, list[str]]] = deque([(top_group, [top_group])])
    while queue:
        grp, chain = queue.popleft()
        for msid in group_to_members.get(grp, ()):
            if obj_class.get(msid) == "group":
                if msid not in seen:
                    seen.add(msid)
                    queue.append((msid, [msid] + chain))
            elif msid not in leaves:
                leaves[msid] = chain
                if len(leaves) >= cap:
                    return leaves
    return leaves


def _check_dcsync(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 12: DCSync / replication rights.

    Identifies principals with GetChanges AND GetChangesAll on the domain
    object, which together enable DCSync (full credential replication).
    Also flags GetChangesInFilteredSet. Group holders are expanded to their
    effective members by the shared actor-member pass in ``analyze()``.
    """
    findings: list[Finding] = []

    # Find domain objects
    for obj in objects:
        if obj.get("object_class") != "domain":
            continue

        target_dn = obj.get("dn", "")
        target_name = obj.get("name", target_dn)

        # Collect replication rights per trustee
        trustee_repl: dict[str, set[str]] = defaultdict(set)

        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue

            mask = ace.get("access_mask", 0)
            if not (mask & AccessMask.DS_CONTROL_ACCESS):
                continue

            trustee_sid = ace.get("trustee_sid", "")
            object_type = ace.get("object_type")
            if not trustee_sid:
                continue

            if object_type == GUID_DS_REPL_GET_CHANGES:
                trustee_repl[trustee_sid].add("GetChanges")
            elif object_type == GUID_DS_REPL_GET_CHANGES_ALL:
                trustee_repl[trustee_sid].add("GetChangesAll")
            elif object_type == GUID_DS_REPL_GET_CHANGES_FILTERED:
                trustee_repl[trustee_sid].add("GetChangesInFilteredSet")
            elif object_type is None:
                # AllExtendedRights includes all replication rights
                trustee_repl[trustee_sid].update(
                    {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}
                )

        # Report principals with DCSync capability (group holders are expanded
        # to their members by the shared actor-member pass in analyze()).
        for trustee_sid, repl_rights in trustee_repl.items():
            builtin = _is_builtin(trustee_sid)
            trustee_name = _resolve_name(trustee_sid, sid_map, domain)

            if {"GetChanges", "GetChangesAll"} <= repl_rights:
                severity = Severity.CRITICAL
                desc = (
                    f"{trustee_name} has DCSync rights (GetChanges + GetChangesAll) "
                    f"on {target_name} — can replicate all credentials including KRBTGT"
                )
            elif repl_rights:
                severity = Severity.HIGH
                desc = (
                    f"{trustee_name} has partial replication rights "
                    f"({', '.join(sorted(repl_rights))}) on {target_name}"
                )
            else:
                continue

            findings.append(Finding(
                category=Category.DCSYNC,
                severity=severity,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=target_dn,
                target_name=target_name,
                target_class="domain",
                description=desc,
                rights=sorted(repl_rights),
                is_builtin=builtin,
                details={"replication_rights": sorted(repl_rights)},
            ))

    return findings


# ---------------------------------------------------------------------------
# LAPS / gMSA credential access checks
# ---------------------------------------------------------------------------
_LAPS_GUIDS = {GUID_LAPS_LEGACY, GUID_LAPS_PASSWORD, GUID_LAPS_ENCRYPTED_PASSWORD}


def _check_laps_read(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check: ReadLAPSPassword — principals that can read LAPS passwords.

    Detects DS_CONTROL_ACCESS or DS_READ_PROPERTY on LAPS attributes
    (ms-Mcs-AdmPwd, ms-LAPS-Password, ms-LAPS-EncryptedPassword) on
    computer objects.
    """
    findings: list[Finding] = []

    for obj in objects:
        if obj.get("object_class") != "computer":
            continue
        target_sid = obj.get("object_sid") or ""
        target_name = obj.get("name", obj.get("dn", ""))
        target_dn = obj.get("dn", "")

        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            trustee_sid = ace.get("trustee_sid", "")
            if not trustee_sid or trustee_sid == target_sid:
                continue

            mask = ace.get("access_mask", 0)
            object_type = ace.get("object_type")

            can_read = False
            laps_type = ""

            # GenericAll grants all property reads
            if mask & AccessMask.GENERIC_ALL:
                can_read = True
                laps_type = "GenericAll"
            # AllExtendedRights (DS_CONTROL_ACCESS with no object_type)
            elif mask & AccessMask.DS_CONTROL_ACCESS and object_type is None:
                can_read = True
                laps_type = "AllExtendedRights"
            # Specific LAPS property read or extended right
            elif mask & (AccessMask.DS_CONTROL_ACCESS | AccessMask.DS_READ_PROPERTY):
                if object_type in _LAPS_GUIDS:
                    can_read = True
                    laps_type = GUID_LABELS.get(object_type, "LAPS")

            if can_read:
                builtin = _is_builtin(trustee_sid)
                trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                inherited = ace.get("inherited", False)
                findings.append(Finding(
                    category=Category.LAPS_READ,
                    severity=Severity.HIGH,
                    principal_sid=trustee_sid,
                    principal_name=trustee_name,
                    target_dn=target_dn,
                    target_name=target_name,
                    target_class="computer",
                    description=(
                        f"{trustee_name} can read LAPS password on {target_name} "
                        f"via {laps_type}"
                    ),
                    rights=[laps_type],
                    inherited=inherited,
                    is_builtin=builtin,
                    details={"laps_type": laps_type},
                ))

    return findings


def _check_gmsa_read(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check: ReadGMSAPassword — principals that can read gMSA managed passwords.

    Detects DS_CONTROL_ACCESS or DS_READ_PROPERTY on msDS-ManagedPassword
    on gMSA (msDS-GroupManagedServiceAccount) objects, or principals listed
    in msDS-GroupMSAMembership.
    """
    findings: list[Finding] = []

    for obj in objects:
        obj_class = obj.get("object_class", "")
        # gMSA accounts may be classified as 'msDS-GroupManagedServiceAccount' or 'user'
        # with the msDS-ManagedPassword property indicator
        props = obj.get("properties", {})
        is_gmsa = (
            obj_class == "gmsa"
            or obj_class == "msds-groupmanagedserviceaccount"
            or props.get("msDS-GroupMSAMembership") is not None
            or obj_class == "user" and (props.get("objectCategory") or "").lower().find("ms-ds-group-managed-service-account") >= 0
        )
        if not is_gmsa:
            continue

        target_sid = obj.get("object_sid") or ""
        target_name = obj.get("name", obj.get("dn", ""))
        target_dn = obj.get("dn", "")

        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            trustee_sid = ace.get("trustee_sid", "")
            if not trustee_sid or trustee_sid == target_sid:
                continue

            mask = ace.get("access_mask", 0)
            object_type = ace.get("object_type")

            can_read = False
            via = ""

            if mask & AccessMask.GENERIC_ALL:
                can_read = True
                via = "GenericAll"
            elif mask & AccessMask.DS_CONTROL_ACCESS and object_type is None:
                can_read = True
                via = "AllExtendedRights"
            elif mask & (AccessMask.DS_CONTROL_ACCESS | AccessMask.DS_READ_PROPERTY):
                if object_type == GUID_GMSA_MANAGED_PASSWORD:
                    can_read = True
                    via = "msDS-ManagedPassword"

            if can_read:
                builtin = _is_builtin(trustee_sid)
                trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                inherited = ace.get("inherited", False)
                findings.append(Finding(
                    category=Category.GMSA_READ,
                    severity=Severity.HIGH,
                    principal_sid=trustee_sid,
                    principal_name=trustee_name,
                    target_dn=target_dn,
                    target_name=target_name,
                    target_class="msds-groupmanagedserviceaccount",
                    description=(
                        f"{trustee_name} can read gMSA password of {target_name} "
                        f"via {via}"
                    ),
                    rights=[via],
                    inherited=inherited,
                    is_builtin=builtin,
                    details={"via": via},
                ))

    return findings


def _check_adcs(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 13: ADCS certificate abuse (ESC1-ESC13).

    Detects dangerous certificate template configurations and enrollment
    rights. Requires certificate template and CA objects in the collection
    (object_class 'certtemplate' or 'pki').
    """
    findings: list[Finding] = []

    cert_templates = [o for o in objects if o.get("object_class") == "certtemplate"]
    ca_objects = [o for o in objects if o.get("object_class") == "pki"]

    if not cert_templates and not ca_objects:
        return findings  # No ADCS data collected

    for tmpl in cert_templates:
        props = tmpl.get("properties", {})
        tmpl_name = tmpl.get("name", tmpl.get("dn", ""))
        tmpl_dn = tmpl.get("dn", "")

        # Parse template flags
        name_flag = 0
        try:
            name_flag = int(props.get("msPKI-Certificate-Name-Flag", 0) or 0)
        except (ValueError, TypeError):
            pass

        enrollment_flag = 0
        try:
            enrollment_flag = int(props.get("msPKI-Enrollment-Flag", 0) or 0)
        except (ValueError, TypeError):
            pass

        ra_sig = 0
        try:
            ra_sig = int(props.get("msPKI-RA-Signature", 0) or 0)
        except (ValueError, TypeError):
            pass

        ekus = props.get("pKIExtendedKeyUsage", [])
        if isinstance(ekus, str):
            ekus = [ekus]

        # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
        supplies_san = bool(name_flag & 0x00000001)

        # Manager approval required flag
        manager_approval = bool(enrollment_flag & 0x00000002)

        # Dangerous EKU check
        any_purpose_eku = "2.5.29.37.0" in ekus
        client_auth_eku = "1.3.6.1.5.5.7.3.2" in ekus
        smart_card_eku = "1.3.6.1.4.1.311.20.2.2" in ekus
        no_eku = len(ekus) == 0

        # ESC1: Enrollee supplies SAN + client auth EKU + no manager approval + no RA sig
        if supplies_san and (client_auth_eku or smart_card_eku or any_purpose_eku or no_eku):
            if not manager_approval and ra_sig == 0:
                # Check who can enroll
                for ace in tmpl.get("dacl", []):
                    trustee_sid = ace.get("trustee_sid", "")
                    if not trustee_sid:
                        continue
                    if _can_enroll(ace):
                        # Suppress only when the enroller is ALREADY Tier Zero;
                        # a low-priv enroller (Domain Users etc.) IS the attack.
                        builtin = _adcs_enroller_privileged(trustee_sid)
                        trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                        findings.append(Finding(
                            category=Category.ADCS_ABUSE,
                            severity=Severity.CRITICAL,
                            principal_sid=trustee_sid,
                            principal_name=trustee_name,
                            target_dn=tmpl_dn,
                            target_name=tmpl_name,
                            target_class="certtemplate",
                            description=(
                                f"ESC1: {trustee_name} can enroll in template '{tmpl_name}' "
                                "which allows requestor-supplied SAN with client auth EKU — "
                                "can impersonate any user"
                            ),
                            rights=["Enroll"],
                            is_builtin=builtin,
                            details={"esc_type": "ESC1", "template": tmpl_name},
                        ))

        # ESC2: Template with Any Purpose or no EKU (can be used for anything)
        # Skip if already reported as ESC1 for the same template (avoids double-reporting)
        esc1_trustee_sids = {
            f.principal_sid for f in findings
            if f.details.get("esc_type") == "ESC1" and f.details.get("template") == tmpl_name
        }
        if any_purpose_eku or no_eku:
            if not manager_approval and ra_sig == 0:
                for ace in tmpl.get("dacl", []):
                    trustee_sid = ace.get("trustee_sid", "")
                    if not trustee_sid:
                        continue
                    if _can_enroll(ace) and not _adcs_enroller_privileged(trustee_sid) and trustee_sid not in esc1_trustee_sids:
                        trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                        findings.append(Finding(
                            category=Category.ADCS_ABUSE,
                            severity=Severity.HIGH,
                            principal_sid=trustee_sid,
                            principal_name=trustee_name,
                            target_dn=tmpl_dn,
                            target_name=tmpl_name,
                            target_class="certtemplate",
                            description=(
                                f"ESC2: {trustee_name} can enroll in template '{tmpl_name}' "
                                "with Any Purpose / no EKU — dangerous subordinate CA potential"
                            ),
                            rights=["Enroll"],
                            details={"esc_type": "ESC2", "template": tmpl_name},
                        ))

        # ESC4: Non-builtin principal has write access to certificate template
        for ace in tmpl.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            trustee_sid = ace.get("trustee_sid", "")
            if not trustee_sid:
                continue

            rights_list = _extract_acl_rights(ace)
            if rights_list and not _adcs_enroller_privileged(trustee_sid):
                trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                findings.append(Finding(
                    category=Category.ADCS_ABUSE,
                    severity=Severity.CRITICAL,
                    principal_sid=trustee_sid,
                    principal_name=trustee_name,
                    target_dn=tmpl_dn,
                    target_name=tmpl_name,
                    target_class="certtemplate",
                    description=(
                        f"ESC4: {trustee_name} has {', '.join(rights_list)} on template "
                        f"'{tmpl_name}' — can modify template to enable ESC1/ESC2"
                    ),
                    rights=rights_list,
                    details={"esc_type": "ESC4", "template": tmpl_name},
                ))

    # ESC3: Enrollment agent template — Certificate Request Agent EKU
    # OID 1.3.6.1.4.1.311.20.2.1 = Certificate Request Agent
    CERT_REQUEST_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"
    for tmpl in cert_templates:
        props = tmpl.get("properties", {})
        tmpl_name = tmpl.get("name", tmpl.get("dn", ""))
        tmpl_dn = tmpl.get("dn", "")
        ekus = props.get("pKIExtendedKeyUsage", [])
        if isinstance(ekus, str):
            ekus = [ekus]

        enrollment_flag = 0
        try:
            enrollment_flag = int(props.get("msPKI-Enrollment-Flag", 0))
        except (ValueError, TypeError):
            pass
        ra_sig = 0
        try:
            ra_sig = int(props.get("msPKI-RA-Signature", 0))
        except (ValueError, TypeError):
            pass
        manager_approval = bool(enrollment_flag & 0x00000002)

        if CERT_REQUEST_AGENT_OID in ekus and not manager_approval and ra_sig == 0:
            for ace in tmpl.get("dacl", []):
                trustee_sid = ace.get("trustee_sid", "")
                if not trustee_sid:
                    continue
                if _can_enroll(ace) and not _adcs_enroller_privileged(trustee_sid):
                    trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                    findings.append(Finding(
                        category=Category.ADCS_ABUSE,
                        severity=Severity.HIGH,
                        principal_sid=trustee_sid,
                        principal_name=trustee_name,
                        target_dn=tmpl_dn,
                        target_name=tmpl_name,
                        target_class="certtemplate",
                        description=(
                            f"ESC3: {trustee_name} can enroll in template '{tmpl_name}' "
                            "with Certificate Request Agent EKU — can request certs on behalf of others"
                        ),
                        rights=["Enroll"],
                        details={"esc_type": "ESC3", "template": tmpl_name},
                    ))

    # ESC7: Non-builtin principal with Manage CA / Manage Certificates on CA object
    # ESC6: CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag
    # GoldenCert: Non-builtin principal with admin on CA host
    for ca in ca_objects:
        ca_name = ca.get("name", ca.get("dn", ""))
        ca_dn = ca.get("dn", "")
        ca_props = ca.get("properties", {})
        # CA-host enrichment from `collect crawl --adcs` (None fields = unread).
        adcs = ca.get("adcs") or {}

        # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2. The LDAP `flags` attribute does
        # NOT carry this — it's a CA registry value — so prefer the enriched
        # (registry-truth) value when the CA was crawled with --adcs.
        ca_flags = 0
        try:
            ca_flags = int(ca_props.get("flags", 0))
        except (ValueError, TypeError):
            pass
        editf_san2 = bool(ca_flags & 0x00040000)  # EDITF_ATTRIBUTESUBJECTALTNAME2
        if adcs.get("editf_san2") is not None:
            editf_san2 = bool(adcs["editf_san2"])

        # -- CA-host ESCs from --adcs enrichment (only when present) ----------
        if adcs.get("web_enrollment_http"):  # ESC8
            findings.append(Finding(
                category=Category.ADCS_ABUSE,
                severity=Severity.CRITICAL,
                principal_sid="S-1-5-11",  # Authenticated Users (coerce+relay)
                principal_name="Authenticated Users",
                target_dn=ca_dn,
                target_name=ca_name,
                target_class="pki",
                description=(
                    f"ESC8: CA '{ca_name}' exposes HTTP web enrollment (certsrv) — "
                    "vulnerable to NTLM relay (PetitPotam/coercion) to obtain a "
                    "certificate as a relayed victim (e.g. a DC)"
                ),
                details={"esc_type": "ESC8", "ca": ca_name},
            ))
        if adcs.get("enforce_encrypt_rpc") is False:  # ESC11 (known-not-enforced)
            findings.append(Finding(
                category=Category.ADCS_ABUSE,
                severity=Severity.HIGH,
                principal_sid="S-1-5-11",
                principal_name="Authenticated Users",
                target_dn=ca_dn,
                target_name=ca_name,
                target_class="pki",
                description=(
                    f"ESC11: CA '{ca_name}' does not enforce encrypted RPC "
                    "enrollment (IF_ENFORCEENCRYPTICERTREQUEST off) — ICPR RPC "
                    "requests can be NTLM-relayed"
                ),
                details={"esc_type": "ESC11", "ca": ca_name},
            ))
        # ESC7 from the CA role-security (registry) DACL — the real Manage CA /
        # Manage Certificates rights (LDAP object DACL below is separate).
        for ace in adcs.get("ca_security") or []:
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            tsid = ace.get("trustee_sid", "")
            if not tsid or _adcs_enroller_privileged(tsid):
                continue
            mask = ace.get("access_mask", 0)
            ca_rights = []
            if mask & 0x01:
                ca_rights.append("ManageCA")
            if mask & 0x02:
                ca_rights.append("ManageCertificates")
            if not ca_rights:
                continue
            tname = _resolve_name(tsid, sid_map, domain)
            findings.append(Finding(
                category=Category.ADCS_ABUSE,
                severity=Severity.CRITICAL,
                principal_sid=tsid,
                principal_name=tname,
                target_dn=ca_dn,
                target_name=ca_name,
                target_class="pki",
                description=(
                    f"ESC7: {tname} has {', '.join(ca_rights)} on CA "
                    f"'{ca_name}' (CA role security) — can manage CA / issue certs"
                ),
                rights=ca_rights,
                details={"esc_type": "ESC7", "ca": ca_name, "source": "ca_security"},
            ))

        if editf_san2:
            findings.append(Finding(
                category=Category.ADCS_ABUSE,
                severity=Severity.CRITICAL,
                principal_sid=ca.get("object_sid", ""),
                principal_name=ca_name,
                target_dn=ca_dn,
                target_name=ca_name,
                target_class="pki",
                description=(
                    f"ESC6a: CA '{ca_name}' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled — "
                    "any enrollee can specify arbitrary SAN in requests"
                ),
                details={"esc_type": "ESC6a", "ca": ca_name, "editf_san2": True},
            ))

        for ace in ca.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            mask = ace.get("access_mask", 0)
            trustee_sid = ace.get("trustee_sid", "")
            if not trustee_sid:
                continue

            # Start with standard rights, then add CA-specific ones
            rights_list = _extract_acl_rights(ace)

            # ManageCA (0x01) and ManageCertificates (0x02) specific to CA objects.
            # Only flag these when generic/broad access rights aren't already present,
            # since 0x01/0x02 collide with DS_LIST_CONTENTS/DS_READ_PROPERTY.
            has_broad = mask & (AccessMask.GENERIC_ALL | AccessMask.GENERIC_WRITE | AccessMask.WRITE_DAC | AccessMask.WRITE_OWNER)
            if mask & 0x01 and not has_broad:
                rights_list.append("ManageCA")
            if mask & 0x02 and not has_broad:
                rights_list.append("ManageCertificates")

            if rights_list and not _is_builtin(trustee_sid):
                trustee_name = _resolve_name(trustee_sid, sid_map, domain)

                # ESC7: ManageCA or ManageCertificates
                if "ManageCA" in rights_list or "ManageCertificates" in rights_list or "GenericAll" in rights_list:
                    findings.append(Finding(
                        category=Category.ADCS_ABUSE,
                        severity=Severity.CRITICAL,
                        principal_sid=trustee_sid,
                        principal_name=trustee_name,
                        target_dn=ca_dn,
                        target_name=ca_name,
                        target_class="pki",
                        description=(
                            f"ESC7: {trustee_name} has {', '.join(rights_list)} on CA "
                            f"'{ca_name}' — can manage CA configuration"
                        ),
                        rights=rights_list,
                        details={"esc_type": "ESC7", "ca": ca_name},
                    ))

                # ESC6b: ManageCA without EDITF enabled = can enable it
                if ("ManageCA" in rights_list or "GenericAll" in rights_list) and not editf_san2:
                    findings.append(Finding(
                        category=Category.ADCS_ABUSE,
                        severity=Severity.HIGH,
                        principal_sid=trustee_sid,
                        principal_name=trustee_name,
                        target_dn=ca_dn,
                        target_name=ca_name,
                        target_class="pki",
                        description=(
                            f"ESC6b: {trustee_name} has ManageCA on '{ca_name}' — "
                            "can enable EDITF_ATTRIBUTESUBJECTALTNAME2 to allow arbitrary SAN"
                        ),
                        rights=rights_list,
                        details={"esc_type": "ESC6b", "ca": ca_name},
                    ))

                # GoldenCert: WriteDACL/WriteOwner/GenericAll on CA = CA private key access
                if any(r in rights_list for r in ("GenericAll", "WriteDACL", "WriteOwner")):
                    findings.append(Finding(
                        category=Category.ADCS_ABUSE,
                        severity=Severity.CRITICAL,
                        principal_sid=trustee_sid,
                        principal_name=trustee_name,
                        target_dn=ca_dn,
                        target_name=ca_name,
                        target_class="pki",
                        description=(
                            f"GoldenCert: {trustee_name} has {', '.join(rights_list)} on CA "
                            f"'{ca_name}' — can potentially extract CA private key to forge certificates"
                        ),
                        rights=rights_list,
                        details={"esc_type": "GoldenCert", "ca": ca_name},
                    ))

    # ESC9/ESC10: Template conditions for weak mapping / no security extension
    # These require DC registry values (StrongCertificateBindingEnforcement,
    # CertificateMappingMethods) which may be present in collection metadata.
    dc_registry = {}
    for obj in objects:
        if obj.get("object_class") == "dc_registry":
            dc_registry = obj.get("properties", {})
            break

    strong_binding = 1  # Default: 1 = compatibility mode
    try:
        strong_binding = int(dc_registry.get("StrongCertificateBindingEnforcement", 1))
    except (ValueError, TypeError):
        pass

    cert_mapping = 0x1F  # Default: all methods enabled
    try:
        cert_mapping = int(dc_registry.get("CertificateMappingMethods", 0x1F))
    except (ValueError, TypeError):
        pass

    for tmpl in cert_templates:
        props = tmpl.get("properties", {})
        tmpl_name = tmpl.get("name", tmpl.get("dn", ""))
        tmpl_dn = tmpl.get("dn", "")
        schema_version = 0
        try:
            schema_version = int(props.get("msPKI-Template-Schema-Version", 0))
        except (ValueError, TypeError):
            pass

        # msPKI-Enrollment-Flag bit 0x00080000 = CT_FLAG_NO_SECURITY_EXTENSION
        enrollment_flag = 0
        try:
            enrollment_flag = int(props.get("msPKI-Enrollment-Flag", 0))
        except (ValueError, TypeError):
            pass
        no_security_ext = bool(enrollment_flag & 0x00080000)

        # ESC9: No security extension in certificate + weak binding enforcement
        # Condition: no szOID_NTDS_CA_SECURITY_EXT and StrongCertificateBindingEnforcement != 2
        if no_security_ext and strong_binding != 2:
            for ace in tmpl.get("dacl", []):
                trustee_sid = ace.get("trustee_sid", "")
                if not trustee_sid:
                    continue
                if _can_enroll(ace) and not _is_builtin(trustee_sid):
                    trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                    findings.append(Finding(
                        category=Category.ADCS_ABUSE,
                        severity=Severity.HIGH,
                        principal_sid=trustee_sid,
                        principal_name=trustee_name,
                        target_dn=tmpl_dn,
                        target_name=tmpl_name,
                        target_class="certtemplate",
                        description=(
                            f"ESC9a: Template '{tmpl_name}' has CT_FLAG_NO_SECURITY_EXTENSION "
                            f"and StrongCertificateBindingEnforcement={strong_binding} (not 2) — "
                            "certificate mapping bypass possible"
                        ),
                        rights=["Enroll"],
                        details={
                            "esc_type": "ESC9a",
                            "template": tmpl_name,
                            "strong_binding": strong_binding,
                        },
                    ))

        # ESC10: Weak certificate mapping with schema v1 templates or UPN mapping
        # CertificateMappingMethods & 0x04 = UPN mapping enabled
        upn_mapping = bool(cert_mapping & 0x04)
        if upn_mapping and strong_binding != 2:
            # Schema v1 templates or templates without security extension
            if schema_version == 1 or no_security_ext:
                for ace in tmpl.get("dacl", []):
                    trustee_sid = ace.get("trustee_sid", "")
                    if not trustee_sid:
                        continue
                    if _can_enroll(ace) and not _is_builtin(trustee_sid):
                        trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                        variant = "ESC10a" if schema_version == 1 else "ESC10b"
                        findings.append(Finding(
                            category=Category.ADCS_ABUSE,
                            severity=Severity.HIGH,
                            principal_sid=trustee_sid,
                            principal_name=trustee_name,
                            target_dn=tmpl_dn,
                            target_name=tmpl_name,
                            target_class="certtemplate",
                            description=(
                                f"{variant}: Template '{tmpl_name}' vulnerable to weak certificate "
                                f"mapping (UPN mapping enabled, StrongCertBinding={strong_binding}, "
                                f"schema v{schema_version}) — account takeover via certificate"
                            ),
                            rights=["Enroll"],
                            details={
                                "esc_type": variant,
                                "template": tmpl_name,
                                "cert_mapping": cert_mapping,
                                "strong_binding": strong_binding,
                                "schema_version": schema_version,
                            },
                        ))

    # ESC13: Issuance policy with OID group link
    # If a template has an issuance policy that links to a group via OID,
    # enrolling gets membership in that group.
    # Build a lookup: OID value -> group DN(s) from oidobject entries.
    oid_objects = [o for o in objects if o.get("object_class") == "oidobject"]
    oid_to_group: dict[str, str] = {}
    for oid_obj in oid_objects:
        oid_props = oid_obj.get("properties", {})
        oid_val = oid_props.get("msPKI-Cert-Template-OID", "")
        group_link = oid_props.get("msDS-OIDToGroupLink", "")
        if oid_val and group_link:
            oid_to_group[oid_val] = group_link

    for tmpl in cert_templates:
        props = tmpl.get("properties", {})
        tmpl_name = tmpl.get("name", tmpl.get("dn", ""))
        tmpl_dn = tmpl.get("dn", "")
        issuance_policies = props.get("msPKI-Certificate-Policy", [])
        if isinstance(issuance_policies, str):
            issuance_policies = [issuance_policies]

        # Check if any issuance policy OID has a group link via OID objects
        oid_group_links = [
            oid_to_group[p] for p in issuance_policies if p in oid_to_group
        ]

        if issuance_policies and oid_group_links:
            enrollment_flag = 0
            try:
                enrollment_flag = int(props.get("msPKI-Enrollment-Flag", 0))
            except (ValueError, TypeError):
                pass
            ra_sig = 0
            try:
                ra_sig = int(props.get("msPKI-RA-Signature", 0))
            except (ValueError, TypeError):
                pass
            manager_approval = bool(enrollment_flag & 0x00000002)

            if not manager_approval and ra_sig == 0:
                for ace in tmpl.get("dacl", []):
                    trustee_sid = ace.get("trustee_sid", "")
                    if not trustee_sid:
                        continue
                    if _can_enroll(ace) and not _is_builtin(trustee_sid):
                        trustee_name = _resolve_name(trustee_sid, sid_map, domain)
                        group_names = ", ".join(oid_group_links[:3])
                        findings.append(Finding(
                            category=Category.ADCS_ABUSE,
                            severity=Severity.HIGH,
                            principal_sid=trustee_sid,
                            principal_name=trustee_name,
                            target_dn=tmpl_dn,
                            target_name=tmpl_name,
                            target_class="certtemplate",
                            description=(
                                f"ESC13: {trustee_name} can enroll in template '{tmpl_name}' "
                                f"with issuance policy linked to group(s): {group_names} — "
                                "enrollment grants group membership via OID link"
                            ),
                            rights=["Enroll"],
                            details={
                                "esc_type": "ESC13",
                                "template": tmpl_name,
                                "oid_group_links": oid_group_links,
                            },
                        ))

    # WritePKINameFlag / WritePKIEnrollmentFlag: WriteProperty on template PKI attributes
    for tmpl in cert_templates:
        tmpl_name = tmpl.get("name", tmpl.get("dn", ""))
        tmpl_dn = tmpl.get("dn", "")

        for ace in tmpl.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            mask = ace.get("access_mask", 0)
            trustee_sid = ace.get("trustee_sid", "")
            object_type = ace.get("object_type")
            if not trustee_sid or not (mask & AccessMask.DS_WRITE_PROPERTY):
                continue
            if _is_builtin(trustee_sid):
                continue

            pki_right = ""
            if object_type == GUID_PKI_NAME_FLAG:
                pki_right = "WritePKINameFlag"
            elif object_type == GUID_PKI_ENROLLMENT_FLAG:
                pki_right = "WritePKIEnrollmentFlag"
            else:
                continue

            trustee_name = _resolve_name(trustee_sid, sid_map, domain)
            findings.append(Finding(
                category=Category.ADCS_ABUSE,
                severity=Severity.HIGH,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=tmpl_dn,
                target_name=tmpl_name,
                target_class="certtemplate",
                description=(
                    f"{pki_right}: {trustee_name} can write {pki_right.replace('Write', '')} "
                    f"on template '{tmpl_name}' — can modify template to enable SAN supply or enrollment flags"
                ),
                rights=[pki_right],
                details={"esc_type": pki_right, "template": tmpl_name},
            ))

    return findings


def _check_trust_abuse(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Check 14: Trust and forest trust abuse paths.

    Analyzes trustedDomain objects for dangerous trust configurations and
    checks for SIDHistory on user/computer accounts.
    """
    findings: list[Finding] = []

    # Trust direction constants
    TRUST_INBOUND = 1
    TRUST_OUTBOUND = 2
    TRUST_BIDIRECTIONAL = 3

    trust_dir_names = {
        TRUST_INBOUND: "Inbound",
        TRUST_OUTBOUND: "Outbound",
        TRUST_BIDIRECTIONAL: "Bidirectional",
    }

    # Check trustedDomain objects
    for obj in objects:
        if obj.get("object_class") != "trusteddomain":
            continue

        props = obj.get("properties", {})
        trust_name = obj.get("name", obj.get("dn", ""))

        trust_direction = 0
        try:
            trust_direction = int(props.get("trustDirection", 0))
        except (ValueError, TypeError):
            pass

        trust_attributes = 0
        try:
            trust_attributes = int(props.get("trustAttributes", 0))
        except (ValueError, TypeError):
            pass

        dir_name = trust_dir_names.get(trust_direction, f"Unknown({trust_direction})")

        # TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20
        is_intra_forest = bool(trust_attributes & 0x20)
        # TRUST_ATTRIBUTE_FILTER_SIDS = 0x04
        sid_filtering = bool(trust_attributes & 0x04)

        desc_parts = [f"Trust to '{trust_name}' — {dir_name}"]
        if not is_intra_forest:
            desc_parts.append("EXTERNAL/FOREST trust")
        if not sid_filtering and not is_intra_forest:
            desc_parts.append("SID FILTERING DISABLED — SIDHistory abuse possible")

        severity = Severity.MEDIUM
        if trust_direction in (TRUST_INBOUND, TRUST_BIDIRECTIONAL) and not sid_filtering and not is_intra_forest:
            severity = Severity.HIGH

        findings.append(Finding(
            category=Category.TRUST_ABUSE,
            severity=severity,
            principal_sid="",
            principal_name=domain,
            target_dn=obj.get("dn", ""),
            target_name=trust_name,
            target_class="trusteddomain",
            description="; ".join(desc_parts),
            details={
                "trust_direction": dir_name,
                "sid_filtering": sid_filtering,
                "trust_attributes": trust_attributes,
            },
        ))

    # Check for SIDHistory on user/computer accounts
    for obj in objects:
        if obj.get("object_class") not in ("user", "computer"):
            continue

        props = obj.get("properties", {})
        sid_history = props.get("sIDHistory", [])
        if isinstance(sid_history, str):
            sid_history = [sid_history]
        if not sid_history:
            continue

        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))

        # Check if any SIDHistory entries are for high-value targets
        hv_entries = [s for s in sid_history if _is_high_value(s)]

        severity = Severity.CRITICAL if hv_entries else Severity.HIGH

        findings.append(Finding(
            category=Category.TRUST_ABUSE,
            severity=severity,
            principal_sid=sid,
            principal_name=name,
            target_dn=obj.get("dn", ""),
            target_name=name,
            target_class=obj.get("object_class", ""),
            description=(
                f"{name} has SIDHistory entries: {', '.join(sid_history[:3])}"
                + (" — includes HIGH-VALUE SID" if hv_entries else "")
            ),
            details={"sid_history": sid_history, "high_value_entries": hv_entries},
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 15b: Session abuse (HasSession edges from network collection)
# ---------------------------------------------------------------------------
def _check_session_abuse(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
    *,
    sessions: list[dict] | None = None,
) -> list[Finding]:
    """Analyse session data for credential-theft lateral movement paths.

    When a high-privilege user has a session on a computer where a
    lower-privilege user has local admin access, the low-privilege user
    can extract the high-privilege user's credentials (Kerberos tickets,
    NT hash, potentially cleartext password).
    """
    if not sessions:
        return []

    findings: list[Finding] = []

    # Build reverse SID map: name -> SID
    name_to_sid: dict[str, str] = {}
    for sid, name in sid_map.items():
        name_to_sid[name.lower()] = sid
    for obj in objects:
        sid = obj.get("object_sid") or ""
        name = obj.get("name", "")
        if sid and name:
            name_to_sid[name.lower()] = sid

    # Identify which users have sessions on which hosts
    host_sessions: dict[str, list[str]] = {}  # host -> [usernames]
    for sess in sessions:
        host = sess.get("target_host", "")
        user = sess.get("username", "")
        if host and user:
            host_sessions.setdefault(host.lower(), []).append(user)

    # Find high-value users with sessions
    hv_users_with_sessions: list[tuple[str, str, str]] = []  # (user, user_sid, host)
    for host, users in host_sessions.items():
        for user in users:
            user_lower = user.lower()
            # Strip domain prefix
            if "\\" in user_lower:
                user_lower = user_lower.split("\\", 1)[1]
            user_sid = name_to_sid.get(user_lower, "")
            if user_sid and _is_high_value(user_sid):
                hv_users_with_sessions.append((user, user_sid, host))

    for user, user_sid, host in hv_users_with_sessions:
        findings.append(Finding(
            category=Category.SESSION_ABUSE,
            severity=Severity.HIGH,
            principal_sid=user_sid,
            principal_name=user,
            target_dn="",
            target_name=host,
            target_class="session",
            description=(
                f"High-value user {user} has an active session on {host}. "
                f"If an attacker gains local admin on this host, they can "
                f"extract privileged credentials."
            ),
            details={
                "user": user,
                "host": host,
            },
        ))

    # Report total session count as info
    total_sessions = sum(len(v) for v in host_sessions.values())
    if total_sessions > 0:
        findings.append(Finding(
            category=Category.SESSION_ABUSE,
            severity=Severity.INFO,
            principal_sid="",
            principal_name="Summary",
            target_dn="",
            target_name="Session Summary",
            target_class="session",
            description=(
                f"{total_sessions} active session(s) discovered across "
                f"{len(host_sessions)} host(s)."
            ),
            details={
                "total_sessions": total_sessions,
                "total_hosts": len(host_sessions),
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 15c: Local group access (AdminTo / CanRDP / ExecuteDCOM / CanPSRemote)
# ---------------------------------------------------------------------------
def _check_local_access(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
    *,
    local_group_members: list[dict] | None = None,
) -> list[Finding]:
    """Analyse local group membership for lateral movement edges.

    Reports non-builtin principals that are members of local
    Administrators, Remote Desktop Users, Distributed COM Users, or
    Remote Management Users on domain computers.
    """
    if not local_group_members:
        return []

    findings: list[Finding] = []

    # Group by edge type
    edge_groups: dict[str, list[dict]] = {}
    for member in local_group_members:
        edge_type = member.get("edge_type", "Unknown")
        edge_groups.setdefault(edge_type, []).append(member)

    edge_descriptions = {
        "AdminTo": (
            "Local Administrator access — can execute commands, dump credentials, "
            "and extract Kerberos tickets from these hosts."
        ),
        "CanRDP": (
            "Remote Desktop access — can interactively log on to these hosts."
        ),
        "ExecuteDCOM": (
            "Distributed COM access — can execute commands via DCOM lateral movement."
        ),
        "CanPSRemote": (
            "PowerShell Remoting access — can execute commands via WinRM."
        ),
    }

    for edge_type, members in edge_groups.items():
        # Filter to non-builtin, non-expected members
        interesting: list[dict] = []
        for m in members:
            member_sid = m.get("member_sid", "")
            # Skip well-known expected SIDs (SYSTEM, Administrators, Domain Admins)
            if member_sid in WELL_KNOWN_SIDS:
                continue
            if _is_builtin(member_sid):
                continue
            interesting.append(m)

        if not interesting:
            continue

        # Resolve names
        affected = []
        for m in interesting:
            member_sid = m.get("member_sid", "")
            member_name = m.get("member_name", "") or sid_map.get(member_sid, member_sid)
            host = m.get("target_host", "")
            affected.append(f"{member_name} -> {host}")

        # Count unique non-builtin principals
        unique_principals = len({m.get("member_sid", "") for m in interesting})
        unique_hosts = len({m.get("target_host", "") for m in interesting})

        if edge_type == "AdminTo":
            severity = Severity.HIGH
        elif edge_type in ("CanRDP", "CanPSRemote"):
            severity = Severity.MEDIUM
        else:
            severity = Severity.INFO

        findings.append(Finding(
            category=Category.LOCAL_ACCESS,
            severity=severity,
            principal_sid="",
            principal_name=f"{unique_principals} principal(s)",
            target_dn="",
            target_name=f"{edge_type} ({unique_hosts} hosts)",
            target_class="local-group",
            description=(
                f"{len(interesting)} {edge_type} relationship(s): "
                f"{unique_principals} principal(s) across {unique_hosts} host(s). "
                f"{edge_descriptions.get(edge_type, '')}"
            ),
            details={
                "edge_type": edge_type,
                "relationships": affected[:20],
                "total": len(interesting),
                "unique_principals": unique_principals,
                "unique_hosts": unique_hosts,
            },
        ))

    return findings


def _adcs_domain_sid_for(sid: str, domain_sids: list[str]) -> str:
    """Return the domain object SID that owns `sid` (longest matching prefix)."""
    best = ""
    for d in domain_sids:
        if sid.startswith(d) and len(d) > len(best):
            best = d
    if best:
        return best
    return domain_sids[0] if len(domain_sids) == 1 else ""


def _add_adcs_edges(graph, sid_names, objects, sid_map):
    """Add ADCS ESC escalation edges: abusing principal -> its domain object.

    Derived directly from the ADCS findings check so every ESC the check
    detects (ESC1/2/3/4/6/7/9/GoldenCert, and any added later) becomes a
    pathfinding edge with no duplicated detection logic. Each ESC yields a
    certificate authenticating as a privileged principal => domain compromise.
    Findings whose 'principal' is not an attacker-controllable object (e.g.
    ESC6a, where it is the CA itself) are skipped.
    """
    domain_sids = [o.get("object_sid") for o in objects
                   if o.get("object_class") == "domain" and o.get("object_sid")]
    if not domain_sids:
        return
    obj_class = {o.get("object_sid"): (o.get("object_class") or "").lower()
                 for o in objects if o.get("object_sid")}

    for f in _check_adcs(objects, sid_map, ""):
        psid = f.principal_sid
        esc = f.details.get("esc_type", "")
        if not psid or not esc or _is_builtin(psid):
            continue
        cls = obj_class.get(psid, "")
        if cls and cls not in _PRINCIPAL_CLASSES:
            continue  # e.g. ESC6a: the "principal" is the CA object, not an actor
        norm = esc[:-1] if esc[-1] in ("a", "b") else esc   # ESC6a/9a -> ESC6/9
        dom = _adcs_domain_sid_for(psid, domain_sids)
        if dom and psid != dom:
            graph[psid].add((dom, "ADCS" + norm))


def _ca_has_web_enrollment(ca: dict) -> bool:
    """True if a CA exposes web enrollment (ESC8 relay candidate).

    Pure-LDAP signal: an explicit web-enrollment flag (e.g. from a BloodHound
    import), or the presence of CES enrollment-server URIs. Classic certsrv
    role detection requires an active HTTP probe (not done here).
    """
    props = ca.get("properties", {}) or {}
    if props.get("webenrollment") or props.get("hasenrollmentendpoint"):
        return True
    servers = props.get("msPKI-Enrollment-Servers") or props.get("msPKI-Enrollment-Server")
    return bool(servers)


def _add_esc8_edges(graph, objects, domain_sids):
    """Add ESC8 edges: Domain Computers (515) -> domain for web-enroll CAs.

    ESC8 = coerce a DC's NTLM auth and relay it to the CA's web enrollment to
    obtain a DC certificate -> DCSync. Any domain machine can coerce, so we add
    one edge from the Domain Computers group to the domain; computers reach it
    via their (already modelled) primary-group membership.
    """
    if not domain_sids:
        return
    vuln_domains = set()
    for ca in objects:
        if ca.get("object_class") == "pki" and _ca_has_web_enrollment(ca):
            dom = _adcs_domain_sid_for(ca.get("object_sid") or "", domain_sids)
            if dom:
                vuln_domains.add(dom)
    for dom in vuln_domains:
        graph[f"{dom}-515"].add((dom, "ADCSESC8"))


def _add_coercion_edges(graph, objects, domain_sids):
    """Add CoerceToTGT edges: non-DC unconstrained-delegation host -> domain.

    An attacker controlling a host with unconstrained delegation can coerce a
    DC (PetitPotam/PrinterBug) to authenticate to it, capture the DC's TGT, and
    DCSync — i.e. domain compromise. DCs themselves (SERVER_TRUST) are excluded
    (already Tier Zero), as are disabled accounts.
    """
    if not domain_sids:
        return
    for obj in objects:
        if obj.get("object_class") not in ("user", "computer"):
            continue
        uac = _get_uac(obj)
        if not (uac & UAC.TRUSTED_FOR_DELEGATION):
            continue
        if uac & UAC.SERVER_TRUST or uac & UAC.ACCOUNT_DISABLE:
            continue
        sid = obj.get("object_sid") or ""
        dom = _adcs_domain_sid_for(sid, domain_sids)
        if sid and dom and sid != dom:
            graph[sid].add((dom, "CoerceToTGT"))


def _add_network_edges(
    graph: dict[str, set[tuple[str, str]]],
    sid_names: dict[str, str],
    objects: list[dict],
    sid_map: dict[str, str],
    sessions: list[dict] | None = None,
    local_group_members: list[dict] | None = None,
) -> None:
    """Add HasSession and local-access edges to an attack graph.

    Session edges (HasSession):
      Computer --[HasSession]--> User
      The computer "possesses" the user's credentials.  If you compromise
      the computer, you gain the user's credentials.  In graph terms the
      edge goes from the host (source of compromise) to the user (target
      of credential theft).

    Local-access edges (AdminTo, CanRDP, ExecuteDCOM, CanPSRemote):
      User --[AdminTo/...]--> Computer
      The user can access the computer with the given privilege level.
    """
    # Build hostname -> computer SID map
    host_to_sid: dict[str, str] = {}
    for obj in objects:
        if obj.get("object_class") != "computer":
            continue
        sid = obj.get("object_sid", "")
        if not sid:
            continue
        name = obj.get("name", "")
        props = obj.get("properties", {})
        dns_name = props.get("dNSHostName", "")

        if name:
            host_to_sid[name.lower().rstrip("$")] = sid
            host_to_sid[name.lower()] = sid
        if dns_name:
            host_to_sid[dns_name.lower()] = sid

    # Build username -> user SID map
    name_to_sid: dict[str, str] = {}
    for s, n in sid_map.items():
        name_to_sid[n.lower()] = s
    for obj in objects:
        sid = obj.get("object_sid", "")
        name = obj.get("name", "")
        if sid and name:
            name_to_sid[name.lower()] = sid

    # HasSession edges: computer -> user (computer possesses user credentials)
    if sessions:
        for sess in sessions:
            user = sess.get("username", "")
            host = sess.get("target_host", "")
            if not user or not host:
                continue
            # Resolve user to SID
            user_lower = user.lower()
            if "\\" in user_lower:
                user_lower = user_lower.split("\\", 1)[1]
            user_sid = name_to_sid.get(user_lower, "")
            # Resolve host to SID
            host_sid = host_to_sid.get(host.lower(), "")
            if user_sid and host_sid and user_sid != host_sid:
                graph[host_sid].add((user_sid, "HasSession"))
                if host_sid not in sid_names and host:
                    sid_names[host_sid] = host
                if user_sid not in sid_names and user:
                    sid_names[user_sid] = user

    # Local-access edges: member -> computer
    if local_group_members:
        for member in local_group_members:
            member_sid = member.get("member_sid", "")
            host = member.get("target_host", "")
            edge_type = member.get("edge_type", "AdminTo")
            if not member_sid or not host:
                continue
            host_sid = host_to_sid.get(host.lower(), "")
            if host_sid and member_sid != host_sid:
                graph[member_sid].add((host_sid, edge_type))
                if member_sid not in sid_names:
                    name = member.get("member_name", "") or sid_map.get(member_sid, member_sid)
                    sid_names[member_sid] = name
                if host_sid not in sid_names:
                    sid_names[host_sid] = host


def _acl_edge_labels(mask: int, object_type: str | None) -> list[str]:
    """Return granular edge labels for an ACE's access mask and object type.

    Uses actual AD permission/right names.  ``WriteProperty`` edges use
    colon notation (``WriteProperty:<attribute>``) to show the target
    attribute.
    """
    labels: list[str] = []

    # Mask-level rights — each flag tested individually
    if mask & AccessMask.GENERIC_ALL:
        labels.append("GenericAll")
    if mask & AccessMask.WRITE_DAC:
        labels.append("WriteDACL")
    if mask & AccessMask.WRITE_OWNER:
        labels.append("WriteOwner")
    if mask & AccessMask.GENERIC_WRITE:
        labels.append("GenericWrite")

    # Extended rights (DS_CONTROL_ACCESS)
    if mask & AccessMask.DS_CONTROL_ACCESS:
        if object_type is None:
            labels.append("AllExtendedRights")
        elif object_type in _DANGEROUS_EXTENDED_RIGHTS:
            labels.append(GUID_LABELS.get(object_type, object_type))

    # WriteProperty on specific dangerous attributes
    if mask & AccessMask.DS_WRITE_PROPERTY:
        if object_type is None:
            if "GenericWrite" not in labels:  # avoid redundancy with GenericWrite
                labels.append("WriteAllProperties")
        elif object_type in _DANGEROUS_WRITE_PROPS:
            # Shadow Credentials: use dedicated edge label for msDS-KeyCredentialLink
            if object_type == GUID_MSDS_KEY_CREDENTIAL_LINK:
                labels.append("WriteShadowCredentials")
            else:
                attr_name = GUID_LABELS.get(object_type, object_type)
                labels.append(f"WriteProperty:{attr_name}")

    return labels


def _check_shortest_paths(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
    *,
    sessions: list[dict] | None = None,
    local_group_members: list[dict] | None = None,
    azure_edges: list[dict] | None = None,
) -> list[Finding]:
    """Check 15: Shortest attack paths to high-value targets.

    Builds a directed attack graph from group membership, ACL abuse edges,
    ownership, and network-collected edges (HasSession, AdminTo, CanRDP,
    ExecuteDCOM, CanPSRemote), then uses multi-source reverse BFS from
    high-value targets to find shortest paths from any non-builtin principal.
    """
    findings: list[Finding] = []

    # Build the full attack graph (includes delegation, RBCD, SID history,
    # GPLink, Contains, trust edges — not just MemberOf/ACL/Owns/Network)
    graph, sid_names, _ = _build_attack_graph(
        objects, sid_map=sid_map,
        sessions=sessions,
        local_group_members=local_group_members,
        azure_edges=azure_edges,
    )

    # Map SID -> object_class so we can keep path SOURCES to attacker-
    # controllable principals (users/groups/computers), not GPOs/OUs/etc.
    obj_class: dict[str, str] = {}
    for obj in objects:
        s = obj.get("object_sid") or ""
        if s:
            obj_class[s] = (obj.get("object_class") or "").lower()

    # Find all high-value target SIDs (well-known/RID matches, computed Tier
    # Zero objects incl. Azure tenant, plus DCs detected by RID-516 membership).
    hv_sids = _high_value_target_sids(objects, graph, obj_class)

    if not hv_sids:
        return findings

    # Build reverse graph for BFS from targets backward
    reverse_graph: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for src, edges in graph.items():
        for tgt, label in edges:
            reverse_graph[tgt].add((src, label))

    # Multi-source reverse BFS from all high-value targets
    dist: dict[str, int] = {}
    parent: dict[str, tuple[str, str]] = {}  # sid -> (next_toward_hv, edge_label)
    nearest_hv: dict[str, str] = {}

    queue: deque[tuple[str, int]] = deque()
    for hv_sid in hv_sids:
        dist[hv_sid] = 0
        nearest_hv[hv_sid] = hv_sid
        queue.append((hv_sid, 0))

    max_depth = SHORTEST_PATH_MAX_DEPTH

    while queue:
        current, d = queue.popleft()
        if d >= max_depth:
            continue

        for predecessor, edge_label in reverse_graph.get(current, set()):
            if predecessor in dist:
                continue
            dist[predecessor] = d + 1
            parent[predecessor] = (current, edge_label)
            nearest_hv[predecessor] = nearest_hv[current]
            queue.append((predecessor, d + 1))

    # Report findings for reachable non-builtin, non-HV principals
    for sid in sorted(dist.keys(), key=lambda s: dist[s]):
        d = dist[sid]
        if d == 0 or _is_builtin(sid) or sid in hv_sids:
            continue
        # A path SOURCE must be something an attacker can control — a
        # user/group/computer principal. Skip GPOs, OUs, containers, the
        # domain object, etc. (they appear via GPLink/Contains edges but
        # are not attacker-controllable starting points).
        cls = obj_class.get(sid, "")
        if cls and cls not in _PRINCIPAL_CLASSES:
            continue

        # Reconstruct path with edge labels
        path_sids: list[str] = [sid]
        path_edges: list[str] = []
        current = sid
        while current in parent:
            next_node, edge_label = parent[current]
            path_edges.append(edge_label)
            path_sids.append(next_node)
            current = next_node

        path_names = [
            sid_names.get(s, _resolve_name(s, sid_map, domain))
            for s in path_sids
        ]
        target_name = path_names[-1]

        # Build description with edge labels:  name -[label]-> name -[label]-> ...
        desc_parts: list[str] = [path_names[0]]
        for i, edge in enumerate(path_edges):
            desc_parts.append(f"-[{edge}]-> {path_names[i + 1]}")
        path_str = " ".join(desc_parts)

        # Any path to a Tier-Zero target = full domain/forest compromise, which
        # is CRITICAL impact regardless of hop count. The hop count (shown in the
        # report) conveys effort/likelihood, not impact.
        severity = Severity.CRITICAL

        findings.append(Finding(
            category=Category.SHORTEST_PATH,
            severity=severity,
            principal_sid=sid,
            principal_name=path_names[0],
            target_dn="",
            target_name=target_name,
            target_class="high-value",
            description=f"Shortest path ({d} hops): {path_str}",
            details={
                "path_sids": path_sids,
                "path_names": path_names,
                "path_edges": path_edges,
                "depth": d,
                "target_hv_sid": nearest_hv[sid],
            },
        ))

    return findings


def paths_to_target(
    data: dict,
    target: str,
    source: str | None = None,
    max_depth: int = SHORTEST_PATH_MAX_DEPTH,
) -> list[Finding]:
    """Shortest attack paths to an ARBITRARY target (not just Tier Zero).

    Resolves ``target`` (and optional ``source``) by name/SID/sAMAccountName,
    builds the attack graph, and reverse-BFS from the target. With no source,
    returns paths from every controllable principal that can reach the target;
    with a source, returns the single source->target path. Returns Finding
    objects (reusing the shortest-path schema) so existing renderers work.
    """
    objects = data.get("objects", [])
    sid_map = dict(data.get("sid_map", {}))
    domain = data.get("meta", {}).get("domain", "unknown")
    for obj in objects:
        sid = obj.get("object_sid")
        name = obj.get("name") or obj.get("dn", "")
        if sid and name and sid not in sid_map:
            sid_map[sid] = name

    graph, sid_names, _ = _build_attack_graph(
        objects, sid_map=sid_map,
        sessions=data.get("sessions"),
        local_group_members=data.get("local_group_members"),
        azure_edges=data.get("azure_edges"),
    )
    target_sids = _resolve_owned_sids([target], objects, sid_map)
    if not target_sids:
        return []
    source_sids = _resolve_owned_sids([source], objects, sid_map) if source else None

    obj_class = {o.get("object_sid"): (o.get("object_class") or "").lower()
                 for o in objects if o.get("object_sid")}

    reverse_graph: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for src, edges in graph.items():
        for tgt, label in edges:
            reverse_graph[tgt].add((src, label))

    findings: list[Finding] = []
    for tsid in target_sids:
        dist: dict[str, int] = {tsid: 0}
        parent: dict[str, tuple[str, str]] = {}
        queue: deque[tuple[str, int]] = deque([(tsid, 0)])
        while queue:
            current, d = queue.popleft()
            if d >= max_depth:
                continue
            for predecessor, edge_label in reverse_graph.get(current, set()):
                if predecessor in dist:
                    continue
                dist[predecessor] = d + 1
                parent[predecessor] = (current, edge_label)
                queue.append((predecessor, d + 1))

        target_name = sid_names.get(tsid, _resolve_name(tsid, sid_map, domain))
        for sid in sorted(dist, key=lambda s: dist[s]):
            d = dist[sid]
            if d == 0:
                continue
            if source_sids is not None:
                if sid not in source_sids:
                    continue
            else:
                cls = obj_class.get(sid, "")
                if (cls and cls not in _PRINCIPAL_CLASSES) or _is_builtin(sid):
                    continue

            path_sids = [sid]
            path_edges: list[str] = []
            current = sid
            while current in parent:
                next_node, edge_label = parent[current]
                path_edges.append(edge_label)
                path_sids.append(next_node)
                current = next_node
            path_names = [sid_names.get(s, _resolve_name(s, sid_map, domain))
                          for s in path_sids]
            desc_parts = [path_names[0]]
            for i, edge in enumerate(path_edges):
                desc_parts.append(f"-[{edge}]-> {path_names[i + 1]}")
            severity = (Severity.CRITICAL if d <= 2
                        else Severity.HIGH if d <= 4 else Severity.MEDIUM)
            findings.append(Finding(
                category=Category.SHORTEST_PATH,
                severity=severity,
                principal_sid=sid,
                principal_name=path_names[0],
                target_dn="",
                target_name=target_name,
                target_class=obj_class.get(tsid, ""),
                description=f"Path ({d} hops): {' '.join(desc_parts)}",
                details={
                    "path_sids": path_sids,
                    "path_names": path_names,
                    "path_edges": path_edges,
                    "depth": d,
                    "target_sid": tsid,
                },
            ))
    return findings


def _high_value_target_sids(objects, graph, obj_class) -> set[str]:
    """All Tier-Zero / high-value target SIDs: well-known/RID matches, computed
    Tier-Zero objects (domain, Azure tenant/sub/KV, DCs), plus DCs detected by
    membership in the Domain Controllers group (RID 516)."""
    hv: set[str] = set()
    custom_rids = HIGH_VALUE_RIDS - TIER_ZERO_RIDS
    for obj in objects:
        sid = obj.get("object_sid") or ""
        if sid and (_is_high_value(sid) or is_tier_zero_object(obj, custom_rids)):
            hv.add(sid)
    dc_group_sids = {s for s in obj_class if s.rsplit("-", 1)[-1] == "516"}
    if dc_group_sids:
        for src, edges in graph.items():
            for dst, label in edges:
                if label == "MemberOf" and dst in dc_group_sids:
                    hv.add(src)
    return hv


def paths_to_tier_zero(
    data: dict,
    source: str,
    max_depth: int = SHORTEST_PATH_MAX_DEPTH,
) -> list[Finding]:
    """Shortest attack path from ``source`` to its NEAREST Tier-Zero target.

    Unlike :func:`paths_to_target` (which needs a named target), this finds the
    closest high-value target of ANY kind — on-prem Domain Admins / DC, the
    Entra tenant (via hybrid sync), an ADCS CA, etc. Used so that *any* principal
    that shows up on a path can be exported, even when the destination isn't DA.
    Returns SHORTEST_PATH Findings (one per resolved source SID).
    """
    objects = data.get("objects", [])
    sid_map = dict(data.get("sid_map", {}))
    domain = data.get("meta", {}).get("domain", "unknown")
    for obj in objects:
        sid = obj.get("object_sid")
        name = obj.get("name") or obj.get("dn", "")
        if sid and name and sid not in sid_map:
            sid_map[sid] = name

    graph, sid_names, _ = _build_attack_graph(
        objects, sid_map=sid_map,
        sessions=data.get("sessions"),
        local_group_members=data.get("local_group_members"),
        azure_edges=data.get("azure_edges"),
    )
    source_sids = _resolve_owned_sids([source], objects, sid_map)
    if not source_sids:
        return []
    obj_class = {o.get("object_sid"): (o.get("object_class") or "").lower()
                 for o in objects if o.get("object_sid")}
    hv_sids = _high_value_target_sids(objects, graph, obj_class)
    if not hv_sids:
        return []

    findings: list[Finding] = []
    for ssid in source_sids:
        # forward BFS from the source; first Tier-Zero node popped is nearest
        dist: dict[str, int] = {ssid: 0}
        parent: dict[str, tuple[str, str]] = {}
        queue: deque[str] = deque([ssid])
        hit: str | None = None
        while queue:
            cur = queue.popleft()
            if cur in hv_sids and cur != ssid:
                hit = cur
                break
            if dist[cur] >= max_depth:
                continue
            for nxt, label in graph.get(cur, set()):
                if nxt not in dist:
                    dist[nxt] = dist[cur] + 1
                    parent[nxt] = (cur, label)
                    queue.append(nxt)
        if hit is None:
            continue

        path_sids = [hit]
        path_edges: list[str] = []
        cur = hit
        while cur in parent:
            prev, label = parent[cur]
            path_edges.append(label)
            path_sids.append(prev)
            cur = prev
        path_sids.reverse()
        path_edges.reverse()
        path_names = [sid_names.get(s, _resolve_name(s, sid_map, domain))
                      for s in path_sids]
        d = len(path_edges)
        desc_parts = [path_names[0]]
        for i, edge in enumerate(path_edges):
            desc_parts.append(f"-[{edge}]-> {path_names[i + 1]}")
        severity = (Severity.CRITICAL if d <= 2
                    else Severity.HIGH if d <= 4 else Severity.MEDIUM)
        findings.append(Finding(
            category=Category.SHORTEST_PATH,
            severity=severity,
            principal_sid=ssid,
            principal_name=path_names[0],
            target_dn="",
            target_name=path_names[-1],
            target_class=obj_class.get(hit, ""),
            description=f"Path ({d} hops): {' '.join(desc_parts)}",
            details={
                "path_sids": path_sids,
                "path_names": path_names,
                "path_edges": path_edges,
                "depth": d,
                "target_sid": hit,
            },
        ))
    return findings


def tier_zero_reach(data: dict) -> dict[str, int]:
    """Map principal SID -> min hops to a Tier Zero target (from attack paths)."""
    result = analyze(data, categories={"paths"})
    reach: dict[str, int] = {}
    for f in result.findings:
        if f.category == Category.SHORTEST_PATH:
            sid = f.principal_sid
            d = f.details.get("depth", 99)
            if sid and (sid not in reach or d < reach[sid]):
                reach[sid] = d
    return reach


def name_to_sid_index(data: dict) -> dict[str, str]:
    """Lower-cased name / sAMAccountName -> SID, for resolving finding principals."""
    idx: dict[str, str] = {}
    for sid, name in (data.get("sid_map") or {}).items():
        if name:
            idx.setdefault(name.lower(), sid)
    for o in data.get("objects", []):
        sid = o.get("object_sid")
        if not sid:
            continue
        nm = o.get("name")
        if nm:
            idx.setdefault(nm.lower(), sid)
        sam = (o.get("properties") or {}).get("sAMAccountName")
        if sam:
            idx[sam.lower()] = sid   # sAMAccountName wins (scan findings use it)
    return idx


def _node_matches_predicate(obj: dict, pred: str) -> bool:
    """Evaluate a single ad-hoc query predicate against an object."""
    cls = (obj.get("object_class") or "").lower()
    props = obj.get("properties", {}) or {}
    uac = _get_uac(obj)
    p = pred.strip().lower()
    if not p:
        return True
    if p.startswith("type:"):
        return cls == p.split(":", 1)[1]
    if p.startswith("name:"):
        return p.split(":", 1)[1] in (obj.get("name", "") or "").lower()
    if p == "tier0":
        return is_tier_zero_object(obj)
    if p == "kerberoastable":
        spns = props.get("servicePrincipalName") or []
        return cls == "user" and bool(spns)
    if p == "asrep":
        return bool(uac & UAC.DONT_REQ_PREAUTH)
    if p == "unconstrained":
        return bool(uac & UAC.TRUSTED_FOR_DELEGATION) and not (uac & UAC.SERVER_TRUST)
    if p == "enabled":
        return not (uac & UAC.ACCOUNT_DISABLE)
    if p == "disabled":
        return bool(uac & UAC.ACCOUNT_DISABLE)
    if p == "admincount":
        return bool(props.get("adminCount"))
    raise ValueError(
        f"Unknown predicate: {pred!r} (use type:/name:/tier0/kerberoastable/"
        "asrep/unconstrained/enabled/disabled/admincount)"
    )


def query_graph(
    data: dict,
    predicates: list[str] | None = None,
    reaches: str | None = None,
    reachable_from: str | None = None,
    max_depth: int = SHORTEST_PATH_MAX_DEPTH,
) -> list[dict]:
    """Ad-hoc graph query: filter objects by predicates and/or reachability.

    predicates: ANDed node predicates (see _node_matches_predicate).
    reaches: keep only nodes with a path to this target ("tier0" = any Tier
        Zero node, else a resolved name/SID).
    reachable_from: keep only nodes reachable FROM this source principal.
    Returns dicts: {sid, name, type, tags}.
    """
    objects = data.get("objects", [])
    sid_map = dict(data.get("sid_map", {}))
    domain = data.get("meta", {}).get("domain", "unknown")
    for obj in objects:
        s = obj.get("object_sid")
        n = obj.get("name") or obj.get("dn", "")
        if s and n and s not in sid_map:
            sid_map[s] = n

    preds = predicates or []
    matched = {o.get("object_sid"): o for o in objects
               if o.get("object_sid")
               and all(_node_matches_predicate(o, p) for p in preds)}
    result_sids = set(matched)

    if reaches or reachable_from:
        graph, sid_names, _ = _build_attack_graph(
            objects, sid_map=sid_map,
            sessions=data.get("sessions"),
            local_group_members=data.get("local_group_members"),
            azure_edges=data.get("azure_edges"),
        )
    else:
        sid_names = {o.get("object_sid"): (o.get("name") or o.get("dn", ""))
                     for o in objects if o.get("object_sid")}

    if reaches:
        if reaches.lower() == "tier0":
            targets = {o.get("object_sid") for o in objects
                       if o.get("object_sid")
                       and (_is_high_value(o.get("object_sid")) or is_tier_zero_object(o))}
        else:
            targets = _resolve_owned_sids([reaches], objects, sid_map)
        reverse: dict[str, set[str]] = defaultdict(set)
        for src, edges in graph.items():
            for dst, _label in edges:
                reverse[dst].add(src)
        reach_set: set[str] = set()
        seen = set(targets)
        queue = deque((t, 0) for t in targets)
        while queue:
            cur, d = queue.popleft()
            if d >= max_depth:
                continue
            for pred in reverse.get(cur, set()):
                if pred in seen:
                    continue
                seen.add(pred)
                reach_set.add(pred)
                queue.append((pred, d + 1))
        result_sids &= reach_set

    if reachable_from:
        sources = _resolve_owned_sids([reachable_from], objects, sid_map)
        from_set: set[str] = set()
        seen = set(sources)
        queue = deque((s, 0) for s in sources)
        while queue:
            cur, d = queue.popleft()
            if d >= max_depth:
                continue
            for dst, _label in graph.get(cur, set()):
                if dst in seen:
                    continue
                seen.add(dst)
                from_set.add(dst)
                queue.append((dst, d + 1))
        result_sids &= from_set

    by_sid = {o.get("object_sid"): o for o in objects if o.get("object_sid")}
    rows: list[dict] = []
    for s in sorted(result_sids, key=lambda x: sid_names.get(x, x)):
        obj = by_sid.get(s, {})
        tags = [t for t in ("kerberoastable", "asrep", "unconstrained", "admincount", "tier0")
                if obj and _safe_pred(obj, t)]
        rows.append({
            "sid": s,
            "name": sid_names.get(s, _resolve_name(s, sid_map, domain)),
            "type": (obj.get("object_class") or "").lower(),
            "tags": tags,
        })
    return rows


def _safe_pred(obj: dict, pred: str) -> bool:
    try:
        return _node_matches_predicate(obj, pred)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Blast radius (owned principals)
# ---------------------------------------------------------------------------
def _add_azure_edges(graph, azure_edges, objects=None):
    """Add Azure/Entra + hybrid edges into the unified attack graph.

    Each azure edge is {edge_type, source_id, target_id}; the source can
    compromise/reach the target. Includes hybrid SyncedTo* edges that bridge
    on-prem AD (SID nodes) and Entra (GUID nodes), enabling cross-realm paths.

    High-value Entra role assignments (e.g. Global Administrator) target the
    role's *scope* ("/"), so we also link the holder to the tenant object
    (Tier Zero) — holding such a role == tenant compromise.
    """
    from ..utils_pkg.azure_ingestor import (
        _HIGHVALUE_ENTRA_ROLES, _HIGHVALUE_ENTRA_ROLE_NAMES)

    tenant_sids = [o.get("object_sid") for o in (objects or [])
                   if o.get("object_class") == "azure_tenant" and o.get("object_sid")]

    for edge in azure_edges or []:
        src = edge.get("source_id", "")
        dst = edge.get("target_id", "")
        label = edge.get("edge_type", "")
        if src and dst and label and src != dst:
            graph[src].add((dst, label))
        # Route high-value role holders to the tenant (Tier Zero). Carry the
        # role name on the edge so paths show WHICH role grants the access.
        if label in ("AZHasRole", "AZPIMEligible"):
            props = edge.get("properties", {})
            role = props.get("roleTemplateId", "")
            if role in _HIGHVALUE_ENTRA_ROLES:
                rname = (_HIGHVALUE_ENTRA_ROLE_NAMES.get(role)
                         or props.get("roleName") or "privileged role")
                routed_label = f"{label}: {rname}"
                for tsid in tenant_sids:
                    if src and src != tsid:
                        graph[src].add((tsid, routed_label))


# Attack-graph cache: keyed by id(objects), storing the input references so a
# reused id() can never alias (identity-checked on hit). Bounded LRU — one loaded
# collection normally, room for a hybrid/second. Cleared on collection change.
_GRAPH_CACHE: "OrderedDict[int, tuple]" = OrderedDict()
# Membership-graph cache: _build_group_graph does an expensive transitive DFS and
# is called by _build_attack_graph, _expand_actor_findings, and the nested-
# membership check — cache it by objects identity so it's built once.
_GROUP_GRAPH_CACHE: "OrderedDict[int, tuple]" = OrderedDict()
_GRAPH_CACHE_MAX = 2


def clear_graph_cache() -> None:
    """Drop the cached attack/membership graph(s). Call when the loaded
    collection changes (a new collection means new graphs)."""
    _GRAPH_CACHE.clear()
    _GROUP_GRAPH_CACHE.clear()


def _build_attack_graph(
    objects: list[dict],
    sid_map: dict[str, str] | None = None,
    sessions: list[dict] | None = None,
    local_group_members: list[dict] | None = None,
    azure_edges: list[dict] | None = None,
) -> tuple[
    dict[str, set[tuple[str, str]]],   # forward graph: src -> {(dst, label)}
    dict[str, str],                     # sid -> display name
    dict[str, str],                     # dn_lower -> sid
]:
    """Build the directed attack graph used by both shortest-path and blast radius.

    Edge types: MemberOf, ACL, Owns, Delegation (constrained/RBCD),
    HasSession, AdminTo, CanRDP, ExecuteDCOM, CanPSRemote.

    The result is cached by input identity (see _GRAPH_CACHE): the graph is
    expensive to build on large collections and is rebuilt by every graph
    command (analyze / shortest / trace / find). Callers only read it, so
    returning the shared object is safe. Cleared on collection change via
    clear_graph_cache().
    """
    # Key on the inputs that shape the graph. sid_map is NOT one of them — the
    # graph/sid_names/dn_to_sid are derived from `objects` (+ session/local/azure
    # edges); sid_map only feeds name resolution that comes from the objects
    # themselves. Dropping it lets 'analyze' → 'shortest'/'trace'/'find' reuse the
    # graph even though each rebuilds its own sid_map.
    _ck = id(objects)
    _hit = _GRAPH_CACHE.get(_ck)
    if _hit is not None:
        _o, _se, _lg, _az, _res = _hit
        if (_o is objects and _se is sessions
                and _lg is local_group_members and _az is azure_edges):
            _GRAPH_CACHE.move_to_end(_ck)
            return _res

    graph: dict[str, set[tuple[str, str]]] = defaultdict(set)
    sid_names: dict[str, str] = {}

    for obj in objects:
        sid = obj.get("object_sid") or ""
        name = obj.get("name", obj.get("dn", ""))
        if sid:
            sid_names[sid] = name

    # Group membership edges
    member_of, _, dn_to_sid = _build_group_graph(objects)
    for sid, groups in member_of.items():
        for group_sid in groups:
            graph[sid].add((group_sid, "MemberOf"))

    # ACL edges
    for obj in objects:
        target_sid = obj.get("object_sid") or ""
        if not target_sid:
            continue
        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            trustee_sid = ace.get("trustee_sid", "")
            if not trustee_sid or trustee_sid == target_sid:
                continue

            mask = ace.get("access_mask", 0)
            object_type = ace.get("object_type")

            for label in _acl_edge_labels(mask, object_type):
                graph[trustee_sid].add((target_sid, label))

    # Ownership edges
    for obj in objects:
        owner_sid = obj.get("owner_sid")
        target_sid = obj.get("object_sid") or ""
        if owner_sid and target_sid and owner_sid != target_sid:
            graph[owner_sid].add((target_sid, "Owns"))

    # Constrained delegation edges: principal -> each SPN target
    # If a principal has msDS-AllowedToDelegateTo, they can impersonate
    # users to those services. Map SPN -> owning SID via dn_to_sid.
    spn_to_sid: dict[str, str] = {}
    for obj in objects:
        sid = obj.get("object_sid") or ""
        if not sid:
            continue
        spns = obj.get("properties", {}).get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        for spn in spns:
            # Extract hostname from SPN (e.g. "MSSQLSvc/srv01.corp.local:1433")
            host = spn.split("/", 1)[-1].split(":")[0].lower() if "/" in spn else ""
            if host:
                spn_to_sid[host] = sid
            spn_to_sid[spn.lower()] = sid

    for obj in objects:
        sid = obj.get("object_sid") or ""
        if not sid:
            continue
        props = obj.get("properties", {})
        uac_val = 0
        try:
            uac_val = int(props.get("userAccountControl", 0))
        except (ValueError, TypeError):
            pass
        if uac_val & UAC.ACCOUNT_DISABLE:
            continue

        # Constrained delegation targets
        delegate_to = props.get("msDS-AllowedToDelegateTo", [])
        if isinstance(delegate_to, str):
            delegate_to = [delegate_to]
        for target_spn in delegate_to:
            host = target_spn.split("/", 1)[-1].split(":")[0].lower() if "/" in target_spn else ""
            target_sid = spn_to_sid.get(target_spn.lower()) or spn_to_sid.get(host, "")
            if target_sid and target_sid != sid:
                label = "AllowedToDelegate"
                if uac_val & UAC.TRUSTED_TO_AUTH_FOR_DELEGATION:
                    label = "AllowedToDelegate+S4U"
                graph[sid].add((target_sid, label))

    # RBCD edges: principals listed in msDS-AllowedToActOnBehalfOfOtherIdentity
    # can impersonate users TO the target object
    for obj in objects:
        target_sid = obj.get("object_sid") or ""
        if not target_sid:
            continue
        rbcd_raw = obj.get("properties", {}).get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not rbcd_raw:
            continue
        # rbcd_raw may be a list of SIDs or a serialized SD; handle both
        if isinstance(rbcd_raw, list):
            for actor_sid in rbcd_raw:
                if isinstance(actor_sid, str) and actor_sid != target_sid:
                    graph[actor_sid].add((target_sid, "AllowedToAct"))
        elif isinstance(rbcd_raw, str) and rbcd_raw.upper().startswith("S-1-"):
            if rbcd_raw != target_sid:
                graph[rbcd_raw].add((target_sid, "AllowedToAct"))

    # SID History edges: principal has SIDHistory -> SIDHistory target
    for obj in objects:
        sid = obj.get("object_sid") or ""
        if not sid:
            continue
        sid_history = obj.get("properties", {}).get("sIDHistory", [])
        if isinstance(sid_history, str):
            sid_history = [sid_history]
        for hist_sid in sid_history:
            if isinstance(hist_sid, str) and hist_sid != sid:
                graph[sid].add((hist_sid, "HasSIDHistory"))

    # GPLink edges: GPO -> OU (GPO controls the OU and its contents)
    # Contains edges: OU -> child objects
    dn_to_obj: dict[str, dict] = {}
    for obj in objects:
        dn = obj.get("dn", "")
        if dn:
            dn_to_obj[dn.lower()] = obj

    for obj in objects:
        dn = obj.get("dn", "")
        obj_sid = obj.get("object_sid") or ""

        # Contains: parent OU -> child object (enables OU takeover -> child control)
        if dn and obj_sid:
            parts = dn.split(",", 1)
            if len(parts) == 2:
                parent_dn = parts[1].lower()
                parent_obj = dn_to_obj.get(parent_dn)
                if parent_obj:
                    parent_sid = parent_obj.get("object_sid") or ""
                    if parent_sid and parent_sid != obj_sid:
                        graph[parent_sid].add((obj_sid, "Contains"))

        # GPLink: parse gPLink attribute on OUs/domains
        gplink = obj.get("properties", {}).get("gPLink", "")
        if gplink and obj_sid:
            for match in re.finditer(r"\[LDAP://([^;]+);(\d+)\]", gplink, re.IGNORECASE):
                flags = int(match.group(2))
                if flags & 1:  # bit 0 = link disabled, skip
                    continue
                gpo_dn = match.group(1).lower()
                gpo_obj = dn_to_obj.get(gpo_dn)
                if gpo_obj:
                    gpo_sid = gpo_obj.get("object_sid") or ""
                    if gpo_sid:
                        # GPO applies to the OU (GPO -> OU is the control direction)
                        graph[gpo_sid].add((obj_sid, "GPLink"))

    # Cross-forest trust edges: TrustedDomain objects -> domain
    # Enables multi-forest path traversal when multiple collections are loaded
    # Determine the local domain SID once (avoid O(n²) inner loop)
    local_domain_sid = ""
    for o in objects:
        if o.get("object_class") == "domain" and o.get("object_sid"):
            local_domain_sid = o["object_sid"]
            break

    for obj in objects:
        if obj.get("object_class") != "trusteddomain":
            continue
        props = obj.get("properties", {})
        trust_sid = props.get("securityIdentifier", "")
        if not trust_sid:
            continue
        trust_name = obj.get("name", "")
        try:
            direction = int(props.get("trustDirection") or 0)
        except (ValueError, TypeError):
            direction = 0
        try:
            attrs = int(props.get("trustAttributes") or 0)
        except (ValueError, TypeError):
            attrs = 0
        sid_filtering = bool(attrs & 0x04)

        if not local_domain_sid:
            continue

        # Direction: 1=Inbound (they trust us), 2=Outbound (we trust them), 3=Bidirectional
        label_suffix = ""
        if sid_filtering:
            label_suffix = " (SID-filtered)"

        if direction in (2, 3):  # We trust them: can authenticate from trusted domain
            graph[trust_sid].add((local_domain_sid, f"TrustedBy{label_suffix}"))
            sid_names.setdefault(trust_sid, trust_name)
        if direction in (1, 3):  # They trust us: can access trusted domain
            graph[local_domain_sid].add((trust_sid, f"TrustedBy{label_suffix}"))
            sid_names.setdefault(trust_sid, trust_name)

    # Network-collected edges (HasSession, AdminTo, CanRDP, etc.)
    _add_network_edges(
        graph, sid_names, objects, sid_map or {},
        sessions=sessions,
        local_group_members=local_group_members,
    )

    _domain_sids = [o.get("object_sid") for o in objects
                    if o.get("object_class") == "domain" and o.get("object_sid")]
    _add_adcs_edges(graph, sid_names, objects, sid_map or {})
    _add_coercion_edges(graph, objects, _domain_sids)
    _add_esc8_edges(graph, objects, _domain_sids)
    _add_azure_edges(graph, azure_edges, objects)

    _res = (graph, sid_names, dn_to_sid)
    _GRAPH_CACHE[_ck] = (objects, sessions, local_group_members, azure_edges, _res)
    _GRAPH_CACHE.move_to_end(_ck)
    while len(_GRAPH_CACHE) > _GRAPH_CACHE_MAX:
        _GRAPH_CACHE.popitem(last=False)
    return _res


def _resolve_owned_sids(
    owned_identifiers: list[str],
    objects: list[dict],
    sid_map: dict[str, str],
) -> set[str]:
    """Resolve --owned identifiers (names, SIDs, sAMAccountNames) to SIDs."""
    owned_sids: set[str] = set()

    # Build lookup maps
    name_to_sid: dict[str, str] = {}
    sam_to_sid: dict[str, str] = {}
    for obj in objects:
        sid = obj.get("object_sid") or ""
        if not sid:
            continue
        name = obj.get("name", "")
        sam = obj.get("properties", {}).get("sAMAccountName", "")
        if name:
            name_to_sid[name.lower()] = sid
        if sam:
            sam_to_sid[sam.lower()] = sid

    # Also allow reverse lookup via sid_map values
    name_from_map: dict[str, str] = {}
    for sid, name in sid_map.items():
        name_from_map[name.lower()] = sid

    for ident in owned_identifiers:
        ident_stripped = ident.strip()
        ident_lower = ident_stripped.lower()

        # Direct SID
        if ident_stripped.upper().startswith("S-1-"):
            owned_sids.add(ident_stripped)
            continue

        # Strip DOMAIN\ prefix if present
        if "\\" in ident_lower:
            ident_lower = ident_lower.split("\\", 1)[1]

        # Match by sAMAccountName (case-insensitive)
        if ident_lower in sam_to_sid:
            owned_sids.add(sam_to_sid[ident_lower])
            continue

        # Match by display name
        if ident_lower in name_to_sid:
            owned_sids.add(name_to_sid[ident_lower])
            continue

        # Match via sid_map
        if ident_lower in name_from_map:
            owned_sids.add(name_from_map[ident_lower])
            continue

        # Try with $ suffix for computer accounts
        if not ident_lower.endswith("$"):
            comp = ident_lower + "$"
            if comp in sam_to_sid:
                owned_sids.add(sam_to_sid[comp])
                continue

    return owned_sids


def _check_blast_radius(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
    *,
    owned_sids: set[str],
    sessions: list[dict] | None = None,
    local_group_members: list[dict] | None = None,
    azure_edges: list[dict] | None = None,
) -> list[Finding]:
    """Check 17: Blast radius analysis from owned/compromised principals.

    Forward BFS from owned nodes through the attack graph to find every
    reachable object, the hop count, and whether high-value targets are reached.
    """
    if not owned_sids:
        return []

    findings: list[Finding] = []
    graph, sid_names, _ = _build_attack_graph(
        objects, sid_map=sid_map,
        sessions=sessions,
        local_group_members=local_group_members,
        azure_edges=azure_edges,
    )

    # Merge sid_map into sid_names for resolution
    for sid, name in sid_map.items():
        if sid not in sid_names:
            sid_names[sid] = name

    def _name(sid: str) -> str:
        return sid_names.get(sid, _resolve_name(sid, sid_map, domain))

    # Run independent BFS per owned principal so each gets its own blast radius
    max_depth = BLAST_RADIUS_MAX_DEPTH

    # Per-owned BFS results
    per_owned_dist: dict[str, dict[str, int]] = {}  # owned_sid -> {reachable_sid -> depth}
    per_owned_parent: dict[str, dict[str, tuple[str, str]]] = {}  # owned_sid -> {sid -> (prev_sid, edge_label)}

    for o_sid in owned_sids:
        dist: dict[str, int] = {o_sid: 0}
        par: dict[str, tuple[str, str]] = {}
        queue: deque[tuple[str, int]] = deque([(o_sid, 0)])

        while queue:
            current, d = queue.popleft()
            if d >= max_depth:
                continue
            for neighbor, edge_label in graph.get(current, set()):
                if neighbor in dist:
                    continue
                # Don't traverse into other owned nodes' subtrees as separate origins
                dist[neighbor] = d + 1
                par[neighbor] = (current, edge_label)
                queue.append((neighbor, d + 1))

        per_owned_dist[o_sid] = dist
        per_owned_parent[o_sid] = par

    # Merge into combined view for finding generation
    by_origin: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for o_sid, dist in per_owned_dist.items():
        for sid, d in dist.items():
            if d == 0:
                continue
            by_origin[o_sid].append((sid, d))

    def _reconstruct_path(target_sid: str, owned_sid: str) -> list[tuple[str, str]]:
        """Return [(sid, edge_label), ...] from owned -> target."""
        par = per_owned_parent[owned_sid]
        path: list[tuple[str, str]] = [(target_sid, "")]
        current = target_sid
        while current in par:
            prev_sid, edge_label = par[current]
            path.append((prev_sid, edge_label))
            current = prev_sid
        path.reverse()
        return path

    def _format_path(path: list[tuple[str, str]]) -> str:
        parts: list[str] = []
        for i, (sid, edge_label) in enumerate(path):
            name = _name(sid)
            if i == 0:
                parts.append(name)
            else:
                # edge_label in each tuple is the edge FROM this node TO the next;
                # use the previous tuple's edge_label as the edge arriving here.
                prev_edge = path[i - 1][1]
                parts.append(f"-[{prev_edge}]-> {name}")
        return " ".join(parts)

    # Generate per-owned-node summary + per-target findings
    for owned_sid in owned_sids:
        owned_name = _name(owned_sid)
        reachable = by_origin.get(owned_sid, [])
        if not reachable:
            continue

        reachable_sorted = sorted(reachable, key=lambda x: x[1])
        hv_targets = [(sid, d) for sid, d in reachable if _is_high_value(sid)]
        total_reachable = len(reachable)

        # Summary finding
        hv_desc = ""
        if hv_targets:
            hv_names = [f"{_name(s)} ({d} hops)" for s, d in sorted(hv_targets, key=lambda x: x[1])]
            hv_desc = f" — HIGH-VALUE TARGETS REACHABLE: {', '.join(hv_names[:5])}"
            if len(hv_names) > 5:
                hv_desc += f" ... and {len(hv_names) - 5} more"

        findings.append(Finding(
            category=Category.BLAST_RADIUS,
            severity=Severity.CRITICAL if hv_targets else Severity.HIGH,
            principal_sid=owned_sid,
            principal_name=owned_name,
            target_dn="",
            target_name=f"{total_reachable} objects reachable",
            target_class="summary",
            description=(
                f"Owned principal {owned_name} can transitively reach "
                f"{total_reachable} objects (max {max_depth} hops), "
                f"including {len(hv_targets)} high-value target(s){hv_desc}"
            ),
            details={
                "owned_sid": owned_sid,
                "total_reachable": total_reachable,
                "hv_count": len(hv_targets),
                "max_depth_reached": max(d for _, d in reachable) if reachable else 0,
                "by_depth": {
                    str(depth): len([s for s, dd in reachable if dd == depth])
                    for depth in sorted({d for _, d in reachable})
                },
            },
        ))

        # Individual path findings for high-value targets
        for hv_sid, hv_depth in sorted(hv_targets, key=lambda x: x[1]):
            path = _reconstruct_path(hv_sid, owned_sid)
            path_str = _format_path(path)

            findings.append(Finding(
                category=Category.BLAST_RADIUS,
                severity=Severity.CRITICAL,
                principal_sid=owned_sid,
                principal_name=owned_name,
                target_dn="",
                target_name=_name(hv_sid),
                target_class="high-value",
                description=f"Path to {_name(hv_sid)} ({hv_depth} hops): {path_str}",
                details={
                    "owned_sid": owned_sid,
                    "target_sid": hv_sid,
                    "depth": hv_depth,
                    "path_sids": [s for s, _ in path],
                    "path_names": [_name(s) for s, _ in path],
                    "path_edges": [e for _, e in path if e],
                },
            ))

        # Individual findings for non-HV reachable objects at <= 3 hops
        for r_sid, r_depth in reachable_sorted:
            if _is_high_value(r_sid):
                continue  # already reported above
            if r_depth > 3:
                continue  # only detail close neighbors

            path = _reconstruct_path(r_sid, owned_sid)
            path_str = _format_path(path)

            findings.append(Finding(
                category=Category.BLAST_RADIUS,
                severity=Severity.HIGH if r_depth == 1 else Severity.MEDIUM,
                principal_sid=owned_sid,
                principal_name=owned_name,
                target_dn="",
                target_name=_name(r_sid),
                target_class="reachable",
                description=f"{_name(r_sid)} ({r_depth} hops): {path_str}",
                details={
                    "owned_sid": owned_sid,
                    "target_sid": r_sid,
                    "depth": r_depth,
                    "path_sids": [s for s, _ in path],
                    "path_names": [_name(s) for s, _ in path],
                    "path_edges": [e for _, e in path if e],
                },
            ))

    return findings


# ---------------------------------------------------------------------------
# Cross-correlation
# ---------------------------------------------------------------------------
def _cross_correlate(findings: list[Finding]) -> list[Finding]:
    """Check 16: Cross-correlate findings to surface compound risks.

    Looks for principals that appear in multiple check categories and elevates
    the combined risk.
    """
    correlated: list[Finding] = []

    # Index findings by principal SID for quick lookup
    by_principal: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.is_builtin:
            continue
        by_principal[f.principal_sid].append(f)

    # Index SIDs by category for target-side correlation
    kerberoastable_sids: set[str] = set()
    asrep_sids: set[str] = set()
    unconstrained_sids: set[str] = set()
    da_member_sids: set[str] = set()
    laps_read_sids: set[str] = set()
    gmsa_read_sids: set[str] = set()
    session_abuse_sids: set[str] = set()
    local_access_sids: set[str] = set()
    rbcd_sids: set[str] = set()
    ownership_sids: set[str] = set()
    gpo_abuse_sids: set[str] = set()
    ou_control_sids: set[str] = set()
    adcs_abuse_sids: set[str] = set()
    trust_abuse_sids: set[str] = set()
    dcsync_sids: set[str] = set()
    config_sids: set[str] = set()
    hybrid_sync_sids: set[str] = set()
    azure_priv_sids: set[str] = set()
    constrained_sids: set[str] = set()

    _category_sid_map = {
        Category.KERBEROAST: kerberoastable_sids,
        Category.ASREP_ROAST: asrep_sids,
        Category.UNCONSTRAINED_DELEG: unconstrained_sids,
        Category.GROUP_MEMBERSHIP: da_member_sids,
        Category.LAPS_READ: laps_read_sids,
        Category.GMSA_READ: gmsa_read_sids,
        Category.SESSION_ABUSE: session_abuse_sids,
        Category.LOCAL_ACCESS: local_access_sids,
        Category.RBCD: rbcd_sids,
        Category.OWNERSHIP: ownership_sids,
        Category.GPO_ABUSE: gpo_abuse_sids,
        Category.OU_CONTROL: ou_control_sids,
        Category.ADCS_ABUSE: adcs_abuse_sids,
        Category.TRUST_ABUSE: trust_abuse_sids,
        Category.DCSYNC: dcsync_sids,
        Category.DANGEROUS_CONFIG: config_sids,
        Category.HYBRID_SYNC: hybrid_sync_sids,
        Category.AZURE_PRIVILEGE: azure_priv_sids,
        Category.CONSTRAINED_DELEG: constrained_sids,
    }

    for f in findings:
        if f.is_builtin:
            continue
        sid_set = _category_sid_map.get(f.category)
        if sid_set is not None:
            sid_set.add(f.principal_sid)

    already_reported: set[tuple[str, str]] = set()

    def _add_correlated(sid: str, name: str, desc: str, severity: Severity, details: dict | None = None) -> None:
        key = (sid, desc)
        if key in already_reported:
            return
        already_reported.add(key)
        correlated.append(Finding(
            category=Category.CROSS_CORRELATION,
            severity=severity,
            principal_sid=sid,
            principal_name=name,
            target_dn="",
            target_name="(compound risk)",
            target_class="",
            description=desc,
            details=details or {},
        ))

    for sid, pfindings in by_principal.items():
        categories = {f.category for f in pfindings}
        name = pfindings[0].principal_name

        # Helper lists computed once per principal
        constrained_findings = [f for f in pfindings if f.category == Category.CONSTRAINED_DELEG]
        has_protocol_transition = any(f.details.get("protocol_transition") for f in constrained_findings)
        acl_targets = [f.target_name for f in pfindings if f.category == Category.ACL_ABUSE]

        # =================================================================
        # Kerberoasting compound paths
        # =================================================================

        # Kerberoastable + DA member
        if sid in kerberoastable_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND a member of a DA-equivalent group — roast for immediate DA access",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_da"},
            )

        # Kerberoastable + ACL abuse
        if sid in kerberoastable_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has ACL abuse rights on: {', '.join(acl_targets[:3])} — roast → escalate",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_acl"},
            )

        # Kerberoastable + unconstrained delegation
        if sid in kerberoastable_sids and sid in unconstrained_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has unconstrained delegation — roast → capture TGTs",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_unconstrained"},
            )

        # Kerberoastable + constrained delegation (PT)
        if sid in kerberoastable_sids and constrained_findings and has_protocol_transition:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has constrained delegation with protocol transition — roast → S4U2Self impersonation",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_constrained_pt"},
            )

        # Kerberoastable + RBCD
        if sid in kerberoastable_sids and sid in rbcd_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND can configure RBCD — roast → resource-based delegation abuse",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_rbcd"},
            )

        # Kerberoastable + DCSync
        if sid in kerberoastable_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has DCSync rights — roast → replicate all domain hashes",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_dcsync"},
            )

        # Kerberoastable + LAPS read
        if sid in kerberoastable_sids and sid in laps_read_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND can read LAPS passwords — roast → local admin on managed hosts",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_laps"},
            )

        # Kerberoastable + gMSA read
        if sid in kerberoastable_sids and sid in gmsa_read_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND can read gMSA passwords — roast → impersonate service account",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_gmsa"},
            )

        # Kerberoastable + GPO abuse
        if sid in kerberoastable_sids and sid in gpo_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has GPO abuse rights — roast → deploy payload via group policy",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_gpo"},
            )

        # Kerberoastable + ownership
        if sid in kerberoastable_sids and sid in ownership_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND owns high-value objects — roast → modify owned objects",
                Severity.HIGH,
                {"correlation_type": "kerberoast_ownership"},
            )

        # Kerberoastable + ADCS abuse
        if sid in kerberoastable_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has ADCS abuse vectors — roast → certificate-based escalation",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_adcs"},
            )

        # Kerberoastable + local access
        if sid in kerberoastable_sids and sid in local_access_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has local admin/RDP/DCOM access — roast → lateral movement",
                Severity.HIGH,
                {"correlation_type": "kerberoast_local_access"},
            )

        # Kerberoastable + session abuse
        if sid in kerberoastable_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has active sessions on target hosts — roast → credential theft",
                Severity.HIGH,
                {"correlation_type": "kerberoast_session"},
            )

        # Kerberoastable + trust abuse
        if sid in kerberoastable_sids and sid in trust_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has trust abuse vectors — roast → cross-trust escalation",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_trust"},
            )

        # Kerberoastable + dangerous config
        if sid in kerberoastable_sids and sid in config_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has dangerous configuration (e.g., PASSWD_NOTREQD) — trivially roastable",
                Severity.CRITICAL,
                {"correlation_type": "kerberoast_config"},
            )

        # Kerberoastable + OU control
        if sid in kerberoastable_sids and sid in ou_control_sids:
            _add_correlated(
                sid, name,
                f"{name} is kerberoastable AND has OU control rights — roast → modify OU objects",
                Severity.HIGH,
                {"correlation_type": "kerberoast_ou"},
            )

        # =================================================================
        # AS-REP Roasting compound paths
        # =================================================================

        # AS-REP + ACL abuse
        if sid in asrep_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has ACL abuse rights on: {', '.join(acl_targets[:3])} — crack offline → escalate",
                Severity.CRITICAL,
                {"correlation_type": "asrep_acl"},
            )

        # AS-REP + DA member
        if sid in asrep_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND a member of a DA-equivalent group — crack offline for DA",
                Severity.CRITICAL,
                {"correlation_type": "asrep_da"},
            )

        # AS-REP + unconstrained delegation
        if sid in asrep_sids and sid in unconstrained_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has unconstrained delegation — crack → capture TGTs",
                Severity.CRITICAL,
                {"correlation_type": "asrep_unconstrained"},
            )

        # AS-REP + constrained delegation (PT)
        if sid in asrep_sids and constrained_findings and has_protocol_transition:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has constrained delegation with protocol transition — crack → S4U2Self impersonation",
                Severity.CRITICAL,
                {"correlation_type": "asrep_constrained_pt"},
            )

        # AS-REP + RBCD
        if sid in asrep_sids and sid in rbcd_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND can configure RBCD — crack → resource-based delegation abuse",
                Severity.CRITICAL,
                {"correlation_type": "asrep_rbcd"},
            )

        # AS-REP + DCSync
        if sid in asrep_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has DCSync rights — crack → replicate all domain hashes",
                Severity.CRITICAL,
                {"correlation_type": "asrep_dcsync"},
            )

        # AS-REP + LAPS read
        if sid in asrep_sids and sid in laps_read_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND can read LAPS passwords — crack → local admin on managed hosts",
                Severity.CRITICAL,
                {"correlation_type": "asrep_laps"},
            )

        # AS-REP + gMSA read
        if sid in asrep_sids and sid in gmsa_read_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND can read gMSA passwords — crack → impersonate service account",
                Severity.CRITICAL,
                {"correlation_type": "asrep_gmsa"},
            )

        # AS-REP + GPO abuse
        if sid in asrep_sids and sid in gpo_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has GPO abuse rights — crack → deploy payload via group policy",
                Severity.CRITICAL,
                {"correlation_type": "asrep_gpo"},
            )

        # AS-REP + ownership
        if sid in asrep_sids and sid in ownership_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND owns high-value objects — crack → modify owned objects",
                Severity.HIGH,
                {"correlation_type": "asrep_ownership"},
            )

        # AS-REP + ADCS abuse
        if sid in asrep_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has ADCS abuse vectors — crack → certificate-based escalation",
                Severity.CRITICAL,
                {"correlation_type": "asrep_adcs"},
            )

        # AS-REP + local access
        if sid in asrep_sids and sid in local_access_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has local admin/RDP/DCOM access — crack → lateral movement",
                Severity.HIGH,
                {"correlation_type": "asrep_local_access"},
            )

        # AS-REP + session abuse
        if sid in asrep_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has active sessions on target hosts — crack → credential theft",
                Severity.HIGH,
                {"correlation_type": "asrep_session"},
            )

        # AS-REP + trust abuse
        if sid in asrep_sids and sid in trust_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has trust abuse vectors — crack → cross-trust escalation",
                Severity.CRITICAL,
                {"correlation_type": "asrep_trust"},
            )

        # AS-REP + dangerous config
        if sid in asrep_sids and sid in config_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has dangerous configuration — trivially crackable",
                Severity.CRITICAL,
                {"correlation_type": "asrep_config"},
            )

        # AS-REP + OU control
        if sid in asrep_sids and sid in ou_control_sids:
            _add_correlated(
                sid, name,
                f"{name} is AS-REP roastable AND has OU control rights — crack → modify OU objects",
                Severity.HIGH,
                {"correlation_type": "asrep_ou"},
            )

        # =================================================================
        # Unconstrained delegation compound paths
        # =================================================================

        # Unconstrained + ACL abuse
        if sid in unconstrained_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND ACL abuse rights — coerce + capture TGT + escalate",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_acl"},
            )

        # Unconstrained + DA member
        if sid in unconstrained_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND is a DA member — TGT capture for DA persistence",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_da"},
            )

        # Unconstrained + DCSync
        if sid in unconstrained_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND DCSync rights — capture TGTs + replicate hashes",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_dcsync"},
            )

        # Unconstrained + LAPS read
        if sid in unconstrained_sids and sid in laps_read_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND LAPS read — capture TGTs + read local admin passwords",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_laps"},
            )

        # Unconstrained + gMSA read
        if sid in unconstrained_sids and sid in gmsa_read_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND gMSA read — capture TGTs + impersonate service accounts",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_gmsa"},
            )

        # Unconstrained + GPO abuse
        if sid in unconstrained_sids and sid in gpo_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND GPO abuse rights — capture TGTs + deploy via group policy",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_gpo"},
            )

        # Unconstrained + session abuse
        if sid in unconstrained_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND active sessions — TGT capture + credential theft",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_session"},
            )

        # Unconstrained + local access
        if sid in unconstrained_sids and sid in local_access_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND local admin access — pivot → capture TGTs",
                Severity.HIGH,
                {"correlation_type": "unconstrained_local_access"},
            )

        # Unconstrained + ADCS abuse
        if sid in unconstrained_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND ADCS abuse vectors — TGT capture + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_adcs"},
            )

        # Unconstrained + trust abuse
        if sid in unconstrained_sids and sid in trust_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND trust abuse vectors — TGT capture + cross-trust escalation",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_trust"},
            )

        # Unconstrained + ownership
        if sid in unconstrained_sids and sid in ownership_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND owns high-value objects — TGT capture + object modification",
                Severity.HIGH,
                {"correlation_type": "unconstrained_ownership"},
            )

        # Unconstrained + RBCD
        if sid in unconstrained_sids and sid in rbcd_sids:
            _add_correlated(
                sid, name,
                f"{name} has unconstrained delegation AND RBCD configuration rights — dual delegation abuse",
                Severity.CRITICAL,
                {"correlation_type": "unconstrained_rbcd"},
            )

        # =================================================================
        # Constrained delegation (PT) compound paths
        # =================================================================

        # Constrained (PT) + ACL abuse
        if constrained_findings and has_protocol_transition and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND ACL abuse rights — S4U2Self abuse chain",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_acl"},
            )

        # Constrained (PT) + DA member
        if constrained_findings and has_protocol_transition and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND is a DA member — S4U2Self for DA impersonation",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_da"},
            )

        # Constrained (PT) + DCSync
        if constrained_findings and has_protocol_transition and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND DCSync rights — S4U2Self + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_dcsync"},
            )

        # Constrained (PT) + LAPS read
        if constrained_findings and has_protocol_transition and sid in laps_read_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND LAPS read — S4U2Self + local admin passwords",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_laps"},
            )

        # Constrained (PT) + gMSA read
        if constrained_findings and has_protocol_transition and sid in gmsa_read_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND gMSA read — S4U2Self + service account takeover",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_gmsa"},
            )

        # Constrained (PT) + GPO abuse
        if constrained_findings and has_protocol_transition and sid in gpo_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND GPO abuse — S4U2Self + policy deployment",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_gpo"},
            )

        # Constrained (PT) + ADCS abuse
        if constrained_findings and has_protocol_transition and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND ADCS abuse — S4U2Self + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_adcs"},
            )

        # Constrained (PT) + ownership
        if constrained_findings and has_protocol_transition and sid in ownership_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND owns high-value objects — S4U2Self + object takeover",
                Severity.HIGH,
                {"correlation_type": "constrained_pt_ownership"},
            )

        # Constrained (PT) + session abuse
        if constrained_findings and has_protocol_transition and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND active sessions — S4U2Self + credential theft",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_session"},
            )

        # Constrained (PT) + local access
        if constrained_findings and has_protocol_transition and sid in local_access_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND local admin access — S4U2Self + lateral movement",
                Severity.HIGH,
                {"correlation_type": "constrained_pt_local_access"},
            )

        # Constrained (PT) + trust abuse
        if constrained_findings and has_protocol_transition and sid in trust_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has constrained delegation with protocol transition AND trust abuse vectors — S4U2Self + cross-trust escalation",
                Severity.CRITICAL,
                {"correlation_type": "constrained_pt_trust"},
            )

        # =================================================================
        # RBCD compound paths
        # =================================================================

        # RBCD + ACL abuse
        if sid in rbcd_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} can configure RBCD AND has ACL abuse rights — resource-based delegation + ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "rbcd_acl"},
            )

        # RBCD + DA member
        if sid in rbcd_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} can configure RBCD AND is a DA member — RBCD for DA persistence",
                Severity.CRITICAL,
                {"correlation_type": "rbcd_da"},
            )

        # RBCD + DCSync
        if sid in rbcd_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} can configure RBCD AND has DCSync rights — multiple domain compromise paths",
                Severity.CRITICAL,
                {"correlation_type": "rbcd_dcsync"},
            )

        # RBCD + session abuse
        if sid in rbcd_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} can configure RBCD AND has active sessions — delegation abuse + credential theft",
                Severity.HIGH,
                {"correlation_type": "rbcd_session"},
            )

        # RBCD + local access
        if sid in rbcd_sids and sid in local_access_sids:
            _add_correlated(
                sid, name,
                f"{name} can configure RBCD AND has local admin access — delegation abuse + lateral movement",
                Severity.HIGH,
                {"correlation_type": "rbcd_local_access"},
            )

        # RBCD + ADCS abuse
        if sid in rbcd_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} can configure RBCD AND has ADCS abuse vectors — delegation + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "rbcd_adcs"},
            )

        # =================================================================
        # Targeted kerberoasting (ACL → write SPN)
        # =================================================================

        for f in pfindings:
            if f.category != Category.ACL_ABUSE:
                continue
            if any("serviceprincipalname" in r.lower() or "genericwrite" in r.lower()
                   or "genericall" in r.lower() or "writeallproperties" in r.lower()
                   for r in f.rights):
                if f.target_class == "user":
                    _add_correlated(
                        sid, name,
                        f"{name} can write SPN on {f.target_name} — targeted kerberoasting",
                        Severity.HIGH,
                        {"correlation_type": "targeted_kerberoast"},
                    )

        # =================================================================
        # GPO abuse compound paths
        # =================================================================

        # GPO abuse + DA member
        if sid in gpo_abuse_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has GPO abuse rights AND is a DA member — can deploy persistence via GPO",
                Severity.CRITICAL,
                {"correlation_type": "gpo_da"},
            )

        # GPO abuse + ACL abuse
        if sid in gpo_abuse_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has GPO abuse rights AND ACL abuse rights — GPO deployment + ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "gpo_acl"},
            )

        # GPO abuse + local access
        if sid in gpo_abuse_sids and sid in local_access_sids:
            _add_correlated(
                sid, name,
                f"{name} has GPO abuse rights AND local admin access — GPO deployment + lateral movement",
                Severity.HIGH,
                {"correlation_type": "gpo_local_access"},
            )

        # GPO abuse + session abuse
        if sid in gpo_abuse_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has GPO abuse rights AND active sessions — GPO deployment + credential theft",
                Severity.HIGH,
                {"correlation_type": "gpo_session"},
            )

        # GPO abuse + DCSync
        if sid in gpo_abuse_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has GPO abuse rights AND DCSync rights — policy deployment + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "gpo_dcsync"},
            )

        # GPO abuse + OU control
        if sid in gpo_abuse_sids and sid in ou_control_sids:
            _add_correlated(
                sid, name,
                f"{name} has GPO abuse rights AND OU control — link malicious GPO to controlled OU",
                Severity.CRITICAL,
                {"correlation_type": "gpo_ou"},
            )

        # GPO abuse + ADCS abuse
        if sid in gpo_abuse_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has GPO abuse rights AND ADCS abuse vectors — GPO deployment + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "gpo_adcs"},
            )

        # =================================================================
        # OU control compound paths
        # =================================================================

        # OU control + ACL abuse
        if sid in ou_control_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has OU control AND ACL abuse rights — OU modification + ACL escalation",
                Severity.HIGH,
                {"correlation_type": "ou_acl"},
            )

        # OU control + DA member
        if sid in ou_control_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has OU control AND is a DA member — modify OU containing privileged accounts",
                Severity.CRITICAL,
                {"correlation_type": "ou_da"},
            )

        # OU control + DCSync
        if sid in ou_control_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has OU control AND DCSync rights — OU takeover + domain hash replication",
                Severity.CRITICAL,
                {"correlation_type": "ou_dcsync"},
            )

        # =================================================================
        # DCSync compound paths
        # =================================================================

        if sid in dcsync_sids and len(categories) > 1:
            other_cats = categories - {Category.DCSYNC}
            _add_correlated(
                sid, name,
                f"{name} has DCSync rights AND {', '.join(c.value for c in other_cats)} — multiple escalation vectors",
                Severity.CRITICAL,
                {"correlation_type": "dcsync_multi"},
            )

        # =================================================================
        # Ownership compound paths
        # =================================================================

        # Ownership + ACL abuse
        if sid in ownership_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} owns high-value objects AND has ACL abuse rights — modify DACL + escalate",
                Severity.CRITICAL,
                {"correlation_type": "ownership_acl"},
            )

        # Ownership + DA member
        if sid in ownership_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} owns high-value objects AND is a DA member — object takeover for DA persistence",
                Severity.CRITICAL,
                {"correlation_type": "ownership_da"},
            )

        # Ownership + DCSync
        if sid in ownership_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} owns high-value objects AND has DCSync rights — object control + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "ownership_dcsync"},
            )

        # Ownership + GPO abuse
        if sid in ownership_sids and sid in gpo_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} owns high-value objects AND has GPO abuse rights — object takeover + policy deployment",
                Severity.CRITICAL,
                {"correlation_type": "ownership_gpo"},
            )

        # Ownership + ADCS abuse
        if sid in ownership_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} owns high-value objects AND has ADCS abuse vectors — object control + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "ownership_adcs"},
            )

        # =================================================================
        # LAPS read compound paths
        # =================================================================

        # LAPS + DA member
        if sid in laps_read_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} can read LAPS passwords AND is a DA member — local admin access as DA",
                Severity.CRITICAL,
                {"correlation_type": "laps_da"},
            )

        # LAPS + ACL abuse
        if sid in laps_read_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} can read LAPS passwords AND has ACL abuse rights — local admin → ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "laps_acl"},
            )

        # LAPS + session abuse
        if sid in laps_read_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} can read LAPS passwords AND has active sessions — local admin + credential theft",
                Severity.HIGH,
                {"correlation_type": "laps_session"},
            )

        # LAPS + local access
        if sid in laps_read_sids and sid in local_access_sids:
            _add_correlated(
                sid, name,
                f"{name} can read LAPS passwords AND has local admin access — multi-host local admin",
                Severity.HIGH,
                {"correlation_type": "laps_local_access"},
            )

        # LAPS + DCSync
        if sid in laps_read_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} can read LAPS passwords AND has DCSync rights — local admin + domain hash replication",
                Severity.CRITICAL,
                {"correlation_type": "laps_dcsync"},
            )

        # LAPS + GPO abuse
        if sid in laps_read_sids and sid in gpo_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} can read LAPS passwords AND has GPO abuse rights — local admin + GPO deployment",
                Severity.CRITICAL,
                {"correlation_type": "laps_gpo"},
            )

        # =================================================================
        # gMSA read compound paths
        # =================================================================

        # gMSA + DA member
        if sid in gmsa_read_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} can read gMSA passwords AND is a DA member — service account takeover as DA",
                Severity.CRITICAL,
                {"correlation_type": "gmsa_da"},
            )

        # gMSA + ACL abuse
        if sid in gmsa_read_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} can read gMSA passwords AND has ACL abuse rights — service account + ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "gmsa_acl"},
            )

        # gMSA + DCSync
        if sid in gmsa_read_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} can read gMSA passwords AND has DCSync rights — service account + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "gmsa_dcsync"},
            )

        # gMSA + unconstrained delegation
        if sid in gmsa_read_sids and sid in unconstrained_sids:
            _add_correlated(
                sid, name,
                f"{name} can read gMSA passwords AND has unconstrained delegation — service impersonation + TGT capture",
                Severity.CRITICAL,
                {"correlation_type": "gmsa_unconstrained"},
            )

        # gMSA + session abuse
        if sid in gmsa_read_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} can read gMSA passwords AND has active sessions — service account + credential theft",
                Severity.HIGH,
                {"correlation_type": "gmsa_session"},
            )

        # gMSA + ADCS abuse
        if sid in gmsa_read_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} can read gMSA passwords AND has ADCS abuse vectors — service account + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "gmsa_adcs"},
            )

        # =================================================================
        # Session abuse compound paths
        # =================================================================

        # Session + DA member
        if sid in session_abuse_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has sessions on target hosts AND is a DA member — steal DA credentials from session",
                Severity.CRITICAL,
                {"correlation_type": "session_da"},
            )

        # Session + ACL abuse
        if sid in session_abuse_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has sessions on target hosts AND ACL abuse rights — credential theft → ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "session_acl"},
            )

        # Session + DCSync
        if sid in session_abuse_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has sessions on target hosts AND DCSync rights — credential theft + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "session_dcsync"},
            )

        # Session + ADCS abuse
        if sid in session_abuse_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has sessions on target hosts AND ADCS abuse vectors — credential theft + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "session_adcs"},
            )

        # =================================================================
        # Local access compound paths
        # =================================================================

        # Local access + DA member
        if sid in local_access_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has local admin/RDP/DCOM access AND is a DA member — lateral movement as DA",
                Severity.CRITICAL,
                {"correlation_type": "local_access_da"},
            )

        # Local access + ACL abuse
        if sid in local_access_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has local admin/RDP/DCOM access AND ACL abuse rights — lateral movement → ACL escalation",
                Severity.HIGH,
                {"correlation_type": "local_access_acl"},
            )

        # Local access + DCSync
        if sid in local_access_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has local admin/RDP/DCOM access AND DCSync rights — lateral movement + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "local_access_dcsync"},
            )

        # Local access + session abuse
        if sid in local_access_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has local admin/RDP/DCOM access AND active sessions — pivot + credential theft",
                Severity.HIGH,
                {"correlation_type": "local_access_session"},
            )

        # Local access + ADCS abuse
        if sid in local_access_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has local admin/RDP/DCOM access AND ADCS abuse vectors — lateral movement + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "local_access_adcs"},
            )

        # =================================================================
        # ADCS abuse compound paths
        # =================================================================

        # ADCS + DA member
        if sid in adcs_abuse_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has ADCS abuse vectors AND is a DA member — certificate abuse for DA persistence",
                Severity.CRITICAL,
                {"correlation_type": "adcs_da"},
            )

        # ADCS + ACL abuse
        if sid in adcs_abuse_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has ADCS abuse vectors AND ACL abuse rights — certificate + ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "adcs_acl"},
            )

        # ADCS + DCSync
        if sid in adcs_abuse_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has ADCS abuse vectors AND DCSync rights — certificate abuse + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "adcs_dcsync"},
            )

        # ADCS + ownership
        if sid in adcs_abuse_sids and sid in ownership_sids:
            _add_correlated(
                sid, name,
                f"{name} has ADCS abuse vectors AND owns high-value objects — certificate + object takeover",
                Severity.CRITICAL,
                {"correlation_type": "adcs_ownership"},
            )

        # ADCS + trust abuse
        if sid in adcs_abuse_sids and sid in trust_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has ADCS abuse vectors AND trust abuse vectors — certificate + cross-trust escalation",
                Severity.CRITICAL,
                {"correlation_type": "adcs_trust"},
            )

        # =================================================================
        # Trust abuse compound paths
        # =================================================================

        # Trust + DA member
        if sid in trust_abuse_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has trust abuse vectors AND is a DA member — cross-trust DA escalation",
                Severity.CRITICAL,
                {"correlation_type": "trust_da"},
            )

        # Trust + ACL abuse
        if sid in trust_abuse_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has trust abuse vectors AND ACL abuse rights — cross-trust + ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "trust_acl"},
            )

        # Trust + DCSync
        if sid in trust_abuse_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has trust abuse vectors AND DCSync rights — cross-trust + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "trust_dcsync"},
            )

        # Trust + ownership
        if sid in trust_abuse_sids and sid in ownership_sids:
            _add_correlated(
                sid, name,
                f"{name} has trust abuse vectors AND owns high-value objects — cross-trust + object control",
                Severity.CRITICAL,
                {"correlation_type": "trust_ownership"},
            )

        # Trust + session abuse
        if sid in trust_abuse_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has trust abuse vectors AND active sessions — cross-trust + credential theft",
                Severity.CRITICAL,
                {"correlation_type": "trust_session"},
            )

        # Trust + GPO abuse
        if sid in trust_abuse_sids and sid in gpo_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has trust abuse vectors AND GPO abuse rights — cross-trust + policy deployment",
                Severity.CRITICAL,
                {"correlation_type": "trust_gpo"},
            )

        # =================================================================
        # Dangerous configuration compound paths
        # =================================================================

        # Config + ACL abuse
        if sid in config_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has dangerous configuration AND ACL abuse rights — weak config + ACL escalation",
                Severity.HIGH,
                {"correlation_type": "config_acl"},
            )

        # Config + DA member
        if sid in config_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has dangerous configuration AND is a DA member — misconfigured DA account",
                Severity.CRITICAL,
                {"correlation_type": "config_da"},
            )

        # Config + unconstrained delegation
        if sid in config_sids and sid in unconstrained_sids:
            _add_correlated(
                sid, name,
                f"{name} has dangerous configuration AND unconstrained delegation — weak config + TGT capture",
                Severity.CRITICAL,
                {"correlation_type": "config_unconstrained"},
            )

        # Config + DCSync
        if sid in config_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has dangerous configuration AND DCSync rights — weak config + hash replication",
                Severity.CRITICAL,
                {"correlation_type": "config_dcsync"},
            )

        # Config + session abuse
        if sid in config_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has dangerous configuration AND active sessions — weak config + credential theft",
                Severity.HIGH,
                {"correlation_type": "config_session"},
            )

        # Config + ADCS abuse
        if sid in config_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has dangerous configuration AND ADCS abuse vectors — weak config + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "config_adcs"},
            )

        # =================================================================
        # Hybrid / Azure compound paths
        # =================================================================

        # Hybrid sync + ACL abuse
        if sid in hybrid_sync_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} is synced to Entra ID AND has ACL abuse rights — cloud sync + on-prem ACL escalation",
                Severity.CRITICAL,
                {"correlation_type": "hybrid_acl"},
            )

        # Hybrid sync + kerberoastable
        if sid in hybrid_sync_sids and sid in kerberoastable_sids:
            _add_correlated(
                sid, name,
                f"{name} is synced to Entra ID AND kerberoastable — roast → cloud admin access",
                Severity.CRITICAL,
                {"correlation_type": "hybrid_kerberoast"},
            )

        # Hybrid sync + AS-REP
        if sid in hybrid_sync_sids and sid in asrep_sids:
            _add_correlated(
                sid, name,
                f"{name} is synced to Entra ID AND AS-REP roastable — crack → cloud admin access",
                Severity.CRITICAL,
                {"correlation_type": "hybrid_asrep"},
            )

        # Hybrid sync + DA member
        if sid in hybrid_sync_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} is synced to Entra ID AND is a DA member — DA with cloud admin access",
                Severity.CRITICAL,
                {"correlation_type": "hybrid_da"},
            )

        # Hybrid sync + DCSync
        if sid in hybrid_sync_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} is synced to Entra ID AND has DCSync rights — cloud sync + domain hash replication",
                Severity.CRITICAL,
                {"correlation_type": "hybrid_dcsync"},
            )

        # Hybrid sync + session abuse
        if sid in hybrid_sync_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} is synced to Entra ID AND has active sessions — cloud sync + credential theft",
                Severity.HIGH,
                {"correlation_type": "hybrid_session"},
            )

        # Hybrid sync + unconstrained delegation
        if sid in hybrid_sync_sids and sid in unconstrained_sids:
            _add_correlated(
                sid, name,
                f"{name} is synced to Entra ID AND has unconstrained delegation — cloud sync + TGT capture",
                Severity.CRITICAL,
                {"correlation_type": "hybrid_unconstrained"},
            )

        # Azure privilege + ACL abuse
        if sid in azure_priv_sids and Category.ACL_ABUSE in categories:
            _add_correlated(
                sid, name,
                f"{name} has Azure/Entra privilege AND on-prem ACL abuse rights — cloud admin + on-prem escalation",
                Severity.CRITICAL,
                {"correlation_type": "azure_acl"},
            )

        # Azure privilege + kerberoastable
        if sid in azure_priv_sids and sid in kerberoastable_sids:
            _add_correlated(
                sid, name,
                f"{name} has Azure/Entra privilege AND is kerberoastable — roast → cloud + on-prem compromise",
                Severity.CRITICAL,
                {"correlation_type": "azure_kerberoast"},
            )

        # Azure privilege + DA member
        if sid in azure_priv_sids and sid in da_member_sids:
            _add_correlated(
                sid, name,
                f"{name} has Azure/Entra privilege AND is a DA member — dual cloud + on-prem admin",
                Severity.CRITICAL,
                {"correlation_type": "azure_da"},
            )

        # Azure privilege + DCSync
        if sid in azure_priv_sids and sid in dcsync_sids:
            _add_correlated(
                sid, name,
                f"{name} has Azure/Entra privilege AND DCSync rights — cloud admin + domain hash replication",
                Severity.CRITICAL,
                {"correlation_type": "azure_dcsync"},
            )

        # Azure privilege + session abuse
        if sid in azure_priv_sids and sid in session_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has Azure/Entra privilege AND active sessions — cloud admin + credential theft",
                Severity.HIGH,
                {"correlation_type": "azure_session"},
            )

        # Azure privilege + unconstrained delegation
        if sid in azure_priv_sids and sid in unconstrained_sids:
            _add_correlated(
                sid, name,
                f"{name} has Azure/Entra privilege AND unconstrained delegation — cloud admin + TGT capture",
                Severity.CRITICAL,
                {"correlation_type": "azure_unconstrained"},
            )

        # Azure privilege + ADCS abuse
        if sid in azure_priv_sids and sid in adcs_abuse_sids:
            _add_correlated(
                sid, name,
                f"{name} has Azure/Entra privilege AND ADCS abuse vectors — cloud admin + certificate escalation",
                Severity.CRITICAL,
                {"correlation_type": "azure_adcs"},
            )


    return correlated


# ---------------------------------------------------------------------------
# Hybrid / Entra ID checks
# ---------------------------------------------------------------------------
def _check_hybrid_sync(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Identify synced AD users whose Entra identity holds high-value roles.

    This is the most critical hybrid attack path: compromising an on-prem AD
    account whose synced Entra identity is a Global Administrator (or similar)
    grants full tenant takeover without ever touching the cloud directly.
    """
    data = kwargs.get("_full_data")
    if not data:
        return []

    azure_edges = data.get("azure_edges", []) or []
    hybrid_edges = data.get("hybrid_edges", []) or []

    if not hybrid_edges:
        return []

    from ..utils_pkg.azure_ingestor import entra_role_info

    # Build map: entra_id → list of (role_template_id, role_name) high-value roles
    hv_roles: dict[str, list[tuple[str, str]]] = {}
    for edge in azure_edges:
        if edge.get("edge_type") not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {})
        if props.get("isHighValue"):
            template_id = props.get("roleTemplateId", "")
            role_name = props.get("roleName", "Unknown Role")
            hv_roles.setdefault(edge.get("source_id", ""), []).append(
                (template_id, role_name))

    findings: list[Finding] = []
    for edge in hybrid_edges:
        if edge.get("edge_type") != "SyncedToEntraUser":
            continue
        entra_id = edge.get("target_id", "")
        if not entra_id or entra_id not in hv_roles:
            continue

        eprops = edge.get("properties", {})
        ad_name = eprops.get("ad_name", "")
        entra_name = eprops.get("entra_name", "")
        ad_sid = edge.get("source_id", "")

        for template_id, role_name in hv_roles[entra_id]:
            role, impact = entra_role_info(template_id, role_name)
            findings.append(Finding(
                category=Category.HYBRID_SYNC,
                severity=Severity.CRITICAL,
                principal_sid=ad_sid,
                principal_name=ad_name,
                target_dn=f"AZ://aad_user/{entra_id}",
                target_name=entra_name,
                target_class="aad_user",
                description=(
                    f"AD user {ad_name} is synced to Entra user {entra_name}, "
                    f"who holds the '{role}' role — which {impact}. Compromising "
                    f"the on-prem AD account therefore yields that Entra access."
                ),
                rights=[role],
                details={
                    "attack_type": "hybrid_sync_privilege_escalation",
                    "ad_sid": ad_sid,
                    "entra_id": entra_id,
                    "role": role,
                    "role_template_id": template_id,
                },
            ))

    return findings


def _check_azure_globaladmin(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Identify all principals with Global Administrator or equivalent roles.

    Reports both synced and cloud-only principals holding dangerous Entra
    directory roles, plus any eligible-but-not-active PIM assignments.
    """
    data = kwargs.get("_full_data")
    if not data:
        return []

    azure_edges = data.get("azure_edges", []) or []
    if not azure_edges:
        return []

    from ..utils_pkg.azure_ingestor import _HIGHVALUE_ENTRA_ROLES, entra_role_info

    findings: list[Finding] = []
    for edge in azure_edges:
        if edge.get("edge_type") not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {})
        template_id = props.get("roleTemplateId", "")
        if template_id not in _HIGHVALUE_ENTRA_ROLES:
            continue

        principal_id = edge.get("source_id", "")
        principal_name = sid_map.get(principal_id, principal_id)
        role_name, impact = entra_role_info(template_id, props.get("roleName", ""))
        is_pim = edge.get("edge_type") == "AZPIMEligible"

        severity = Severity.HIGH if is_pim else Severity.CRITICAL
        assignment = "eligible (PIM)" if is_pim else "active"

        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE,
            severity=severity,
            principal_sid=principal_id,
            principal_name=principal_name,
            target_dn="",
            target_name=role_name,
            target_class="entra_role",
            description=(
                f"{principal_name} has an {assignment} assignment to "
                f"'{role_name}', which {impact}."
            ),
            rights=[role_name],
            details={
                "attack_type": "azure_high_privilege_role",
                "role_template_id": template_id,
                "assignment_type": assignment,
            },
        ))

    return findings


def _check_azure_app_abuse(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Identify app/service principal ownership abuse paths.

    If a non-admin user owns an application or service principal, they can
    add credentials to it and authenticate as it.  This is dangerous when
    the service principal itself has high-privilege role assignments.
    """
    data = kwargs.get("_full_data")
    if not data:
        return []

    azure_edges = data.get("azure_edges", []) or []
    if not azure_edges:
        return []

    # Collect high-privilege service principal IDs
    sp_roles: dict[str, list[str]] = {}
    for edge in azure_edges:
        if edge.get("edge_type") not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {})
        if props.get("isHighValue"):
            sp_roles.setdefault(edge.get("source_id", ""), []).append(
                props.get("roleName", "Unknown Role")
            )

    # Check ownership edges targeting privileged SPs/Apps
    findings: list[Finding] = []
    for edge in azure_edges:
        if edge.get("edge_type") != "AZOwns":
            continue
        target_id = edge.get("target_id", "")
        if not target_id or target_id not in sp_roles:
            continue

        owner_id = edge.get("source_id", "")
        owner_name = sid_map.get(owner_id, owner_id)
        target_name = sid_map.get(target_id, target_id)
        roles = sp_roles[target_id]

        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE,
            severity=Severity.HIGH,
            principal_sid=owner_id,
            principal_name=owner_name,
            target_dn=f"AZ://aad_sp/{target_id}",
            target_name=target_name,
            target_class="aad_sp",
            description=(
                f"{owner_name} owns {target_name} which has "
                f"[{', '.join(roles)}] role(s). The owner can add secrets "
                f"and authenticate as this privileged service principal."
            ),
            rights=["AZOwns"] + roles,
            details={
                "attack_type": "azure_app_ownership_abuse",
                "roles": roles,
            },
        ))

    return findings


def _check_azure_managed_identity(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Managed-identity abuse paths.

    A managed identity (or an app's backing SP) that holds a high-privilege
    Entra/Azure role is an escalation target: whoever controls the resource
    it is attached to — a VM, Function/App Service, Automation account —
    can request that identity's token and inherit the role. Reports the
    resource -> privileged-identity edges (AZManagedIdentity / AZRunsAs).
    """
    data = kwargs.get("_full_data")
    if not data:
        return []
    azure_edges = data.get("azure_edges", []) or []
    if not azure_edges:
        return []

    # Identities (SP / managed identity) that hold a high-value role.
    identity_roles: dict[str, list[str]] = {}
    for edge in azure_edges:
        if edge.get("edge_type") not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {}) or {}
        if props.get("isHighValue"):
            identity_roles.setdefault(edge.get("source_id", ""), []).append(
                props.get("roleName", "Unknown Role"))

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for edge in azure_edges:
        etype = edge.get("edge_type")
        if etype not in ("AZManagedIdentity", "AZRunsAs"):
            continue
        identity_id = edge.get("target_id", "")
        if identity_id not in identity_roles:
            continue
        resource_id = edge.get("source_id", "")
        key = (resource_id, identity_id)
        if key in seen:
            continue
        seen.add(key)
        roles = identity_roles[identity_id]
        resource_name = sid_map.get(resource_id, resource_id)
        identity_name = sid_map.get(identity_id, identity_id)
        mechanism = ("runs as" if etype == "AZRunsAs"
                     else "has an attached managed identity")
        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE,
            severity=Severity.HIGH,
            principal_sid=resource_id,
            principal_name=resource_name,
            target_dn=f"AZ://aad_sp/{identity_id}",
            target_name=identity_name,
            target_class="aad_sp",
            description=(
                f"{resource_name} {mechanism} {identity_name}, which holds "
                f"[{', '.join(roles)}] — controlling the resource yields a token "
                "for this privileged identity"
            ),
            rights=[etype] + roles,
            details={"attack_type": "azure_managed_identity_abuse",
                     "edge_type": etype, "roles": roles},
        ))

    return findings


# Entra user attributes an attacker (or self-service / helpdesk) can influence,
# which a dynamic-membership rule keying on them turns into a join primitive.
_ATTACKER_INFLUENCEABLE_ATTRS = (
    "userprincipalname", "mail", "othermails", "displayname", "department",
    "jobtitle", "city", "country", "companyname", "employeeid", "givenname",
    "surname", "physicaldeliveryofficename", "streetaddress", "state",
    "postalcode", "telephonenumber", "mobilephone", "preferredlanguage",
)


def _check_azure_dynamic_group(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Dynamic-group privilege abuse.

    A group with dynamic membership (groupTypes contains 'DynamicMembership')
    admits any principal that satisfies its membershipRule. If such a group
    holds a high-value Entra role and the rule keys on an attacker-influenceable
    attribute (UPN, mail, department, ...), a principal who can set that
    attribute joins the group and inherits the role.
    """
    data = kwargs.get("_full_data")
    if not data:
        return []
    azure_edges = data.get("azure_edges", []) or []
    if not azure_edges:
        return []

    group_roles: dict[str, list[str]] = {}
    for edge in azure_edges:
        if edge.get("edge_type") not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {}) or {}
        if props.get("isHighValue"):
            group_roles.setdefault(edge.get("source_id", ""), []).append(
                props.get("roleName", "Unknown Role"))

    findings: list[Finding] = []
    for obj in objects:
        if obj.get("object_class") != "aad_group":
            continue
        gid = obj.get("object_sid", "")
        if gid not in group_roles:
            continue
        props = obj.get("properties", {})
        group_types = props.get("groupTypes", []) or []
        if isinstance(group_types, str):
            group_types = [group_types]
        if not any("dynamicmembership" in str(t).lower() for t in group_types):
            continue

        rule = str(props.get("membershipRule", "") or "")
        rule_l = rule.lower()
        influenceable = [a for a in _ATTACKER_INFLUENCEABLE_ATTRS if a in rule_l]
        roles = group_roles[gid]
        name = obj.get("name", gid)
        if influenceable:
            sev = Severity.HIGH
            why = (f"its rule keys on attacker-influenceable attribute(s) "
                   f"({', '.join(influenceable)}) — a principal who can set one "
                   "joins the group and inherits the role")
        else:
            sev = Severity.MEDIUM
            why = ("membership is rule-based — any principal that satisfies the "
                   "rule inherits the role")
        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE,
            severity=sev,
            principal_sid=gid,
            principal_name=name,
            target_dn=f"AZ://aad_group/{gid}",
            target_name=name,
            target_class="aad_group",
            description=(
                f"Dynamic group '{name}' holds [{', '.join(roles)}] and {why}"
            ),
            rights=["DynamicMembership"] + roles,
            details={"attack_type": "azure_dynamic_group_abuse",
                     "roles": roles, "membership_rule": rule,
                     "influenceable_attrs": influenceable},
        ))

    return findings


def _ca_users_cond(pol_props: dict) -> dict:
    conds = pol_props.get("conditions", {}) or {}
    return conds.get("users", {}) or {}


def _ca_targets_all_users(pol_props: dict) -> bool:
    inc = _ca_users_cond(pol_props).get("includeUsers", []) or []
    if isinstance(inc, str):
        inc = [inc]
    return any(str(u).lower() == "all" for u in inc)


def _ca_grants(pol_props: dict) -> list[str]:
    gc = pol_props.get("grantControls", {}) or {}
    built = gc.get("builtInControls", []) or []
    if isinstance(built, str):
        built = [built]
    return [str(b).lower() for b in built]


def _check_azure_conditional_access(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Conditional Access posture gaps.

    Assesses collected CA policies (requires Policy.Read.All at collection) for
    common bypasses: policies that aren't enforced (disabled / report-only),
    exclusions that let privileged principals skip enforcement, legacy
    authentication not being blocked, and no tenant-wide MFA requirement.
    """
    policies = [o for o in objects if o.get("object_class") == "aad_ca_policy"]
    if not policies:
        return []   # no CA policies collected — cannot assess

    findings: list[Finding] = []
    tenant = domain or "tenant"
    any_blocks_legacy = False
    any_mfa_all = False

    for pol in policies:
        props = pol.get("properties", {})
        name = pol.get("name", props.get("displayName", "policy"))
        pid = pol.get("object_sid", "")
        state = str(props.get("state", "")).lower()
        grants = _ca_grants(props)
        enforcing_control = "mfa" in grants or "block" in grants

        if state == "disabled":
            findings.append(Finding(
                category=Category.AZURE_PRIVILEGE, severity=Severity.INFO,
                principal_sid=pid, principal_name=name,
                target_dn=f"AZ://aad_ca_policy/{pid}", target_name=name,
                target_class="aad_ca_policy",
                description=f"Conditional Access policy '{name}' is disabled — its control is not enforced",
                details={"attack_type": "azure_ca_gap", "gap": "disabled"},
            ))
            continue
        if state in ("enabledforreportingbutnotenforced", "reportonly"):
            findings.append(Finding(
                category=Category.AZURE_PRIVILEGE, severity=Severity.INFO,
                principal_sid=pid, principal_name=name,
                target_dn=f"AZ://aad_ca_policy/{pid}", target_name=name,
                target_class="aad_ca_policy",
                description=f"Conditional Access policy '{name}' is report-only — not enforced",
                details={"attack_type": "azure_ca_gap", "gap": "report_only"},
            ))
            continue

        # state == enabled below
        users = _ca_users_cond(props)
        client_types = props.get("conditions", {}).get("clientAppTypes", []) or []
        if isinstance(client_types, str):
            client_types = [client_types]
        client_types_l = {str(c).lower() for c in client_types}

        # Track tenant-wide protections
        if "block" in grants and _ca_targets_all_users(props) and (
                client_types_l & {"exchangeactivesync", "other"} or "all" in client_types_l):
            any_blocks_legacy = True
        if "mfa" in grants and _ca_targets_all_users(props):
            any_mfa_all = True

        # Exclusions on an enforcing policy = a bypass surface
        if enforcing_control:
            excl_roles = users.get("excludeRoles", []) or []
            excl_users = users.get("excludeUsers", []) or []
            excl_groups = users.get("excludeGroups", []) or []
            if excl_roles:
                findings.append(Finding(
                    category=Category.AZURE_PRIVILEGE, severity=Severity.HIGH,
                    principal_sid=pid, principal_name=name,
                    target_dn=f"AZ://aad_ca_policy/{pid}", target_name=name,
                    target_class="aad_ca_policy",
                    description=(
                        f"Enabled CA policy '{name}' excludes {len(excl_roles)} directory "
                        "role(s) from enforcement — excluded (often privileged) roles bypass "
                        f"its {'/'.join(grants)} control"
                    ),
                    details={"attack_type": "azure_ca_gap", "gap": "role_exclusion",
                             "excluded_roles": excl_roles},
                ))
            elif excl_users or excl_groups:
                findings.append(Finding(
                    category=Category.AZURE_PRIVILEGE, severity=Severity.MEDIUM,
                    principal_sid=pid, principal_name=name,
                    target_dn=f"AZ://aad_ca_policy/{pid}", target_name=name,
                    target_class="aad_ca_policy",
                    description=(
                        f"Enabled CA policy '{name}' excludes "
                        f"{len(excl_users) + len(excl_groups)} principal(s)/group(s) from its "
                        f"{'/'.join(grants)} control — verify none are privileged"
                    ),
                    details={"attack_type": "azure_ca_gap", "gap": "principal_exclusion"},
                ))

    if not any_blocks_legacy:
        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE, severity=Severity.HIGH,
            principal_sid=tenant, principal_name=tenant,
            target_dn="", target_name=tenant, target_class="azure_tenant",
            description=(
                "Legacy authentication is not blocked by any enabled Conditional Access "
                "policy — legacy protocols bypass MFA (password spray / credential stuffing)"
            ),
            details={"attack_type": "azure_ca_gap", "gap": "legacy_auth_allowed"},
        ))
    if not any_mfa_all:
        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE, severity=Severity.MEDIUM,
            principal_sid=tenant, principal_name=tenant,
            target_dn="", target_name=tenant, target_class="azure_tenant",
            description=(
                "No enabled Conditional Access policy requires MFA for all users — "
                "accounts without MFA are exposed to credential attacks"
            ),
            details={"attack_type": "azure_ca_gap", "gap": "no_mfa_all_users"},
        ))

    return findings


def _check_azure_federation(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Federated-domain / Golden SAML exposure.

    A verified domain with authenticationType 'Federated' trusts an external
    IdP (typically AD FS) to issue tokens. Whoever can steal that IdP's
    token-signing certificate can mint SAML tokens for any user — including
    Global Administrator — bypassing MFA and Conditional Access (Golden SAML).
    """
    findings: list[Finding] = []
    for obj in objects:
        if obj.get("object_class") != "aad_domain":
            continue
        props = obj.get("properties", {})
        if str(props.get("authenticationType", "")).lower() != "federated":
            continue
        name = obj.get("name", obj.get("object_sid", "domain"))
        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE,
            severity=Severity.HIGH,
            principal_sid=obj.get("object_sid", name),
            principal_name=name,
            target_dn=f"AZ://aad_domain/{obj.get('object_sid', name)}",
            target_name=name,
            target_class="aad_domain",
            description=(
                f"Domain '{name}' is federated — an external IdP (e.g. AD FS) issues "
                "tokens. Theft of its token-signing certificate enables Golden SAML: "
                "forge tokens for any user (incl. Global Admin), bypassing MFA/CA"
            ),
            details={"attack_type": "azure_federation",
                     "authentication_type": "Federated"},
        ))
    return findings


def _check_seamless_sso(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Entra Seamless SSO (AZUREADSSOACC$) exposure.

    Seamless SSO is backed by the on-prem computer account AZUREADSSOACC$. Its
    Kerberos decryption key, if not rotated regularly, lets an attacker who has
    extracted it forge Silver Tickets to impersonate any user to Entra ID.
    Flags the account's presence so key rotation can be verified.
    """
    findings: list[Finding] = []
    for obj in objects:
        if obj.get("object_class") != "computer":
            continue
        sam = str(obj.get("name", "")).upper().rstrip("$")
        props = obj.get("properties", {})
        sam2 = str(props.get("sAMAccountName", "")).upper().rstrip("$")
        if "AZUREADSSOACC" not in (sam, sam2):
            continue
        findings.append(Finding(
            category=Category.HYBRID_SYNC,
            severity=Severity.MEDIUM,
            principal_sid=obj.get("object_sid", ""),
            principal_name="AZUREADSSOACC$",
            target_dn=obj.get("dn", ""),
            target_name="AZUREADSSOACC$",
            target_class="computer",
            description=(
                "Entra Seamless SSO is enabled (AZUREADSSOACC$ present). If its "
                "Kerberos key is not rotated regularly, an attacker who extracts it "
                "can forge Silver Tickets to impersonate any user to Entra ID — "
                "verify the key is rolled on a schedule"
            ),
            details={"attack_type": "seamless_sso",
                     "pwdLastSet": props.get("pwdLastSet", "")},
        ))
    return findings


def _check_azure_cross_tenant_sync(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Inbound cross-tenant synchronization abuse.

    A cross-tenant access partner with inbound user synchronization enabled lets
    the partner tenant provision (and update) users in this tenant. A compromised
    or malicious partner can create backdoor accounts or take over synced users.
    """
    findings: list[Finding] = []
    for obj in objects:
        if obj.get("object_class") != "aad_xtenant_partner":
            continue
        props = obj.get("properties", {})
        sync = props.get("identitySynchronization", {}) or {}
        inbound = sync.get("userSyncInbound", {}) or {}
        if not inbound.get("isSyncAllowed"):
            continue
        partner = props.get("tenantId", "") or obj.get("name", "partner")
        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE,
            severity=Severity.HIGH,
            principal_sid=partner,
            principal_name=partner,
            target_dn="", target_name=domain or "tenant",
            target_class="azure_tenant",
            description=(
                f"Inbound cross-tenant sync is enabled from partner tenant {partner} — "
                "a compromised or malicious partner can provision backdoor users or take "
                "over synced accounts in this tenant"
            ),
            details={"attack_type": "azure_cross_tenant_sync", "partner_tenant": partner},
        ))
    return findings


def _check_azure_admin_units(
    objects: list[dict], sid_map: dict, domain: str, **kwargs: object,
) -> list[Finding]:
    """Administrative-unit-scoped privileged roles.

    A high-value directory role scoped to an administrative unit administers
    every member of that AU. If Tier-Zero or otherwise sensitive objects are
    placed in the AU, the AU-scoped admin can take them over (e.g. an AU-scoped
    Privileged Authentication Administrator resetting an admin's password).
    """
    data = kwargs.get("_full_data")
    if not data:
        return []
    azure_edges = data.get("azure_edges", []) or []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for edge in azure_edges:
        if edge.get("edge_type") not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {}) or {}
        if not props.get("isHighValue"):
            continue
        scope = str(edge.get("target_id", ""))
        if not scope.lower().startswith("/administrativeunits/"):
            continue
        principal_id = edge.get("source_id", "")
        au = scope.split("/administrativeUnits/", 1)[-1] if "/administrativeUnits/" in scope \
            else scope.rsplit("/", 1)[-1]
        key = (principal_id, scope)
        if key in seen:
            continue
        seen.add(key)
        pname = sid_map.get(principal_id, principal_id)
        role = props.get("roleName", "a privileged role")
        findings.append(Finding(
            category=Category.AZURE_PRIVILEGE,
            severity=Severity.MEDIUM,
            principal_sid=principal_id,
            principal_name=pname,
            target_dn=f"AZ://administrativeUnit/{au}",
            target_name=au,
            target_class="aad_admin_unit",
            description=(
                f"{pname} holds {role} scoped to administrative unit {au} — administers "
                "every member of that AU; dangerous if sensitive/Tier-Zero objects are in it"
            ),
            rights=[role],
            details={"attack_type": "azure_admin_unit_scoped_role",
                     "role": role, "administrative_unit": au},
        ))
    return findings


# ---------------------------------------------------------------------------
# Weighted Dijkstra and edge-filtered path queries (public API)
# ---------------------------------------------------------------------------

def dijkstra_shortest_paths(
    graph: dict[str, set[tuple[str, str]]],
    sources: set[str],
    targets: set[str],
    max_cost: float = 30.0,
    include_edges: set[str] | None = None,
    exclude_edges: set[str] | None = None,
) -> list[dict]:
    """Find weighted shortest paths from sources to targets using Dijkstra.

    Args:
        graph: Forward attack graph (src -> set of (dst, edge_label)).
        sources: Starting SIDs.
        targets: Goal SIDs.
        max_cost: Maximum cumulative path cost.
        include_edges: If set, only traverse edges with these labels.
        exclude_edges: If set, skip edges with these labels.

    Returns:
        List of dicts with keys: source, target, cost, path_sids, path_edges.
    """
    import heapq

    inc_lower = {e.lower() for e in include_edges} if include_edges is not None else None
    exc_lower = {e.lower() for e in exclude_edges} if exclude_edges is not None else None

    def _edge_allowed(label: str) -> bool:
        ll = label.lower()
        base = ll.split(":")[0]
        if inc_lower is not None:
            if ll not in inc_lower and base not in inc_lower:
                return False
        if exc_lower is not None:
            if ll in exc_lower or base in exc_lower:
                return False
        return True

    results: list[dict] = []

    for src in sources:
        # (cost, counter, node, path_sids, path_edges) — counter breaks ties
        counter = 0
        heap: list[tuple[float, int, str, list[str], list[str]]] = [
            (0.0, counter, src, [src], [])
        ]
        visited: dict[str, float] = {}

        while heap:
            cost, _, node, path, edges = heapq.heappop(heap)

            if cost > max_cost:
                break

            if node in visited and visited[node] <= cost:
                continue
            visited[node] = cost

            if node in targets and node != src:
                results.append({
                    "source": src,
                    "target": node,
                    "cost": round(cost, 2),
                    "path_sids": list(path),
                    "path_edges": list(edges),
                })
                # Don't stop expanding — this target may be on the path to
                # another target, so fall through to neighbor expansion.

            for neighbor, label in graph.get(node, set()):
                if not _edge_allowed(label):
                    continue
                w = get_edge_weight(label)
                new_cost = cost + w
                if new_cost > max_cost:
                    continue
                if neighbor in visited and visited[neighbor] <= new_cost:
                    continue
                counter += 1
                heapq.heappush(
                    heap,
                    (new_cost, counter, neighbor, path + [neighbor], edges + [label]),
                )

    return sorted(results, key=lambda r: r["cost"])


def filtered_bfs(
    graph: dict[str, set[tuple[str, str]]],
    sources: set[str],
    max_depth: int = 10,
    include_edges: set[str] | None = None,
    exclude_edges: set[str] | None = None,
) -> dict[str, dict]:
    """BFS with edge-type filtering. Returns reachable nodes with path info.

    Args:
        graph: Forward attack graph.
        sources: Starting SIDs.
        max_depth: Maximum hop count.
        include_edges: If set, only traverse these edge types.
        exclude_edges: If set, skip these edge types.

    Returns:
        Dict of sid -> {depth, parent_sid, edge_label, source_sid}.
    """
    inc_lower = {e.lower() for e in include_edges} if include_edges is not None else None
    exc_lower = {e.lower() for e in exclude_edges} if exclude_edges is not None else None

    def _edge_allowed(label: str) -> bool:
        ll = label.lower()
        base = ll.split(":")[0]
        if inc_lower is not None:
            if ll not in inc_lower and base not in inc_lower:
                return False
        if exc_lower is not None:
            if ll in exc_lower or base in exc_lower:
                return False
        return True

    result: dict[str, dict] = {}
    queue: deque[tuple[str, int, str]] = deque()  # (sid, depth, source_sid)

    for src in sources:
        result[src] = {"depth": 0, "parent_sid": "", "edge_label": "", "source_sid": src}
        queue.append((src, 0, src))

    while queue:
        current, d, src_sid = queue.popleft()
        if d >= max_depth:
            continue
        for neighbor, label in graph.get(current, set()):
            if not _edge_allowed(label):
                continue
            if neighbor in result:
                continue
            result[neighbor] = {
                "depth": d + 1,
                "parent_sid": current,
                "edge_label": label,
                "source_sid": src_sid,
            }
            queue.append((neighbor, d + 1, src_sid))

    return result


def _domain_maq(objects: list[dict]) -> int:
    """MachineAccountQuota for the collection (>0 => any user can create computers)."""
    for obj in objects:
        if obj.get("object_class") == "domain":
            try:
                return int(obj.get("properties", {}).get("ms-DS-MachineAccountQuota", 0) or 0)
            except (ValueError, TypeError):
                return 0
    return 0


# Trustees broad enough that "any authenticated user" effectively holds the right.
_BROAD_ENROLL_RIDS = ("-513", "-515", "-545")   # Domain Users, Domain Computers, Users
_BROAD_ENROLL_SIDS = {"S-1-5-11", "S-1-1-0", "S-1-5-32-545"}


def _is_broad_trustee(sid: str) -> bool:
    return sid in _BROAD_ENROLL_SIDS or any(sid.endswith(r) for r in _BROAD_ENROLL_RIDS)


def _check_certifried(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """Certifried (CVE-2022-26923).

    A machine-enrollable client-auth template that builds its SAN from the
    account's dNSHostName lets an attacker who can create a computer (MAQ>0)
    spoof that computer's dNSHostName to a DC and enroll for a DC certificate.
    Detected as a precondition: MAQ>0 + such a template. (An unpatched CA —
    pre-May-2022 — makes it directly exploitable; a patched CA needs the
    template to also lack the security extension, i.e. combine with ESC9/16.)
    """
    findings: list[Finding] = []
    maq = _domain_maq(objects)
    if maq <= 0:
        return findings  # no cheap way to create the machine account

    # name-flag bits
    SUPPLIES_SUBJECT = 0x00000001
    SAN_REQUIRE_DNS = 0x08000000
    SAN_REQUIRE_DOMAIN_DNS = 0x00400000

    for tmpl in (o for o in objects if o.get("object_class") == "certtemplate"):
        props = tmpl.get("properties", {})
        name = tmpl.get("name", tmpl.get("dn", ""))
        try:
            name_flag = int(props.get("msPKI-Certificate-Name-Flag", 0) or 0)
        except (ValueError, TypeError):
            name_flag = 0
        try:
            enroll_flag = int(props.get("msPKI-Enrollment-Flag", 0) or 0)
        except (ValueError, TypeError):
            enroll_flag = 0
        try:
            ra_sig = int(props.get("msPKI-RA-Signature", 0) or 0)
        except (ValueError, TypeError):
            ra_sig = 0

        ekus = props.get("pKIExtendedKeyUsage", [])
        if isinstance(ekus, str):
            ekus = [ekus]
        auth_capable = (
            "1.3.6.1.5.5.7.3.2" in ekus         # Client Authentication
            or "1.3.6.1.4.1.311.20.2.2" in ekus  # Smart Card Logon
            or "2.5.29.37.0" in ekus             # Any Purpose
            or len(ekus) == 0                    # no EKU
        )
        auto_san_from_dns = bool(name_flag & (SAN_REQUIRE_DNS | SAN_REQUIRE_DOMAIN_DNS))
        supplies_subject = bool(name_flag & SUPPLIES_SUBJECT)   # that would be ESC1
        manager_approval = bool(enroll_flag & 0x00000002)

        if not (auth_capable and auto_san_from_dns and not supplies_subject):
            continue
        if manager_approval or ra_sig != 0:
            continue

        # Machine-enrollable by a broad principal?
        for ace in tmpl.get("dacl", []):
            trustee_sid = ace.get("trustee_sid", "")
            if not trustee_sid or not _can_enroll(ace):
                continue
            if not _is_broad_trustee(trustee_sid):
                continue
            trustee_name = _resolve_name(trustee_sid, sid_map, domain)
            findings.append(Finding(
                category=Category.ADCS_ABUSE,
                severity=Severity.HIGH,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=tmpl.get("dn", ""),
                target_name=name,
                target_class="certtemplate",
                description=(
                    f"Certifried (CVE-2022-26923): template '{name}' is enrollable by "
                    f"{trustee_name} and builds its SAN from dNSHostName — with "
                    f"MachineAccountQuota={maq}>0 any user can create a computer, set its "
                    "dNSHostName to a DC, and obtain a DC certificate"
                ),
                rights=["Enroll"],
                is_builtin=_is_builtin(trustee_sid),
                details={"esc_type": "Certifried", "cve": "CVE-2022-26923",
                         "template": name, "machine_account_quota": maq},
            ))
            break   # one finding per template is enough

    return findings


# msDS access-mask bits used for "can weaponize this object"
_MASK_GENERIC_ALL = 0x10000000
_MASK_GENERIC_WRITE = 0x40000000
_MASK_WRITE_PROP = 0x00000020
_MASK_WRITE_DACL = 0x00040000
_MASK_WRITE_OWNER = 0x00080000
_DMSA_WEAPONIZE_MASK = (
    _MASK_GENERIC_ALL | _MASK_GENERIC_WRITE | _MASK_WRITE_PROP
    | _MASK_WRITE_DACL | _MASK_WRITE_OWNER
)


def _is_dmsa(obj: dict) -> bool:
    cls = str(obj.get("object_class", "")).lower()
    return cls == "dmsa" or "delegatedmanagedservice" in cls


def _check_dmsa_badsuccessor(
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
) -> list[Finding]:
    """dMSA takeover / BadSuccessor (Windows Server 2025).

    A delegated Managed Service Account (dMSA) can be configured to *succeed*
    another account via msDS-ManagedAccountPrecededByLink, inheriting that
    account's privileges. Anyone who can create a dMSA or write that link on
    one can escalate to any principal — including Tier Zero — hence
    "BadSuccessor". Detects (a) dMSAs already superseding a privileged account,
    and (b) principals with write control over an existing dMSA.
    """
    findings: list[Finding] = []
    dmsas = [o for o in objects if _is_dmsa(o)]
    if not dmsas:
        return findings   # no dMSA objects collected (pre-Server-2025 / not gathered)

    by_dn = {str(o.get("dn", "")).lower(): o for o in objects if o.get("dn")}

    for dmsa in dmsas:
        props = dmsa.get("properties", {})
        name = dmsa.get("name", dmsa.get("dn", ""))
        dn = dmsa.get("dn", "")

        # (a) Already superseding a predecessor — critical if that account is privileged.
        pred = (props.get("msDS-ManagedAccountPrecededByLink")
                or props.get("msds-managedaccountprecededbylink") or "")
        if isinstance(pred, list):
            pred = pred[0] if pred else ""
        if pred:
            pred_obj = by_dn.get(str(pred).lower())
            pred_sid = pred_obj.get("object_sid", "") if pred_obj else ""
            pred_name = _resolve_name(pred_sid, sid_map, domain) if pred_sid else str(pred)
            # Privileged predecessor = well-known Tier Zero, or AdminSDHolder-protected
            # (adminCount=1, which AD stamps on DA/EA/etc. members).
            try:
                pred_admincount = int((pred_obj or {}).get("properties", {}).get("adminCount", 0) or 0)
            except (ValueError, TypeError):
                pred_admincount = 0
            if pred_sid and (_is_high_value(pred_sid) or pred_admincount == 1):
                findings.append(Finding(
                    category=Category.DMSA_ABUSE,
                    severity=Severity.CRITICAL,
                    principal_sid=dmsa.get("object_sid", ""),
                    principal_name=name,
                    target_dn=dn,
                    target_name=pred_name,
                    target_class="msds-delegatedmanagedserviceaccount",
                    description=(
                        f"dMSA '{name}' supersedes privileged account {pred_name} "
                        "(msDS-ManagedAccountPrecededByLink) — inherits its privileges "
                        "(BadSuccessor)"
                    ),
                    details={"attack": "BadSuccessor", "predecessor": pred_name},
                ))

        # (b) Who can weaponize this dMSA (write the succession link / full control)?
        for ace in dmsa.get("dacl", []):
            trustee_sid = ace.get("trustee_sid", "")
            if not trustee_sid or _is_builtin(trustee_sid) or _is_high_value(trustee_sid):
                continue
            try:
                mask = int(ace.get("access_mask", 0) or 0)
            except (ValueError, TypeError):
                mask = 0
            if not (mask & _DMSA_WEAPONIZE_MASK):
                continue
            trustee_name = _resolve_name(trustee_sid, sid_map, domain)
            findings.append(Finding(
                category=Category.DMSA_ABUSE,
                severity=Severity.HIGH,
                principal_sid=trustee_sid,
                principal_name=trustee_name,
                target_dn=dn,
                target_name=name,
                target_class="msds-delegatedmanagedserviceaccount",
                description=(
                    f"{trustee_name} has write control over dMSA '{name}' — can set its "
                    "succession link (msDS-ManagedAccountPrecededByLink) to any account "
                    "and escalate (BadSuccessor)"
                ),
                rights=["WriteProperty"],
                details={"attack": "BadSuccessor", "dmsa": name},
            ))

    return findings


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

_CHECK_REGISTRY: list[CheckDef] = [
    CheckDef("acl", "ACL-based privilege escalation (GenericAll, WriteDACL, WriteOwner, extended rights, WriteProperty)", _check_acl_abuse),
    CheckDef("kerberoast", "Kerberoastable user accounts (SPN set on non-computer accounts)", _check_kerberoastable),
    CheckDef("asrep", "AS-REP roastable users (pre-authentication not required)", _check_asrep_roastable),
    CheckDef("unconstrained", "Unconstrained delegation (TGT capture risk)", _check_unconstrained_delegation),
    CheckDef("constrained", "Constrained delegation (S4U2Proxy / protocol transition)", _check_constrained_delegation),
    CheckDef("rbcd", "Resource-based constrained delegation (S4U2Self/S4U2Proxy)", _check_rbcd),
    CheckDef("membership", "Nested group membership paths to DA-equivalent groups", _check_nested_da_membership),
    CheckDef("config", "Dangerous configurations (PASSWD_NOTREQD, orphaned adminCount, MAQ)", _check_dangerous_config),
    CheckDef("ownership", "Object ownership abuse on high-value targets", _check_ownership),
    CheckDef("gpo", "GPO abuse paths (modification rights, linking, inheritance)", _check_gpo_abuse),
    CheckDef("ou", "OU control and AdminSDHolder abuse", _check_ou_control),
    CheckDef("dcsync", "DCSync / replication rights (GetChanges + GetChangesAll)", _check_dcsync),
    CheckDef("laps", "LAPS password read access (ms-Mcs-AdmPwd, ms-LAPS-Password)", _check_laps_read),
    CheckDef("gmsa", "gMSA managed password read access (msDS-ManagedPassword)", _check_gmsa_read),
    CheckDef("adcs", "ADCS certificate abuse (ESC1-ESC13, GoldenCert, WritePKI)", _check_adcs),
    CheckDef("certifried", "Certifried (CVE-2022-26923) — dNSHostName SAN cert abuse via MAQ", _check_certifried),
    CheckDef("dmsa", "dMSA takeover / BadSuccessor (Server 2025 delegated MSA succession)", _check_dmsa_badsuccessor),
    CheckDef("trust", "Trust and forest trust abuse paths (SIDHistory, SID filtering)", _check_trust_abuse),
    CheckDef("sessions", "Session abuse — high-value users with active sessions (credential theft risk)", _check_session_abuse),
    CheckDef("local-access", "Local group access — AdminTo, CanRDP, ExecuteDCOM, CanPSRemote edges", _check_local_access),
    CheckDef("shortest-path", "Shortest attack paths to high-value targets via graph analysis", _check_shortest_paths),
    CheckDef("blast-radius", "Blast radius from owned/compromised principals (requires --owned)", _check_blast_radius),
    CheckDef("correlation", "Cross-correlated compound risks from multiple findings", _cross_correlate, is_meta=True),
    # Hybrid / Azure checks (only produce findings when azure data is present)
    CheckDef("hybrid-sync", "Synced AD users with high-value Entra roles (hybrid attack paths)", _check_hybrid_sync, category="hybrid"),
    CheckDef("azure-globaladmin", "Principals with Global Admin or equivalent Entra roles", _check_azure_globaladmin, category="azure"),
    CheckDef("azure-app-abuse", "App/SP ownership abuse paths to high-privilege roles", _check_azure_app_abuse, category="azure"),
    CheckDef("azure-managed-identity", "Managed-identity abuse — resources running as privileged identities", _check_azure_managed_identity, category="azure"),
    CheckDef("azure-dynamic-group", "Dynamic-group privilege abuse (rule-based membership to a privileged role)", _check_azure_dynamic_group, category="azure"),
    CheckDef("azure-conditional-access", "Conditional Access posture gaps (unenforced policies, exclusions, legacy auth, MFA)", _check_azure_conditional_access, category="azure"),
    CheckDef("azure-federation", "Federated-domain / Golden SAML exposure (external IdP token-signing)", _check_azure_federation, category="azure"),
    CheckDef("seamless-sso", "Entra Seamless SSO (AZUREADSSOACC$) Silver-ticket-to-cloud exposure", _check_seamless_sso, category="hybrid"),
    CheckDef("azure-cross-tenant-sync", "Inbound cross-tenant synchronization abuse (partner-tenant provisioning)", _check_azure_cross_tenant_sync, category="azure"),
    CheckDef("azure-admin-units", "Administrative-unit-scoped privileged roles", _check_azure_admin_units, category="azure"),
]


def list_checks() -> list[CheckDef]:
    """Return the full check registry for display."""
    return list(_CHECK_REGISTRY)


def get_active_checks(
    include: set[str] | None = None,
    exclude: set[str] | None = None,
    categories: set[str] | None = None,
) -> list[CheckDef]:
    """Filter the check registry based on include/exclude/category sets.

    If *include* is provided, only those checks (plus 'correlation') are run.
    If *exclude* is provided, those checks are skipped.
    If *categories* is provided, only checks in those categories are run
    (plus 'correlation' meta-check).
    All filters can be combined: include → categories → exclude.
    """
    checks = list(_CHECK_REGISTRY)

    if include:
        # Always keep correlation meta-check unless explicitly excluded
        include_with_meta = include | {"correlation"}
        checks = [c for c in checks if c.name in include_with_meta]

    if categories:
        # Filter by category tag, always keep meta checks
        cat_set = {c.lower() for c in categories}
        checks = [
            c for c in checks
            if c.is_meta or _CHECK_CATEGORIES.get(c.name, "") in cat_set
        ]

    if exclude:
        checks = [c for c in checks if c.name not in exclude]

    return checks


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
# Whether to hide findings whose ACTOR (trustee/owner) is itself Tier Zero.
# Such principals are already maximally privileged, so "Tier Zero can do X" is
# not an escalation path (same rationale as excluding Tier-Zero shortest-path
# sources). Shown by default; hide with set_show_tier_zero_actors(False)
# (the analyze menu's `run --notier0`).
_HIDE_TIER_ZERO_ACTORS = False

# Categories whose principal_sid is an ACTOR (someone exercising a right),
# not a victim/target — so a Tier-Zero principal_sid means "no escalation".
_ACTOR_CATEGORIES = {
    Category.ACL_ABUSE,
    Category.GPO_ABUSE,
    Category.OU_CONTROL,
    Category.DCSYNC,
    Category.LAPS_READ,
    Category.GMSA_READ,
    Category.OWNERSHIP,
}

# Human verb per actor category, for effective-via-membership descriptions.
_ACTOR_VERB = {
    Category.ACL_ABUSE: "control (ACL)",
    Category.GPO_ABUSE: "GPO control",
    Category.OU_CONTROL: "OU control",
    Category.DCSYNC: "DCSync",
    Category.LAPS_READ: "LAPS read",
    Category.GMSA_READ: "gMSA read",
    Category.OWNERSHIP: "ownership",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO]


def _actor_group_findings(
    findings: list[Finding],
    obj_class: dict[str, str],
    skip_slugs: set[str] | None,
) -> dict[str, list[Finding]]:
    """Actor-category findings whose principal is a GROUP, grouped by the
    group's SID. Skips already-effective findings and any category in
    ``skip_slugs`` (categories being aggregated are not re-expanded)."""
    by_group: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.category not in _ACTOR_CATEGORIES:
            continue
        if skip_slugs and f.category.slug in skip_slugs:
            continue
        if (f.details or {}).get("effective"):
            continue
        if obj_class.get(f.principal_sid) != "group":
            continue
        by_group[f.principal_sid].append(f)
    return by_group


def _project_expansion_size(
    by_group: dict[str, list[Finding]],
    group_to_members: dict[str, set[str]],
    obj_class: dict[str, str],
    cap: int,
) -> int:
    """Conservative upper bound on the number of per-member effective findings
    expansion would emit: for each group, its transitive-member count times the
    number of findings it holds. Holds at most one group's members at a time
    (the walk itself caps at ``_GROUP_MEMBER_CAP``), so it never inflates memory.
    Over-counts (ignores cross-finding dedup), so it never *under*-estimates.
    Early-exits once the running total exceeds a nonzero ``cap``."""
    total = 0
    for gsid, gfindings in by_group.items():
        n = len(_transitive_leaf_members(
            gsid, group_to_members, obj_class, _GROUP_MEMBER_CAP))
        total += n * len(gfindings)
        if cap and total > cap:
            return total
    return total


def _expand_per_member(by_group, group_to_members, obj_class, direct, _name, _rank):
    """One effective Finding per (member, category, target). Walks each holder
    group once (one group's members resident at a time)."""
    best: dict[tuple, tuple] = {}
    for gsid, gfindings in by_group.items():
        members = _transitive_leaf_members(
            gsid, group_to_members, obj_class, _GROUP_MEMBER_CAP)
        for f in gfindings:
            rank = _rank(f.severity)
            tkey = f.target_dn or f.target_name
            for msid, chain in members.items():
                key = (msid, f.category, tkey)
                if key in direct:
                    continue
                cand = (rank, len(chain), f, chain, gsid)
                prev = best.get(key)
                if prev is None or cand[:2] < prev[:2]:
                    best[key] = cand
    out: list[Finding] = []
    for (msid, cat, _t), (_r, _cl, src, chain, top_sid) in best.items():
        member_name = _name(msid)
        top_name = _name(top_sid)
        chain_names = [_name(g) for g in chain]
        det = dict(src.details or {})
        det.update({"effective": True, "via_group": top_name, "via_group_sid": top_sid,
                    "path_names": [member_name] + chain_names + [src.target_name]})
        verb = _ACTOR_VERB.get(cat, "privileged access")
        out.append(Finding(
            category=cat, severity=src.severity,
            principal_sid=msid, principal_name=member_name,
            target_dn=src.target_dn, target_name=src.target_name,
            target_class=src.target_class,
            description=(f"{member_name} has effective {verb} on {src.target_name} "
                        f"via membership in {top_name}"),
            rights=list(src.rights), is_builtin=_is_builtin(msid), details=det,
        ))
    return out


def _expand_rolled_up(by_group, group_to_members, obj_class, direct, _name, _rank):
    """One effective Finding per (member, category, rights, target-class) with a
    count + sample — the bounded-memory mode for very large forests. Memory
    ceiling = unique (member, right, class); one group's members resident at a
    time."""
    agg: dict[tuple, dict] = {}
    for gsid, gfindings in by_group.items():
        members = _transitive_leaf_members(
            gsid, group_to_members, obj_class, _GROUP_MEMBER_CAP)
        for f in gfindings:
            rank = _rank(f.severity)
            tkey = f.target_dn or f.target_name
            rights = tuple(sorted(f.rights))
            for msid, chain in members.items():
                if (msid, f.category, tkey) in direct:
                    continue
                akey = (msid, f.category, rights, f.target_class)
                roll = agg.get(akey)
                if roll is None:
                    agg[akey] = {"count": 1, "rank": rank, "sev": f.severity,
                                 "chain": chain, "top_sid": gsid,
                                 "targets": ([f.target_name] if f.target_name else []),
                                 "rights": list(f.rights)}
                else:
                    roll["count"] += 1
                    if f.target_name and len(roll["targets"]) < 25:
                        roll["targets"].append(f.target_name)
                    if rank < roll["rank"] or (
                            rank == roll["rank"] and len(chain) < len(roll["chain"])):
                        roll.update({"rank": rank, "sev": f.severity,
                                     "chain": chain, "top_sid": gsid})
    out: list[Finding] = []
    for (msid, cat, _rk, tclass), roll in agg.items():
        member_name = _name(msid)
        top_name = _name(roll["top_sid"])
        chain_names = [_name(g) for g in roll["chain"]]
        verb = _ACTOR_VERB.get(cat, "privileged access")
        noun = tclass or "object"
        sample = ", ".join(roll["targets"][:5]) + ("…" if roll["count"] > 5 else "")
        out.append(Finding(
            category=cat, severity=roll["sev"],
            principal_sid=msid, principal_name=member_name,
            target_dn="", target_name=f"{roll['count']} {noun}s", target_class=tclass,
            description=(f"{member_name} has effective {verb} on {roll['count']} "
                        f"{noun}(s) via membership in {top_name}"
                        + (f" (e.g. {sample})" if sample else "")),
            rights=list(roll["rights"]), is_builtin=_is_builtin(msid),
            details={"effective": True, "via_group": top_name,
                     "via_group_sid": roll["top_sid"], "aggregated": True,
                     "count": roll["count"], "targets_sample": roll["targets"][:25],
                     "path_names": [member_name] + chain_names + [f"{roll['count']} {noun}s"]},
        ))
    return out


def _expand_actor_findings(
    findings: list[Finding],
    objects: list[dict],
    sid_map: dict[str, str],
    domain: str,
    *,
    skip_slugs: set[str] | None = None,
    cap: int = _DEFAULT_EXPAND_CAP,
    stats: dict | None = None,
) -> list[Finding]:
    """For every actor-category finding whose principal is a GROUP, emit findings
    for the group's transitive members — they hold the privilege via membership.

    Two modes, chosen by a projected effective-finding count vs ``cap``
    (0 disables rollup): below the cap, one finding per (member, right, target)
    as before (highest severity then shortest chain wins, principals already
    reported directly are skipped); above it, a bounded rolled-up finding per
    (member, right, target-class) with a count. ``skip_slugs`` categories are not
    expanded (expanding contradicts a roll-up and re-explodes them). ``stats``
    (if a dict) is filled with ``{"projected", "cap", "rolled_up"}``.
    """
    member_of, sid_names, _ = _build_group_graph(objects)
    group_to_members: dict[str, set[str]] = defaultdict(set)
    for msid, groups in member_of.items():
        for g in groups:
            group_to_members[g].add(msid)
    obj_class = {o.get("object_sid", ""): (o.get("object_class") or "")
                 for o in objects}

    def _name(sid: str) -> str:
        return sid_names.get(sid) or _resolve_name(sid, sid_map, domain)

    def _rank(sev: Severity) -> int:
        return _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else len(_SEVERITY_ORDER)

    direct = {(f.principal_sid, f.category, f.target_dn or f.target_name)
              for f in findings}
    by_group = _actor_group_findings(findings, obj_class, skip_slugs)

    projected = _project_expansion_size(by_group, group_to_members, obj_class, cap)
    rolled_up = bool(cap) and projected > cap
    if stats is not None:
        stats.update({"projected": projected, "cap": cap, "rolled_up": rolled_up})

    if rolled_up:
        return _expand_rolled_up(by_group, group_to_members, obj_class, direct, _name, _rank)
    return _expand_per_member(by_group, group_to_members, obj_class, direct, _name, _rank)


# Attacker-controllable principal classes valid as a shortest-path SOURCE
# (on-prem AD + Entra identity principals).
_PRINCIPAL_CLASSES = {
    "user", "group", "computer",
    "aad_user", "aad_group", "aad_sp", "aad_app", "aad_device",
}

# Exchange system/service objects that are never meaningful escalation targets
# (health mailboxes, system mailboxes, arbitration/migration mailboxes, etc.).
# Control over these is by-design Exchange-tier management, not an attack path.
_EXCHANGE_NOISE_PREFIXES = (
    "HEALTHMAILBOX", "SM_", "SYSTEMMAILBOX", "DISCOVERYSEARCHMAILBOX",
    "MIGRATION.", "$",
)


def _is_exchange_system_object(name: str | None) -> bool:
    """True if the object name is an Exchange system/service mailbox (noise)."""
    if not name:
        return False
    return name.upper().lstrip().startswith(_EXCHANGE_NOISE_PREFIXES)


def set_show_tier_zero_actors(show: bool) -> None:
    """Show (True) or hide (False, default) low-signal findings: Tier-Zero
    principals acting, and ACL noise targeting Exchange system objects."""
    global _HIDE_TIER_ZERO_ACTORS
    _HIDE_TIER_ZERO_ACTORS = not show


def extend_high_value_rids(rids: set[int]) -> None:
    """Add custom RIDs to the high-value target set.

    Useful for marking custom tier-0 groups as high-value without
    modifying source code.
    """
    global HIGH_VALUE_RIDS
    HIGH_VALUE_RIDS = HIGH_VALUE_RIDS | rids


def set_graph_depth_limits(
    shortest_path: int | None = None,
    blast_radius: int | None = None,
) -> None:
    """Override BFS depth limits for shortest-path and blast-radius checks."""
    global SHORTEST_PATH_MAX_DEPTH, BLAST_RADIUS_MAX_DEPTH
    if shortest_path is not None:
        SHORTEST_PATH_MAX_DEPTH = shortest_path
    if blast_radius is not None:
        BLAST_RADIUS_MAX_DEPTH = blast_radius


def load_collection(path: str | Path) -> dict:
    """Load and validate a collection JSON file.

    Raises ``ValueError`` if required top-level keys are missing.
    """
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Collection file must contain a JSON object, got {type(data).__name__}")
    missing = [k for k in ("meta", "objects", "sid_map") if k not in data]
    if missing:
        raise ValueError(
            f"Collection file is missing required key(s): {', '.join(missing)}. "
            "Ensure the file was produced by 'lazyhound collect'."
        )
    if not isinstance(data["objects"], list):
        raise ValueError("'objects' must be a JSON array")
    if not isinstance(data["sid_map"], dict):
        raise ValueError("'sid_map' must be a JSON object")
    return data


# Path/meta categories are inherently on-path — never pruned.
_PRUNE_KEEP_CATEGORIES = {
    Category.SHORTEST_PATH, Category.BLAST_RADIUS, Category.CROSS_CORRELATION,
}


def _reachable_to_tier_zero(
    objects: list[dict], sid_map: dict[str, str], *,
    sessions=None, local_group_members=None, azure_edges=None,
) -> set[str]:
    """SIDs that can reach any Tier-Zero target — reverse BFS over the full
    attack graph (O(V+E)). Used by ``analyze(prune=True)`` to drop findings
    whose principal leads nowhere. Includes the Tier-Zero targets themselves."""
    graph, _sid_names, _ = _build_attack_graph(
        objects, sid_map=sid_map, sessions=sessions,
        local_group_members=local_group_members, azure_edges=azure_edges)
    obj_class = {o.get("object_sid", ""): (o.get("object_class") or "").lower()
                 for o in objects if o.get("object_sid")}
    hv = _high_value_target_sids(objects, graph, obj_class)
    reverse: dict[str, set[str]] = defaultdict(set)
    for src, edges in graph.items():
        for tgt, _label in edges:
            reverse[tgt].add(src)
    reachable: set[str] = set(hv)
    queue: deque[str] = deque(hv)
    while queue:
        cur = queue.popleft()
        for pred in reverse.get(cur, ()):
            if pred not in reachable:
                reachable.add(pred)
                queue.append(pred)
    return reachable


def prune_findings(findings: list[Finding], reachable: set[str]) -> list[Finding]:
    """Keep only findings whose principal is on a path to Tier Zero (plus the
    path/meta findings, which are inherently on-path)."""
    return [f for f in findings
            if f.category in _PRUNE_KEEP_CATEGORIES
            or not f.principal_sid
            or f.principal_sid in reachable]


def aggregate_findings(findings: list[Finding], slugs: set[str]) -> list[Finding]:
    """Collapse findings in the given finding-category slugs by
    (principal, rights, target-class) into one finding with a count + sample.
    Findings in other categories pass through unchanged."""
    slugs = {s.lower() for s in slugs}
    if not slugs:
        return findings
    passthrough: list[Finding] = []
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        if f.category.slug not in slugs:
            passthrough.append(f)
            continue
        key = (f.principal_sid, f.category, tuple(sorted(f.rights)), f.target_class)
        groups.setdefault(key, []).append(f)
    out = list(passthrough)
    for (psid, cat, rights, tclass), fs in groups.items():
        if len(fs) == 1:
            out.append(fs[0])
            continue
        rep = fs[0]
        def _sev_rank(f):
            return _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
        worst = min(fs, key=_sev_rank).severity
        targets = [x.target_name for x in fs if x.target_name]
        sample = ", ".join(targets[:5]) + ("…" if len(targets) > 5 else "")
        rlabel = "/".join(rights) if rights else cat.value
        noun = tclass or "object"
        out.append(Finding(
            category=cat, severity=worst,
            principal_sid=psid, principal_name=rep.principal_name,
            target_dn="", target_name=f"{len(fs)} {noun}s", target_class=tclass,
            description=(f"{rep.principal_name} has {rlabel} on {len(fs)} "
                         f"{noun}(s)" + (f" (e.g. {sample})" if sample else "")),
            rights=list(rights),
            details={"aggregated": True, "count": len(fs), "targets_sample": targets[:25]},
        ))
    return out


def analyze(
    data: dict,
    checks: set[str] | None = None,
    exclude: set[str] | None = None,
    owned: list[str] | None = None,
    categories: set[str] | None = None,
    progress_callback: "Callable[[str, int, int], None] | None" = None,
    aggregate: set[str] | None = None,
    prune: bool = False,
    expand: bool = True,
    expand_cap: int = _DEFAULT_EXPAND_CAP,
) -> AnalysisResult:
    """Run attack path checks and return combined results with cross-correlation.

    Args:
        data: Parsed collection JSON.
        checks: If provided, only run these named checks (plus correlation).
        exclude: If provided, skip these named checks.
        owned: List of owned/compromised principal identifiers (names, SIDs,
            or sAMAccountNames). When provided, the blast-radius check runs
            automatically and shortest-path is scoped to owned principals.
        categories: If provided, only run checks in these categories
            (e.g. {"acl", "kerberos", "delegation"}).
        aggregate: Finding-category slugs (e.g. {"acl_abuse", "dcsync"}) to
            collapse — many per-object findings become one per
            (principal, right, target-class) with a count + sample. Opt-in;
            other categories are untouched.
        prune: When True, drop findings whose principal cannot reach a
            Tier-Zero target (keeps only the reachable subgraph). Opt-in.
        expand: When True (default), explode each group-held finding into a
            finding per transitive member. Set False (--noexpand) to skip that
            phase entirely — attack paths are unaffected (they come from the
            graph BFS, not expansion), only the per-member effective findings
            are omitted. The biggest single cost at large scale.
        expand_cap: Projected effective-finding count above which expansion
            rolls up to per-(member, right, class) counts (default 250k). 0
            disables rollup (force per-member). When ``prune`` is set,
            expansion input is first restricted to the Tier-Zero-reachable set.
    """
    sid_map = dict(data.get("sid_map", {}))  # copy so we don't mutate input
    meta = data.get("meta", {})
    domain = meta.get("domain", "unknown")
    source = meta.get("dc", "unknown")
    objects = data.get("objects", [])

    # Network collection data (sessions and local group memberships)
    sessions = data.get("sessions")
    local_group_members = data.get("local_group_members")
    azure_edges = data.get("azure_edges")

    # Supplement sid_map with names from all collected objects so that
    # trustee SIDs referencing collected principals always resolve.
    for obj in objects:
        sid = obj.get("object_sid")
        name = obj.get("name") or obj.get("dn", "")
        if sid and name and sid not in sid_map:
            sid_map[sid] = name

    # Resolve owned identifiers to SIDs
    owned_sids: set[str] = set()
    if owned:
        owned_sids = _resolve_owned_sids(owned, objects, sid_map)

    result = AnalysisResult(
        domain=domain, source_file=source, owned_sids=owned_sids,
        total_objects=len(objects),
    )

    active = get_active_checks(checks, exclude, categories=categories)

    # If --owned is provided, ensure blast-radius runs — but only when
    # running the full suite (no category filter) or the 'paths' category.
    if owned_sids:
        if categories is None or "paths" in categories:
            active_names = {c.name for c in active}
            if "blast-radius" not in active_names:
                for c in _CHECK_REGISTRY:
                    if c.name == "blast-radius":
                        active.insert(-1, c)  # before correlation
                        break
        else:
            import sys
            active_cat_names = {c.name for c in active if not c.is_meta}
            _OWNED_RELEVANT = {"blast-radius", "shortest-path", "acl", "paths"}
            if not (active_cat_names & _OWNED_RELEVANT):
                print(
                    f"Warning: --owned has no effect on category "
                    f"{', '.join(sorted(categories))}; blast-radius "
                    f"only runs with 'paths' or the full analysis.",
                    file=sys.stderr,
                )

    # Checks that need the full data dict (hybrid/azure checks)
    _HYBRID_CHECKS = {"hybrid-sync", "azure-globaladmin", "azure-app-abuse",
                      "azure-managed-identity", "azure-dynamic-group",
                      "azure-conditional-access", "azure-admin-units"}

    # Run object-level checks first
    non_meta = [c for c in active if not c.is_meta]
    meta_checks = [c for c in active if c.is_meta]
    total_checks = len(non_meta) + len(meta_checks)
    completed = 0

    for check in non_meta:
        if progress_callback:
            progress_callback(check.name, completed, total_checks)
        if check.name == "blast-radius":
            result.findings.extend(
                check.func(
                    objects, sid_map, domain, owned_sids=owned_sids,
                    sessions=sessions, local_group_members=local_group_members,
                    azure_edges=azure_edges,
                )
            )
        elif check.name == "sessions":
            result.findings.extend(
                check.func(objects, sid_map, domain, sessions=sessions)
            )
        elif check.name == "local-access":
            result.findings.extend(
                check.func(objects, sid_map, domain, local_group_members=local_group_members)
            )
        elif check.name == "shortest-path":
            result.findings.extend(
                check.func(
                    objects, sid_map, domain,
                    sessions=sessions, local_group_members=local_group_members,
                    azure_edges=azure_edges,
                )
            )
        elif check.name in _HYBRID_CHECKS:
            result.findings.extend(
                check.func(objects, sid_map, domain, _full_data=data)
            )
        elif check.name == "acl":
            # --aggregate acl_abuse rolls up inline (bounded peak memory).
            result.findings.extend(
                check.func(objects, sid_map, domain, aggregate=aggregate)
            )
        else:
            result.findings.extend(check.func(objects, sid_map, domain))
        completed += 1

    # A group that holds a dangerous right grants it to its transitive members.
    # Surface those effective holders as their own findings (with the membership
    # path) across every actor category — before suppression, so a member via a
    # Tier-Zero group is hidden by default and a member via a custom group shows.
    # A category being aggregated is being deliberately rolled up; re-exploding
    # it into per-member findings contradicts that (and is the dominant cost at
    # scale), so those categories are skipped from expansion.
    # When pruning, restrict to the Tier-Zero-reachable subgraph BEFORE
    # expanding, so only holder groups that actually reach Tier Zero explode
    # into members (the expensive part). The reachable set is reused for a
    # cheap post-meta filter below (no second BFS).
    reachable: set[str] | None = None
    if prune:
        if progress_callback:
            progress_callback("prune (reachability)", completed, total_checks)
        reachable = _reachable_to_tier_zero(
            objects, sid_map, sessions=sessions,
            local_group_members=local_group_members, azure_edges=azure_edges)
        result.findings = prune_findings(result.findings, reachable)

    if expand:
        if progress_callback:
            progress_callback("expand group members", completed, total_checks)
        _exp_stats: dict = {}
        result.findings.extend(_expand_actor_findings(
            result.findings, objects, sid_map, domain,
            skip_slugs=aggregate, cap=expand_cap, stats=_exp_stats))
        result.expansion_rolled_up = _exp_stats.get("rolled_up", False)
        result.expansion_projected = _exp_stats.get("projected", 0)
        result.expansion_cap = _exp_stats.get("cap", expand_cap)

    # Suppress low-signal findings (default), before correlation so compound
    # risks don't re-introduce the noise:
    #   - actor (trustee/owner) is already Tier Zero, or
    #   - an ACL-family finding targets an Exchange system object.
    if _HIDE_TIER_ZERO_ACTORS:
        def _is_noise(f: Finding) -> bool:
            if f.category not in _ACTOR_CATEGORIES:
                return False
            if _is_high_value(f.principal_sid) or _is_exchange_system_object(f.target_name):
                return True
            # An effective-via-membership finding (e.g. DCSync inherited through a
            # group) is noise when the GROUP it comes through is itself Tier Zero
            # — a Domain Admin "having" DCSync isn't an escalation. Members via a
            # non-Tier-Zero custom group (the high-signal case) are kept.
            if f.details.get("effective") and _is_high_value(f.details.get("via_group_sid", "")):
                return True
            return False

        kept = [f for f in result.findings if not _is_noise(f)]
        result.tier_zero_suppressed = len(result.findings) - len(kept)
        result.findings = kept

    # Then run meta checks (correlation operates on existing findings)
    for check in meta_checks:
        if progress_callback:
            progress_callback(check.name, completed, total_checks)
        result.findings.extend(check.func(result.findings))
        completed += 1

    # Opt-in scale controls (default off — behaviour is unchanged without them).
    # prune first (drop principals that lead nowhere), then aggregate the rest.
    if prune and reachable is not None:
        # Cheap post-filter: drop any meta/correlation finding whose principal
        # is off-path. Expanded members are reachable by construction.
        result.findings = prune_findings(result.findings, reachable)
    if aggregate:
        result.findings = aggregate_findings(result.findings, aggregate)

    if progress_callback:
        progress_callback("done", total_checks, total_checks)

    return result


def analyze_write_dacl(data: dict) -> AnalysisResult:
    """Legacy API: run full analysis (backward compatible).

    The original function only checked WriteDACL. The new version runs all
    checks. Callers that only want ACL findings can filter by category.
    """
    return analyze(data)

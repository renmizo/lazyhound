"""Offline query engine for LazyHound collection JSON files.

Provides a ``CollectionIndex`` that builds fast lookup indexes over collected
AD objects, plus query functions for common pentest lookups: object info,
group membership, SID resolution, ACL inspection, and attribute search.
"""

from __future__ import annotations

import fnmatch
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from .analyzer import (
    _build_group_graph,
    _get_uac,
    _resolve_name,
)

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------
_EPOCH_DIFF = 116444736000000000  # 100-ns intervals between 1601 and 1970

def _norm_dt(dt: datetime | None) -> datetime | None:
    """Make a datetime UTC-aware; treat the AD 1601 epoch as 'unset'."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return None if dt.year <= 1601 else dt


def _filetime_to_datetime(ft: int | str | datetime | None) -> datetime | None:
    """Convert an AD timestamp to a UTC datetime.

    Handles every form the value can reach us in: a raw Windows FILETIME
    (100-ns since 1601, as int or string), an ldap3-formatted ``datetime``
    object (ldap3 auto-converts pwdLastSet/lastLogonTimestamp), or that
    datetime's ISO string after a JSON save/load round-trip. Returns None for
    unset (0) / 'never' sentinels and anything unparseable.
    """
    if ft is None:
        return None
    # ldap3 already formats AD timestamp attributes to datetime objects.
    if isinstance(ft, datetime):
        return _norm_dt(ft)
    if isinstance(ft, str):
        s = ft.strip()
        if not s:
            return None
        # ISO-style datetime string (e.g. a JSON-serialized ldap3 datetime).
        if "-" in s and ":" in s:
            try:
                return _norm_dt(datetime.fromisoformat(s.replace("Z", "+00:00")))
            except ValueError:
                return None
    # Otherwise treat it as a FILETIME integer.
    try:
        ft = int(ft)
    except (ValueError, TypeError):
        return None
    if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:  # unset / 'never expires' sentinel
        return None
    try:
        ts = (ft - _EPOCH_DIFF) / 10_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def _fmt_datetime(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _days_ago(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    delta = datetime.now(tz=timezone.utc) - dt
    return max(0, delta.days)


def _parse_when_created(val: object) -> datetime | None:
    """Parse whenCreated from various formats ldap3 may return.

    ldap3 may return a ``datetime`` object, a generalized-time string
    like ``"20240117212000.0Z"``, or an ISO string from JSON round-trips.
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    s = str(val).strip()
    if not s:
        return None
    # Generalized time: "20240117212000.0Z"
    for fmt in ("%Y%m%d%H%M%S.%fZ", "%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # ISO format from JSON: "2024-01-17 21:20:00+00:00" or "2024-01-17T21:20:00Z"
    try:
        from datetime import datetime as _dt
        dt = _dt.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# UAC flag descriptions
# ---------------------------------------------------------------------------
_UAC_FLAGS = [
    (0x0002, "ACCOUNTDISABLE"),
    (0x0010, "LOCKOUT"),
    (0x0020, "PASSWD_NOTREQD"),
    (0x0040, "PASSWD_CANT_CHANGE"),
    (0x0080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x0200, "NORMAL_ACCOUNT"),
    (0x0800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x1000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x2000, "SERVER_TRUST_ACCOUNT"),
    (0x10000, "DONT_EXPIRE_PASSWORD"),
    (0x20000, "MNS_LOGON_ACCOUNT"),
    (0x40000, "SMARTCARD_REQUIRED"),
    (0x80000, "TRUSTED_FOR_DELEGATION"),
    (0x100000, "NOT_DELEGATED"),
    (0x200000, "USE_DES_KEY_ONLY"),
    (0x400000, "DONT_REQ_PREAUTH"),
    (0x800000, "PASSWORD_EXPIRED"),
    (0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    (0x4000000, "PARTIAL_SECRETS_ACCOUNT"),
]


def _uac_flags(uac: int) -> list[str]:
    return [name for val, name in _UAC_FLAGS if uac & val]


# ---------------------------------------------------------------------------
# Access right descriptions
# ---------------------------------------------------------------------------
_RIGHT_NAMES = {
    "GenericAll": "Full control",
    "GenericWrite": "Write all properties",
    "WriteDACL": "Modify permissions",
    "WriteOwner": "Take ownership",
    "ExtendedRight": "Extended right (e.g. force password change, DCSync)",
    "WriteProperty": "Write specific property",
    "Self": "Self-write (validated write)",
}


# ---------------------------------------------------------------------------
# Domain registry — distinct AD domains present in a (possibly forest) collection
# ---------------------------------------------------------------------------
@dataclass
class DomainInfo:
    domain_sid: str
    fqdn: str
    netbios: str
    object_count: int
    user_count: int

    @property
    def label(self) -> str:
        """Always-non-empty display label: FQDN, else NetBIOS, else the SID."""
        return self.fqdn or self.netbios or self.domain_sid


def _domain_sid_of(sid: str) -> str:
    """Domain SID (S-1-5-21-X-Y-Z) for an AD object SID, '' if domainless.
    Handles a trailing RID and BloodHound 'DOMAIN.FQDN-' prefixes."""
    if not sid:
        return ""
    i = sid.find("S-1-5-21-")
    if i < 0:
        return ""
    parts = sid[i:].split("-")
    if len(parts) == 7:          # already a domain SID (no RID)
        return "-".join(parts)
    if len(parts) >= 8:          # object SID -> strip the RID
        return "-".join(parts[:7])
    return ""


def _fqdn_from_dn(dn: str) -> str:
    labels = [p.strip()[3:] for p in (dn or "").split(",")
              if p.strip().upper().startswith("DC=")]
    return ".".join(labels).lower() if labels else ""


# ---------------------------------------------------------------------------
# CollectionIndex — the core data access layer
# ---------------------------------------------------------------------------
class CollectionIndex:
    """Fast-lookup index over a collection JSON."""

    def __init__(self, data: dict) -> None:
        self.meta: dict = data.get("meta", {})
        self.domain: str = self.meta.get("domain", "unknown")
        self.raw_sid_map: dict[str, str] = dict(data.get("sid_map", {}))
        self.objects: list[dict] = data.get("objects", [])
        self.sessions: list[dict] = data.get("sessions", []) or []
        self.local_group_members: list[dict] = data.get("local_group_members", []) or []

        # Azure/hybrid data (from ingest-azurehound)
        self.azure_objects: list[dict] = data.get("azure_objects", []) or []
        self.azure_edges: list[dict] = data.get("azure_edges", []) or []
        self.hybrid_edges: list[dict] = data.get("hybrid_edges", []) or []
        self.is_hybrid: bool = bool(self.azure_objects or self.hybrid_edges)

        # Build indexes
        self._by_sid: dict[str, dict] = {}
        self._by_name: dict[str, dict] = {}      # lowered sAMAccountName/name
        self._by_dn: dict[str, dict] = {}         # lowered DN
        self._by_class: dict[str, list[dict]] = defaultdict(list)
        self._domains_cache: list[DomainInfo] | None = None

        # Full sid_map including object names
        self.sid_map: dict[str, str] = dict(self.raw_sid_map)

        for obj in self.objects:
            sid = obj.get("object_sid", "")
            dn = obj.get("dn", "")
            name = obj.get("name", "")
            cls = obj.get("object_class", "")

            if sid:
                self._by_sid[sid] = obj
                if name and sid not in self.sid_map:
                    self.sid_map[sid] = name
            if name:
                self._by_name[name.lower()] = obj
            if dn:
                self._by_dn[dn.lower()] = obj
            if cls:
                self._by_class[cls].append(obj)

        # Per-object Azure tenant attribution (BloodHound-style tenantId).
        self._azure_tenant_of: dict[str, str] = {}
        # Index Azure objects (same indexes, different source list)
        for obj in self.azure_objects:
            sid = obj.get("object_sid", "")
            dn = obj.get("dn", "")
            name = obj.get("name", "")
            cls = obj.get("object_class", "")
            # Azure objects are commonly mirrored into BOTH `objects` and
            # `azure_objects`. If this one was already indexed via the objects
            # loop above, don't append it to _by_class again (that double-counts
            # every Azure class — e.g. aad_sp showing 2x in stats/objects_by_class).
            already = bool(sid) and sid in self._by_sid

            if sid:
                self._by_sid[sid] = obj
                if name and sid not in self.sid_map:
                    self.sid_map[sid] = name
                tid = (obj.get("properties", {}) or {}).get("tenantId", "") or "AZURE-TENANT"
                self._azure_tenant_of[sid] = tid
            if name:
                self._by_name[name.lower()] = obj
            if dn:
                self._by_dn[dn.lower()] = obj
            if cls and not already:
                self._by_class[cls].append(obj)

        # Hybrid sync linkage (AD SID <-> Entra id), BloodHound-canonical via the
        # Entra object's onPremisesSecurityIdentifier; hybrid_edges as fallback.
        self._sync_ad_to_entra: dict[str, str] = {}
        self._sync_entra_to_ad: dict[str, str] = {}
        for obj in self.azure_objects:
            props = obj.get("properties", {}) or {}
            onprem = props.get("_onPremSid", "")
            if onprem and props.get("_onPremSyncEnabled"):
                eid = obj.get("object_sid", "")
                if eid:
                    self._sync_entra_to_ad[eid] = onprem
                    self._sync_ad_to_entra[onprem] = eid
        for e in self.hybrid_edges:
            if e.get("edge_type") == "SyncedToEntraUser":
                ad, en = e.get("source_id", ""), e.get("target_id", "")
                if ad and en:
                    self._sync_ad_to_entra.setdefault(ad, en)
                    self._sync_entra_to_ad.setdefault(en, ad)

        # Lazy-built group graph
        self._member_of: dict[str, set[str]] | None = None
        self._sid_names: dict[str, str] | None = None
        self._dn_to_sid: dict[str, str] | None = None

    # -- Group graph (lazy) -------------------------------------------------
    def _ensure_group_graph(self) -> None:
        if self._member_of is None:
            self._member_of, self._sid_names, self._dn_to_sid = _build_group_graph(self.objects)
            # Entra group memberships arrive as AZMemberOf edges (member -> group).
            for e in self.azure_edges:
                if e.get("edge_type") == "AZMemberOf":
                    m, g = e.get("source_id", ""), e.get("target_id", "")
                    if m and g:
                        self._member_of.setdefault(m, set()).add(g)

    # -- Core lookups -------------------------------------------------------
    def domain_of(self, obj: dict) -> str:
        """Realm id for an object: its AD domain SID, its Entra tenant id (Azure
        objects), or '' if truly domainless (BUILTIN/well-known). Used for query
        scoping, so Azure objects scope to their tenant realm."""
        return self.realm_of_sid(obj.get("object_sid", ""))

    def realm_of_sid(self, sid: str) -> str:
        """Home realm id for a principal SID: its Azure tenant id (per-object
        tenantId) for an Entra object, else its AD domain SID, else ''."""
        if not sid:
            return ""
        if sid in self._azure_tenant_of:
            return self._azure_tenant_of[sid]
        return _domain_sid_of(sid)

    def realms_of_sid(self, sid: str) -> set[str]:
        """All realms a principal belongs to. Synced identities span their AD
        domain AND their Entra tenant. Well-known/BUILTIN -> empty set (shown
        in every scope)."""
        realms: set[str] = set()
        home = self.realm_of_sid(sid)
        if home:
            realms.add(home)
        if sid in self._sync_ad_to_entra:                 # synced AD user
            t = self.realm_of_sid(self._sync_ad_to_entra[sid])
            if t:
                realms.add(t)
        if sid in self._sync_entra_to_ad:                 # synced Entra user
            d = _domain_sid_of(self._sync_entra_to_ad[sid])
            if d:
                realms.add(d)
        return realms

    def realm_label_of_sid(self, sid: str) -> str:
        """Display label for a principal's HOME realm (Realm column): AD ->
        e.g. GLOBEX.CORP, Entra -> ENTRA; '' for well-known."""
        home = self.realm_of_sid(sid)
        if not home:
            return ""
        for d in self.domains():
            if d.domain_sid == home:
                if d.netbios.upper().startswith("ENTRA"):
                    return d.netbios                    # tenant -> ENTRA
                return (d.fqdn or d.netbios or home).upper()   # AD -> GLOBEX.CORP
        return home

    def domains(self) -> list[DomainInfo]:
        """Distinct AD domains present in the collection, by object_count desc."""
        if self._domains_cache is not None:
            return self._domains_cache
        agg: dict[str, dict] = {}
        for obj in self.objects:
            dsid = _domain_sid_of(obj.get("object_sid", ""))   # AD domains only
            if not dsid:
                continue
            d = agg.setdefault(dsid, {"count": 0, "users": 0, "fqdn": "",
                                      "netbios": "", "dn": ""})
            d["count"] += 1
            if obj.get("object_class") == "user":
                d["users"] += 1
            if obj.get("object_class") == "domain":
                d["fqdn"] = (obj.get("name", "") or "").lower() or d["fqdn"]
                d["netbios"] = (obj.get("properties", {}).get("flatName", "")
                                or d["netbios"])
            elif obj.get("object_class") == "trusteddomain":
                # A trust target not collected as its own 'domain' node: its
                # 'name' IS the domain FQDN. Fills the gap so forest peers and
                # SID-history/foreign refs resolve to a name instead of a raw
                # SID. Only fills when absent — an authoritative 'domain' node
                # (which sets fqdn unconditionally above) always wins.
                if not d["fqdn"]:
                    d["fqdn"] = (obj.get("name", "") or "").lower()
                if not d["netbios"]:
                    d["netbios"] = (obj.get("properties", {})
                                    .get("flatName", "") or d["netbios"])
            if not d["dn"] and obj.get("dn"):
                d["dn"] = obj["dn"]
        out: list[DomainInfo] = []
        for dsid, d in agg.items():
            # Always prefer a real FQDN. Some collections store the domain
            # object's 'name' as the short NetBIOS-style label ('mydomain'); the
            # member DNs still carry the full FQDN ('...,DC=mydomain,DC=local'),
            # so fall back to the DN-derived name whenever the node name has no
            # dot (isn't a real FQDN).
            node_fqdn = d["fqdn"]
            dn_fqdn = _fqdn_from_dn(d["dn"])
            if node_fqdn and "." in node_fqdn:
                fqdn = node_fqdn
            elif dn_fqdn:
                fqdn = dn_fqdn
            else:
                fqdn = node_fqdn
            netbios = d["netbios"] or (fqdn.split(".")[0].upper() if fqdn else "")
            out.append(DomainInfo(dsid, fqdn, netbios, d["count"], d["users"]))
        # Azure tenants are realms too (one per distinct tenantId). The tenant
        # FQDN is derived from the Entra users' UPN suffixes (the canonical
        # .onmicrosoft.com initial domain) so it parallels AD FQDNs + scopes.
        az_agg: dict[str, dict] = {}
        for obj in self.azure_objects:
            props = obj.get("properties", {}) or {}
            tid = props.get("tenantId", "") or "AZURE-TENANT"
            a = az_agg.setdefault(tid, {"count": 0, "users": 0, "upn_doms": {}})
            a["count"] += 1
            if "user" in (obj.get("object_class", "") or "").lower():
                a["users"] += 1
                name = (obj.get("name", "") or "").lower()
                if "@" in name and "#ext#" not in name:
                    dom = name.split("@", 1)[1]
                    if dom.endswith(".onmicrosoft.com"):
                        a["upn_doms"][dom] = a["upn_doms"].get(dom, 0) + 1
        az_stats = self.meta.get("azure_stats", {}) or {}
        tname = az_stats.get("tenant_name", "")
        # The tenant's real primary domain (from AZTenant.verifiedDomains), e.g.
        # mydomain.local — preferred over the display name / onmicrosoft suffix.
        tdomain = az_stats.get("tenant_domain", "")
        multi = len(az_agg) > 1
        for tid, a in az_agg.items():
            onmicro = max(a["upn_doms"], key=a["upn_doms"].get) if a["upn_doms"] else ""
            netbios = "ENTRA" if not multi else f"ENTRA:{(tname or tid)[:8]}"
            fqdn = ((tdomain if not multi else "") or onmicro
                    or (tname if (tname and not multi) else ""))
            out.append(DomainInfo(tid, fqdn, netbios, a["count"], a["users"]))
        out.sort(key=lambda di: -di.object_count)
        self._domains_cache = out
        return out

    def resolve_domain(self, token: str) -> "DomainInfo | None":
        """Resolve a domain/realm by FQDN, NetBIOS, SID/tenant-id, or the
        aliases 'entra'/'azure'/'aad' (case-insensitive)."""
        t = (token or "").strip().lower()
        if not t:
            return None
        if t in ("entra", "azure", "aad"):
            tenants = [d for d in self.domains()
                       if d.netbios.upper().startswith("ENTRA")]
            return tenants[0] if tenants else None
        for d in self.domains():
            if t in (d.domain_sid.lower(), d.fqdn.lower(), d.netbios.lower()):
                return d
        return None

    def scope_objects(self, objects: list[dict], domain_sid: str) -> list[dict]:
        """Keep objects in `domain_sid` plus all domainless objects (BUILTIN/
        well-known/Azure). Empty domain_sid -> no filtering."""
        if not domain_sid:
            return list(objects)
        out = []
        for o in objects:
            dsid = self.domain_of(o)
            if not dsid or dsid == domain_sid:
                out.append(o)
        return out

    def scope_rows(self, rows: list, domain_sid: str) -> list:
        """Filter result rows to a domain, reading whichever SID key a row uses
        (object_sid / sid / principal_sid, or row[0] for (obj, ...) tuples).
        Keeps domainless rows. Empty domain_sid -> no filtering."""
        if not domain_sid:
            return list(rows)
        out = []
        for r in rows:
            obj = r[0] if isinstance(r, (tuple, list)) and r else r
            sid = ""
            if isinstance(obj, dict):
                sid = (obj.get("object_sid") or obj.get("sid")
                       or obj.get("principal_sid") or "")
            dsid = _domain_sid_of(sid)
            if not dsid or dsid == domain_sid:
                out.append(r)
        return out

    # Class preference for ambiguous name matches: real principals beat
    # name-only collisions (a cert template / OU / GPO that merely shares a name).
    _CLASS_RANK = {"user": 0, "group": 1, "computer": 2}

    def find_all_by_name(self, name: str) -> list[dict]:
        """All objects whose name or sAMAccountName matches, across domains.
        Ranked so the most authoritative match comes first: an exact
        sAMAccountName match beats a name-only match, and principal classes
        (user/group/computer) beat name-only collisions like cert templates."""
        n = (name or "").lower()
        if not n:
            return []
        out = []
        for o in self.objects:
            sam = (o.get("properties", {}).get("sAMAccountName", "") or "").lower()
            nm = (o.get("name", "") or "").lower()
            if sam == n:
                tier = 0
            elif nm == n:
                tier = 1
            elif "@" in nm and nm.split("@", 1)[0] == n:
                tier = 2                       # UPN local-part (e.g. Entra users)
            else:
                continue
            cls = (o.get("object_class", "") or "").lower()
            # sort key: sAMAccountName, then exact name, then UPN local-part;
            # within each, principal classes first.
            out.append(((tier, self._CLASS_RANK.get(cls, 9)), o))
        out.sort(key=lambda t: t[0])
        return [o for _, o in out]

    def get_in_domain(self, identifier: str, domain_sid: str) -> dict | None:
        """Resolve within a domain. Exact SID/DN wins (ignores domain); else the
        name match in `domain_sid`. None if the name exists only elsewhere."""
        obj = self._by_sid.get(identifier) or self._by_dn.get(identifier.lower())
        if obj:
            return obj
        matches = self.find_all_by_name(identifier)
        if not matches:
            return None
        if not domain_sid:
            return matches[0]
        for o in matches:
            if self.domain_of(o) == domain_sid:
                return o
        return None

    def get(self, identifier: str) -> dict | None:
        """Look up an object by name, SID, or DN (case-insensitive)."""
        # Try SID/ID first (exact) — covers AD SIDs and Azure object IDs
        obj = self._by_sid.get(identifier)
        if obj:
            return obj
        # Try name (lowered)
        obj = self._by_name.get(identifier.lower())
        if obj:
            return obj
        # Try DN (lowered)
        obj = self._by_dn.get(identifier.lower())
        if obj:
            return obj
        # Try SID map reverse (name -> find SID -> find obj)
        for sid, name in self.sid_map.items():
            if name.lower() == identifier.lower():
                obj = self._by_sid.get(sid)
                if obj:
                    return obj
        return None

    def resolve(self, identifier: str) -> tuple[str, str]:
        """Resolve an identifier to (SID, name). Returns best-effort."""
        obj = self.get(identifier)
        if obj:
            return obj.get("object_sid", ""), obj.get("name", "")
        # Check sid_map
        if identifier.upper().startswith("S-"):
            name = _resolve_name(identifier, self.sid_map, self.domain)
            return identifier, name
        # Reverse lookup in sid_map
        for sid, name in self.sid_map.items():
            if name.lower() == identifier.lower():
                return sid, name
        return "", identifier

    def objects_by_class(self, cls: str) -> list[dict]:
        return self._by_class.get(cls, [])

    # -- Group membership ---------------------------------------------------
    # AD default primaryGroupID per object class
    _DEFAULT_PRIMARY_GROUP: dict[str, int] = {"user": 513, "computer": 515}

    def _primary_group_members(self, group_sid: str) -> list[dict]:
        """Return objects whose primaryGroupID matches this group's RID."""
        parts = group_sid.rsplit("-", 1)
        if len(parts) != 2:
            return []
        try:
            group_rid = int(parts[1])
        except ValueError:
            return []
        result: list[dict] = []
        for obj in self.objects:
            pgid = obj.get("properties", {}).get("primaryGroupID")
            if pgid is not None:
                try:
                    if int(pgid) == group_rid:
                        result.append(obj)
                except (ValueError, TypeError):
                    continue
            else:
                # Fall back to AD default for the object class
                cls = obj.get("object_class", "")
                default_rid = self._DEFAULT_PRIMARY_GROUP.get(cls)
                if default_rid == group_rid:
                    result.append(obj)
        return result

    def members(self, group_id: str, recursive: bool = True) -> list[dict]:
        """Return members of a group. If recursive, include nested members."""
        obj = self.get(group_id)
        if not obj or obj.get("object_class") not in ("group", "aad_group"):
            return []

        group_sid = obj.get("object_sid", "")

        raw_members = obj.get("properties", {}).get("member", [])
        if isinstance(raw_members, str):
            raw_members = [raw_members]

        direct: list[dict] = []
        seen_sids: set[str] = set()
        for mref in raw_members:
            # `member` entries are DNs from native LDAP collection but SIDs from
            # a BloodHound import — resolve either form.
            mobj = self._by_dn.get(str(mref).lower()) or self._by_sid.get(mref)
            if mobj:
                msid = mobj.get("object_sid", "")
                if msid and msid in seen_sids:
                    continue
                if msid:
                    seen_sids.add(msid)
                direct.append(mobj)

        # Include objects whose primaryGroupID matches this group's RID
        for mobj in self._primary_group_members(group_sid):
            msid = mobj.get("object_sid", "")
            if msid and msid not in seen_sids:
                seen_sids.add(msid)
                direct.append(mobj)

        # Entra members: AZMemberOf edges pointing at this group (member -> group)
        if obj.get("object_class") == "aad_group":
            for e in self.azure_edges:
                if e.get("edge_type") == "AZMemberOf" and e.get("target_id") == group_sid:
                    mobj = self._by_sid.get(e.get("source_id", ""))
                    if mobj:
                        msid = mobj.get("object_sid", "")
                        if msid and msid not in seen_sids:
                            seen_sids.add(msid)
                            direct.append(mobj)

        if not recursive:
            return direct

        # BFS for nested members
        seen_sids: set[str] = set()
        result: list[dict] = []
        queue = list(direct)
        while queue:
            m = queue.pop(0)
            msid = m.get("object_sid", "")
            if msid and msid in seen_sids:
                continue
            if msid:
                seen_sids.add(msid)
            result.append(m)
            # If this member is itself a group, expand it
            if m.get("object_class") == "group":
                nested = m.get("properties", {}).get("member", [])
                if isinstance(nested, str):
                    nested = [nested]
                for nref in nested:
                    nobj = self._by_dn.get(str(nref).lower()) or self._by_sid.get(nref)
                    if nobj and nobj.get("object_sid", "") not in seen_sids:
                        queue.append(nobj)

        return result

    def memberof(self, principal_id: str, recursive: bool = True) -> list[dict]:
        """Return groups a principal belongs to."""
        self._ensure_group_graph()
        assert self._member_of is not None

        obj = self.get(principal_id)
        if not obj:
            return []
        sid = obj.get("object_sid", "")
        if not sid:
            return []

        if not recursive:
            group_sids = self._member_of.get(sid, set())
            return [self._by_sid[gs] for gs in group_sids if gs in self._by_sid]

        # BFS transitive closure
        visited: set[str] = set()
        queue = list(self._member_of.get(sid, set()))
        result: list[dict] = []
        while queue:
            gsid = queue.pop(0)
            if gsid in visited:
                continue
            visited.add(gsid)
            gobj = self._by_sid.get(gsid)
            if gobj:
                result.append(gobj)
            # This group may itself be a member of other groups
            for parent in self._member_of.get(gsid, set()):
                if parent not in visited:
                    queue.append(parent)

        return result

    # -- ACL queries --------------------------------------------------------
    _AZ_CONTROL = {"AZOwns", "AZOwner", "AZAddMembers", "AZAddOwner", "AZManageRole",
                   "AZResetPassword", "AZAddSecret", "AZGrantRole", "AZAppRoleAssignment"}

    def acl(self, target_id: str) -> list[dict]:
        """Access-control over an object. AD objects → DACL ACEs; Entra/Azure
        objects → inbound control edges (AZOwns/AZAddMembers/…) as ACE-like rows."""
        obj = self.get(target_id)
        if not obj:
            return []
        if str(obj.get("object_class", "")).startswith(("aad_", "azure_")):
            sid = obj.get("object_sid", "")
            out = []
            for e in self.azure_edges:
                et = e.get("edge_type", "")
                if e.get("target_id") == sid and et.split(":")[0] in self._AZ_CONTROL:
                    src = e.get("source_id", "")
                    out.append({
                        "ace_type": "Entra",
                        "trustee_sid": src,
                        "trustee_name": self.sid_map.get(src, "") or src,
                        "rights": [et],
                        "inherited": False,
                    })
            return out
        aces = obj.get("dacl", [])
        result = []
        for ace in aces:
            entry = dict(ace)
            trustee_sid = ace.get("trustee_sid", "")
            entry["trustee_name"] = _resolve_name(trustee_sid, self.sid_map, self.domain)
            result.append(entry)
        return result

    def who_can(self, right: str, target_id: str) -> list[dict]:
        """Find principals that have a specific right on a target.

        ``right`` can be: GenericAll, WriteDACL, WriteOwner, GenericWrite,
        ExtendedRight, WriteProperty, or a comma-separated combo.
        """
        obj = self.get(target_id)
        if not obj:
            return []

        wanted = {r.strip().lower() for r in right.split(",")}
        results = []
        for ace in obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            ace_rights = {r.lower() for r in ace.get("rights", [])}
            if wanted & ace_rights:
                trustee_sid = ace.get("trustee_sid", "")
                results.append({
                    "trustee_sid": trustee_sid,
                    "trustee_name": _resolve_name(trustee_sid, self.sid_map, self.domain),
                    "rights": ace.get("rights", []),
                    "inherited": ace.get("inherited", False),
                    "object_type": ace.get("object_type"),
                })
        return results

    # -- Search -------------------------------------------------------------
    def search(self, attr: str, pattern: str, object_class: str | None = None) -> list[dict]:
        """Find objects where a property matches a glob pattern.

        Searches within ``properties.<attr>`` using fnmatch-style patterns.
        Also searches top-level fields (name, dn, object_sid).
        """
        results = []
        pat = pattern.lower()

        objs = self.objects + self.azure_objects
        if object_class:
            objs = self._by_class.get(object_class, [])

        for obj in objs:
            # Check top-level fields
            value = obj.get(attr)
            if value is None:
                value = obj.get("properties", {}).get(attr)
            if value is None:
                continue

            if isinstance(value, list):
                for v in value:
                    if fnmatch.fnmatch(str(v).lower(), pat):
                        results.append(obj)
                        break
            else:
                if fnmatch.fnmatch(str(value).lower(), pat):
                    results.append(obj)

        return results

    # -- OU tree ------------------------------------------------------------
    def ou_tree(self) -> list[dict]:
        """Return OUs/containers as a flat list sorted by DN depth.

        Includes real OU objects from the collection as well as container DNs
        (e.g. ``CN=Users``, ``CN=Computers``) discovered from object DNs.
        Each entry is augmented with ``_counts`` = {users, groups, computers}.
        """
        # Start with collected OU objects
        by_dn: dict[str, dict] = {}
        for ou in self._by_class.get("ou", []):
            dn = ou.get("dn", "")
            if dn:
                by_dn[dn.lower()] = dict(ou)

        # Discover containers from object DNs (CN=Users, CN=Computers, etc.)
        for obj in self.objects:
            dn = obj.get("dn", "")
            if not dn:
                continue
            parts = dn.split(",", 1)
            if len(parts) != 2:
                continue
            parent_dn = parts[1]
            pkey = parent_dn.lower()
            if pkey not in by_dn and parent_dn.upper().startswith("CN="):
                # Synthetic container entry
                cname = parent_dn.split(",", 1)[0].split("=", 1)[1] if "=" in parent_dn else parent_dn
                by_dn[pkey] = {
                    "dn": parent_dn,
                    "name": cname,
                    "object_sid": "",
                    "object_class": "container",
                    "properties": {},
                }

        # Count direct children per parent DN
        counts: dict[str, dict[str, int]] = {}
        for obj in self.objects:
            dn = obj.get("dn", "")
            if not dn:
                continue
            parts = dn.split(",", 1)
            if len(parts) != 2:
                continue
            parent_key = parts[1].lower()
            cls = obj.get("object_class", "")
            if parent_key not in counts:
                counts[parent_key] = {"user": 0, "group": 0, "computer": 0}
            if cls in counts[parent_key]:
                counts[parent_key][cls] += 1

        # Attach counts to each OU/container
        for dn_lower, entry in by_dn.items():
            entry["_counts"] = counts.get(dn_lower, {"user": 0, "group": 0, "computer": 0})

        result = list(by_dn.values())
        return sorted(result, key=lambda o: o.get("dn", "").count(","))

    def _resolve_ou_dn(self, identifier: str) -> str | None:
        """Resolve an OU/container identifier to a DN.

        Accepts a full DN (returned as-is) or an OU name which is looked up
        from the ``ou_tree()`` results.  Returns ``None`` when unresolved.
        """
        # If it looks like a DN (contains '=' and ','), use directly
        if "=" in identifier and "," in identifier:
            return identifier
        # Otherwise try matching by name against OU objects
        low = identifier.lower()
        matches: list[dict] = []
        for ou in self._by_class.get("ou", []):
            if ou.get("name", "").lower() == low:
                matches.append(ou)
        if len(matches) == 1:
            return matches[0].get("dn", identifier)
        # Also check containers discovered in object DNs
        for obj in self.objects:
            dn = obj.get("dn", "")
            parts = dn.split(",", 1)
            if len(parts) == 2:
                parent_dn = parts[1]
                if parent_dn.upper().startswith("CN="):
                    cname = parent_dn.split(",", 1)[0].split("=", 1)[1] if "=" in parent_dn else parent_dn
                    if cname.lower() == low and parent_dn not in [m.get("dn") for m in matches]:
                        matches.append({"dn": parent_dn})
        if len(matches) == 1:
            return matches[0].get("dn", identifier)
        # Ambiguous or not found — return None
        return None

    def ou_members(self, ou_dn: str) -> list[dict]:
        """Return objects whose DN is directly inside an OU/container.

        ``ou_dn`` can be a full DN or an OU name (resolved via
        ``_resolve_ou_dn``).
        """
        resolved = self._resolve_ou_dn(ou_dn)
        if resolved is None:
            # Fall back to treating as literal DN
            resolved = ou_dn
        ou_dn_lower = resolved.lower()
        results = []
        for obj in self.objects:
            dn = obj.get("dn", "")
            if not dn:
                continue
            # Direct child: the parent portion after the first comma matches the OU DN
            parts = dn.split(",", 1)
            if len(parts) == 2 and parts[1].lower() == ou_dn_lower:
                results.append(obj)
        return results

    # -- Convenience queries ------------------------------------------------
    def stale_passwords(
        self, days: int = 365, include_disabled: bool = False,
    ) -> tuple[list[tuple[dict, datetime | None, int | None]], int]:
        """Return users/computers whose pwdLastSet is older than ``days``.

        Returns ``(results, disabled_skipped)`` where *disabled_skipped* is
        the number of disabled accounts that were excluded from results.
        """
        results = []
        disabled_skipped = 0
        for obj in self.objects:
            if obj.get("object_class") not in ("user", "computer"):
                continue
            uac = _get_uac(obj)
            if not include_disabled and (uac & 0x0002):
                disabled_skipped += 1
                continue
            ft = obj.get("properties", {}).get("pwdLastSet")
            dt = _filetime_to_datetime(ft)
            age = _days_ago(dt)
            if age is not None and age >= days:
                results.append((obj, dt, age))
            elif dt is None and ft is not None:
                # pwdLastSet = 0 means "must change at next logon"
                results.append((obj, None, None))
        results.sort(key=lambda x: x[2] if x[2] is not None else 999999, reverse=True)
        return results, disabled_skipped

    def oldest_passwords(
        self, top: int = 25, include_disabled: bool = False,
    ) -> tuple[list[dict], int]:
        """Return the top N accounts sorted by oldest pwdLastSet.

        Each result dict contains the object plus computed password metadata.
        Accounts with PASSWD_NOTREQD or pwdLastSet=0 (never set) sort first.

        Returns ``(rows, disabled_skipped)`` where *disabled_skipped* is
        the number of disabled accounts that were excluded from results.
        """
        rows: list[dict] = []
        disabled_skipped = 0
        for obj in self.objects:
            if obj.get("object_class") not in ("user", "computer"):
                continue
            uac = _get_uac(obj)
            if not include_disabled and (uac & 0x0002):
                disabled_skipped += 1
                continue

            props = obj.get("properties", {})
            ft = props.get("pwdLastSet")
            dt = _filetime_to_datetime(ft)
            age = _days_ago(dt)
            passwd_notreqd = bool(uac & 0x0020)
            never_set = (ft is not None and (dt is None or ft == 0 or str(ft) == "0"))

            # Sort key: never-set and PASSWD_NOTREQD go to top (infinite age),
            # then by actual age descending.
            if never_set or passwd_notreqd:
                sort_key = 999_999_999
            elif age is not None:
                sort_key = age
            else:
                sort_key = -1  # unknown, sort last

            rows.append({
                "object": obj,
                "name": obj.get("name", ""),
                "sid": obj.get("object_sid", ""),
                "object_class": obj.get("object_class", ""),
                "pwd_last_set": _fmt_datetime(dt),
                "pwd_last_set_raw": ft,
                "age_days": age,
                "passwd_notreqd": passwd_notreqd,
                "never_set": never_set,
                "enabled": not bool(uac & 0x0002),
                "_sort_key": sort_key,
            })

        rows.sort(key=lambda r: r["_sort_key"], reverse=True)
        return rows[:top], disabled_skipped

    def spns(self) -> list[tuple[dict, list[str]]]:
        """Return all objects that have SPNs set."""
        results = []
        for obj in self.objects:
            raw = obj.get("properties", {}).get("servicePrincipalName", [])
            if isinstance(raw, str):
                raw = [raw]
            if raw:
                results.append((obj, raw))
        return results

    def cas(self) -> list[dict]:
        """Return all CA enrollment service objects with parsed details."""
        results = []
        for obj in self._by_class.get("pki", []):
            props = obj.get("properties", {})
            templates = props.get("certificateTemplates", [])
            if isinstance(templates, str):
                templates = [templates]
            flags = 0
            try:
                flags = int(props.get("flags", 0) or 0)
            except (ValueError, TypeError):
                pass
            results.append({
                "name": obj.get("name", ""),
                "dns_hostname": props.get("dNSHostName", ""),
                "templates_published": templates,
                "template_count": len(templates),
                "flags": flags,
                "enforce_encryption": bool(flags & 0x200),
                "dn": obj.get("dn", ""),
            })
        return results

    def certificate_templates(self) -> list[dict]:
        """Return all certificate templates with vulnerability assessment."""
        from lazyhound.finder.scan.checks.adcs import (
            CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            CT_FLAG_NO_SECURITY_EXTENSION,
            CLIENT_AUTH,
            ANY_PURPOSE,
            SMART_CARD_LOGON,
            CERTIFICATE_REQUEST_AGENT,
            DANGEROUS_EKUS,
        )

        eku_map = {
            CLIENT_AUTH: "Client Auth",
            "1.3.6.1.5.5.7.3.1": "Server Auth",
            SMART_CARD_LOGON: "Smart Card Logon",
            ANY_PURPOSE: "Any Purpose",
            CERTIFICATE_REQUEST_AGENT: "Certificate Request Agent",
            "1.3.6.1.5.5.7.3.4": "Email Protection",
            "1.3.6.1.5.5.7.3.3": "Code Signing",
        }

        results = []
        for obj in self._by_class.get("certtemplate", []):
            props = obj.get("properties", {})
            name = obj.get("name", "")

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

            schema_version = str(props.get("msPKI-Template-Schema-Version", ""))

            ekus = props.get("pKIExtendedKeyUsage", [])
            if isinstance(ekus, str):
                ekus = [ekus]

            supplies_san = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            no_security_ext = bool(enrollment_flag & CT_FLAG_NO_SECURITY_EXTENSION)
            manager_approval = bool(enrollment_flag & 0x2)
            has_dangerous_eku = not ekus or any(e in DANGEROUS_EKUS for e in ekus)
            is_request_agent = CERTIFICATE_REQUEST_AGENT in ekus
            any_purpose = ANY_PURPOSE in ekus or not ekus

            # Determine ESC vulnerabilities
            esc_ids: list[str] = []
            if supplies_san and has_dangerous_eku and ra_sig == 0:
                if manager_approval:
                    esc_ids.append("ESC1*")  # mitigated by manager approval
                else:
                    esc_ids.append("ESC1")
            if any_purpose and ra_sig == 0 and not supplies_san and not is_request_agent:
                esc_ids.append("ESC2")
            if is_request_agent:
                esc_ids.append("ESC3")
            if no_security_ext:
                esc_ids.append("ESC9")
            if schema_version == "1":
                esc_ids.append("ESC15")

            # Map EKU OIDs to friendly names
            eku_names = []
            for eku in ekus:
                eku_names.append(eku_map.get(eku, eku))
            if not ekus:
                eku_names.append("(No EKU — all purposes)")

            results.append({
                "name": name,
                "schema_version": schema_version,
                "ekus": eku_names,
                "supplies_san": supplies_san,
                "manager_approval": manager_approval,
                "ra_signature": ra_sig,
                "vulnerable": bool(esc_ids),
                "esc_ids": esc_ids,
                "dn": obj.get("dn", ""),
            })
        return results

    def trusts(self) -> list[dict]:
        """Return all trust objects."""
        return self._by_class.get("trusteddomain", [])

    def computers(self, os_pattern: str | None = None) -> list[dict]:
        """Return computers, optionally filtered by OS glob pattern."""
        comps = self._by_class.get("computer", [])
        if os_pattern:
            pat = os_pattern.lower()
            comps = [
                c for c in comps
                if fnmatch.fnmatch(
                    str(c.get("properties", {}).get("operatingSystem", "")).lower(),
                    pat,
                )
            ]
        return comps

    def by_created(
        self,
        object_class: str,
        top: int = 25,
        newest_first: bool = True,
        include_disabled: bool = False,
    ) -> tuple[list[dict], int]:
        """Return objects sorted by whenCreated date.

        Args:
            object_class: "user", "computer", or any collected class.
            top: Number of results to return.
            newest_first: True for newest first, False for oldest first.
            include_disabled: Include disabled accounts (user/computer only).

        Returns ``(rows, disabled_skipped)`` where *disabled_skipped* is
        the number of disabled accounts that were excluded from results.
        """
        rows: list[dict] = []
        disabled_skipped = 0
        objs = self._by_class.get(object_class, [])

        for obj in objs:
            if object_class in ("user", "computer") and not include_disabled:
                uac = _get_uac(obj)
                if uac & 0x0002:
                    disabled_skipped += 1
                    continue

            props = obj.get("properties", {})
            wc = props.get("whenCreated")
            dt = _parse_when_created(wc)

            rows.append({
                "object": obj,
                "name": obj.get("name", ""),
                "sid": obj.get("object_sid", ""),
                "dn": obj.get("dn", ""),
                "object_class": object_class,
                "when_created": _fmt_datetime(dt),
                "when_created_dt": dt,
                "days_ago": _days_ago(dt),
            })

        # Sort: objects without whenCreated go to the end
        sentinel = datetime.min.replace(tzinfo=timezone.utc)
        rows.sort(
            key=lambda r: r["when_created_dt"] or sentinel,
            reverse=newest_first,
        )
        return rows[:top], disabled_skipped

    def stats(self) -> dict:
        """Return summary statistics about the collection."""
        class_counts = {cls: len(objs) for cls, objs in self._by_class.items()}
        disabled = sum(
            1 for o in self.objects
            if o.get("object_class") in ("user", "computer") and _get_uac(o) & 0x0002
        )
        result = {
            "domain": self.domain,
            "dc": self.meta.get("dc", "unknown"),
            "collected_at": self.meta.get("collected_at", "unknown"),
            "collection_method": self.meta.get("collection_method", "unknown"),
            "total_objects": len(self.objects),
            "by_class": class_counts,
            "disabled_accounts": disabled,
            "sid_map_entries": len(self.raw_sid_map),
            "sessions": len(self.sessions),
            "local_group_members": len(self.local_group_members),
        }
        if self.is_hybrid:
            result["azure_objects"] = len(self.azure_objects)
            result["azure_edges"] = len(self.azure_edges)
            result["hybrid_edges"] = len(self.hybrid_edges)
            result["synced_users"] = sum(
                1 for e in self.hybrid_edges if e.get("edge_type") == "SyncedToEntraUser"
            )
            azure_stats = self.meta.get("azure_stats", {})
            if azure_stats:
                result["tenant_name"] = azure_stats.get("tenant_name", "")
                result["tenant_id"] = azure_stats.get("tenant_id", "")
        return result

    # -- Delegation map (Feature 1) ----------------------------------------
    def delegation_map(self) -> list[dict]:
        """Return all delegation relationships (unconstrained, constrained, RBCD).

        Each result dict contains: principal (name/sid/class), delegation_type,
        targets (service list or RBCD principals), and trust boundaries.
        """
        results: list[dict] = []

        for obj in self.objects:
            if obj.get("object_class") not in ("user", "computer"):
                continue
            uac = _get_uac(obj)
            props = obj.get("properties", {})
            name = obj.get("name", "")
            sid = obj.get("object_sid", "")
            cls = obj.get("object_class", "")

            # Unconstrained delegation (TRUSTED_FOR_DELEGATION)
            if uac & 0x80000:
                # Skip DCs — they have unconstrained by default
                if not (uac & 0x2000):  # SERVER_TRUST_ACCOUNT
                    results.append({
                        "principal": name,
                        "principal_sid": sid,
                        "principal_class": cls,
                        "delegation_type": "Unconstrained",
                        "targets": ["ANY SERVICE"],
                        "protocol_transition": False,
                        "enabled": not bool(uac & 0x0002),
                    })

            # Constrained delegation (msDS-AllowedToDelegateTo)
            targets = props.get("msDS-AllowedToDelegateTo", [])
            if isinstance(targets, str):
                targets = [targets]
            if targets:
                # TRUSTED_TO_AUTH_FOR_DELEGATION = protocol transition
                proto_transition = bool(uac & 0x1000000)
                results.append({
                    "principal": name,
                    "principal_sid": sid,
                    "principal_class": cls,
                    "delegation_type": "Constrained",
                    "targets": targets,
                    "protocol_transition": proto_transition,
                    "enabled": not bool(uac & 0x0002),
                })

            # RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
            rbcd = props.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
            if rbcd is not None and rbcd != "":
                results.append({
                    "principal": name,
                    "principal_sid": sid,
                    "principal_class": cls,
                    "delegation_type": "RBCD",
                    "targets": ["(configured via msDS-AllowedToActOnBehalfOfOtherIdentity)"],
                    "protocol_transition": False,
                    "enabled": not bool(uac & 0x0002),
                })

        return results

    # -- Attack surface (Feature 2) ----------------------------------------
    def attack_surface(
        self,
        principal_id: str,
        include_edges: set[str] | None = None,
        exclude_edges: set[str] | None = None,
    ) -> dict | None:
        """Given a compromised principal, show everything it can reach.

        Args:
            include_edges: If set, only consider these edge types.
            exclude_edges: If set, skip these edge types.

        Returns a dict with: groups, acl_rights, delegation_paths, sessions,
        local_admin, kerberoastable status, laps/gmsa readable targets.
        """
        obj = self.get(principal_id)
        if not obj:
            return None

        sid = obj.get("object_sid", "")
        name = obj.get("name", "")
        cls = obj.get("object_class", "")
        uac = _get_uac(obj)
        props = obj.get("properties", {})

        # Build case-insensitive edge filter helper
        inc_lower = {e.lower() for e in include_edges} if include_edges else None
        exc_lower = {e.lower() for e in exclude_edges} if exclude_edges else None

        def _edge_ok(edge_type: str) -> bool:
            el = edge_type.lower()
            if inc_lower is not None and el not in inc_lower:
                return False
            if exc_lower is not None and el in exc_lower:
                return False
            return True

        # Group memberships (recursive)
        groups = self.memberof(principal_id, recursive=True)
        group_names = [g.get("name", "") for g in groups] if _edge_ok("MemberOf") else []
        group_sids = {g.get("object_sid", "") for g in groups} - {""}
        all_sids = ({sid} if sid else set()) | group_sids  # principal + all groups (always needed for ACL lookups)

        # ACL rights on other objects
        acl_rights: list[dict] = []
        if any(_edge_ok(e) for e in ("GenericAll", "WriteDACL", "WriteOwner",
                                      "GenericWrite", "WriteProperty")):
            for target_obj in self.objects:
                for ace in target_obj.get("dacl", []):
                    if "ALLOWED" not in ace.get("ace_type", ""):
                        continue
                    trustee = ace.get("trustee_sid", "")
                    if trustee in all_sids:
                        rights = ace.get("rights", [])
                        dangerous = {"GenericAll", "WriteDACL", "WriteOwner",
                                     "GenericWrite", "ExtendedRight", "WriteProperty"}
                        matching = set(rights) & dangerous
                        # Filter rights by edge filter
                        if inc_lower is not None:
                            matching = {r for r in matching if r.lower() in inc_lower}
                        if exc_lower is not None:
                            matching = {r for r in matching if r.lower() not in exc_lower}
                        if matching:
                            acl_rights.append({
                                "target": target_obj.get("name", ""),
                                "target_class": target_obj.get("object_class", ""),
                                "rights": [r for r in rights if r in matching],
                                "via": _resolve_name(trustee, self.sid_map, self.domain),
                            })

        # Delegation paths
        delegation_targets: list = []
        if _edge_ok("AllowedToDelegate"):
            delegation_targets = props.get("msDS-AllowedToDelegateTo", [])
            if isinstance(delegation_targets, str):
                delegation_targets = [delegation_targets]

        # Sessions (where this principal is logged in)
        principal_sessions: list = []
        if _edge_ok("HasSession"):
            principal_sessions = [
                s for s in self.sessions
                if s.get("username", "").lower() == name.lower()
            ]

        # Local admin (from local_group_members)
        local_admin_on: list = []
        if _edge_ok("AdminTo"):
            local_admin_on = [
                m for m in self.local_group_members
                if m.get("member_sid") in all_sids and m.get("group_rid") == 544
            ]

        # Kerberoastable status
        spns = props.get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        kerberoastable = bool(spns) and cls == "user"

        # AS-REP roastable
        asrep_roastable = bool(uac & 0x400000)  # DONT_REQ_PREAUTH

        return {
            "name": name,
            "sid": sid,
            "object_class": cls,
            "enabled": not bool(uac & 0x0002),
            "groups": group_names,
            "group_count": len(groups),
            "acl_rights": acl_rights,
            "acl_rights_count": len(acl_rights),
            "delegation_targets": delegation_targets,
            "sessions": [
                {"computer": s.get("target_host", ""), "user": s.get("username", "")}
                for s in principal_sessions
            ],
            "local_admin_on": [
                m.get("target_host", "") for m in local_admin_on
            ],
            "kerberoastable": kerberoastable,
            "asrep_roastable": asrep_roastable,
            "spns": spns,
            "admin_count": props.get("adminCount", 0),
        }

    # -- Kerberoastable (Feature 5) ----------------------------------------
    def kerberoastable(self) -> list[dict]:
        """Return user accounts with SPNs set (kerberoastable).

        Excludes machine accounts. Includes encryption type hints and
        password age for prioritization.
        """
        results: list[dict] = []
        for obj in self.objects:
            if obj.get("object_class") != "user":
                continue
            props = obj.get("properties", {})
            spns = props.get("servicePrincipalName", [])
            if isinstance(spns, str):
                spns = [spns]
            if not spns:
                continue

            uac = _get_uac(obj)
            ft = props.get("pwdLastSet")
            dt = _filetime_to_datetime(ft)
            age = _days_ago(dt)

            # Encryption hints from UAC
            des_only = bool(uac & 0x200000)  # USE_DES_KEY_ONLY

            results.append({
                "name": obj.get("name", ""),
                "sid": obj.get("object_sid", ""),
                "dn": obj.get("dn", ""),
                "enabled": not bool(uac & 0x0002),
                "spns": spns,
                "spn_count": len(spns),
                "pwd_last_set": _fmt_datetime(dt),
                "pwd_age_days": age,
                "des_only": des_only,
                "admin_count": int(props.get("adminCount", 0) or 0),
                "description": props.get("description", ""),
            })

        # Sort: enabled first, then by admin_count desc, then by pwd age desc
        results.sort(key=lambda r: (
            not r["enabled"],
            -r["admin_count"],
            -(r["pwd_age_days"] or 0),
        ))
        return results

    # -- Sessions query ----------------------------------------------------

    def query_sessions(
        self, *, host: str | None = None, user: str | None = None,
    ) -> list[dict]:
        """Return session records, optionally filtered by host or user.

        Each result: ``{"username", "source_host", "target_host"}``.
        """
        results = list(self.sessions)
        if host:
            h = host.lower().rstrip("$")
            results = [
                s for s in results
                if h in s.get("target_host", "").lower()
            ]
        if user:
            u = user.lower()
            results = [
                s for s in results
                if u in s.get("username", "").lower()
            ]
        return results

    # -- Local admin / local group query -----------------------------------

    def query_local_admins(
        self,
        *,
        host: str | None = None,
        user: str | None = None,
        edge_type: str | None = None,
    ) -> list[dict]:
        """Return local group membership records with optional filters.

        Each result: ``{"member_sid", "member_name", "group_rid",
        "group_name", "target_host", "edge_type"}``.
        """
        results = list(self.local_group_members)
        if host:
            h = host.lower().rstrip("$")
            results = [
                m for m in results
                if h in m.get("target_host", "").lower()
            ]
        if user:
            u = user.lower()
            results = [
                m for m in results
                if u in m.get("member_name", "").lower()
                or u in m.get("member_sid", "").lower()
            ]
        if edge_type:
            e = edge_type.lower()
            results = [
                m for m in results
                if m.get("edge_type", "").lower() == e
            ]
        return results


# ---------------------------------------------------------------------------
# Object info formatter (returns structured dict for rendering)
# ---------------------------------------------------------------------------
def _enc_types_str(val: int | str | None) -> list[str]:
    """Decode msDS-SupportedEncryptionTypes bitmask to human-readable names."""
    if val is None:
        return []
    try:
        val = int(val)
    except (ValueError, TypeError):
        return []
    names = []
    if val & 0x01:
        names.append("DES-CBC-CRC")
    if val & 0x02:
        names.append("DES-CBC-MD5")
    if val & 0x04:
        names.append("RC4-HMAC")
    if val & 0x08:
        names.append("AES128-CTS")
    if val & 0x10:
        names.append("AES256-CTS")
    return names


def _account_expires_str(val: int | str | None) -> str:
    """Convert accountExpires FILETIME to a human-readable string."""
    if val is None:
        return ""
    try:
        val = int(val)
    except (ValueError, TypeError):
        return ""
    # 0 and 0x7FFFFFFFFFFFFFFF both mean "never expires"
    if val == 0 or val >= 0x7FFFFFFFFFFFFFFF:
        return "Never"
    dt = _filetime_to_datetime(val)
    return _fmt_datetime(dt) if dt else ""


def _dn_to_short_name(dn: str) -> str:
    """Extract CN= value from a DN for display purposes."""
    if not dn:
        return ""
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


# AD default primaryGroupID per object class (used when the attribute is absent
# on older collections that didn't gather it).
_DEFAULT_PRIMARY_GROUP_RID: dict[str, int] = {"user": 513, "computer": 515}


def _primary_group_member_count(idx: "CollectionIndex", group_sid: str) -> int:
    """Count objects that belong to a group via primaryGroupID.

    Primary-group membership (e.g. every user in Domain Users, every computer in
    Domain Computers) is NOT stored in the group's ``member`` attribute — it's
    implied by each object's primaryGroupID matching the group's RID. Counting
    only ``member`` reports 0 for these groups, so this fills the gap.
    """
    parts = group_sid.rsplit("-", 1)
    if len(parts) != 2:
        return 0
    try:
        group_rid = int(parts[1])
    except ValueError:
        return 0
    count = 0
    for obj in idx.objects:
        pgid = obj.get("properties", {}).get("primaryGroupID")
        if pgid is not None:
            try:
                if int(pgid) == group_rid:
                    count += 1
            except (ValueError, TypeError):
                continue
        elif _DEFAULT_PRIMARY_GROUP_RID.get(obj.get("object_class", "")) == group_rid:
            count += 1
    return count


def object_info(idx: CollectionIndex, identifier: str) -> dict | None:
    """Build a comprehensive info dict for a single object."""
    obj = idx.get(identifier)
    if not obj:
        # Fall back to ranked name resolution (sAMAccountName, name, UPN
        # local-part) so 'bob' resolves 'bob@mydomain.local'.
        matches = idx.find_all_by_name(identifier)
        obj = matches[0] if matches else None
    if not obj:
        return None

    props = obj.get("properties", {})
    sid = obj.get("object_sid", "")
    cls = obj.get("object_class", "")
    uac = _get_uac(obj)

    # whenCreated (available on new collections)
    wc_dt = _parse_when_created(props.get("whenCreated"))

    info: dict = {
        "name": obj.get("name", ""),
        "sam_account_name": props.get("sAMAccountName", obj.get("name", "")),
        "dn": obj.get("dn", ""),
        "object_sid": sid,
        "object_class": cls,
        "when_created": _fmt_datetime(wc_dt),
        "owner": _resolve_name(obj.get("owner_sid"), idx.sid_map, idx.domain),
        "owner_sid": obj.get("owner_sid", ""),
    }

    if cls in ("user", "computer"):
        info["enabled"] = not bool(uac & 0x0002)
        info["uac_flags"] = _uac_flags(uac)
        info["uac_raw"] = uac

        pwd_ft = props.get("pwdLastSet")
        pwd_dt = _filetime_to_datetime(pwd_ft)
        info["pwd_last_set"] = _fmt_datetime(pwd_dt)
        info["pwd_age_days"] = _days_ago(pwd_dt)

        last_logon_ft = props.get("lastLogonTimestamp")
        last_logon_dt = _filetime_to_datetime(last_logon_ft)
        info["last_logon"] = _fmt_datetime(last_logon_dt)
        info["last_logon_days"] = _days_ago(last_logon_dt)

        info["admin_count"] = props.get("adminCount", 0)
        info["description"] = props.get("description", "")

        spns = props.get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        info["spns"] = spns

        delegation_targets = props.get("msDS-AllowedToDelegateTo", [])
        if isinstance(delegation_targets, str):
            delegation_targets = [delegation_targets]
        info["delegation_targets"] = delegation_targets

        sid_history = props.get("sIDHistory", [])
        if isinstance(sid_history, str):
            sid_history = [sid_history]
        info["sid_history"] = sid_history

        rbcd = props.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        info["rbcd_configured"] = rbcd is not None and rbcd != ""

        enc_types = _enc_types_str(props.get("msDS-SupportedEncryptionTypes"))
        info["supported_enc_types"] = enc_types

    # -- User-specific fields --------------------------------------------------
    if cls == "user":
        info["display_name"] = props.get("displayName", "")
        info["user_principal_name"] = props.get("userPrincipalName", "")
        info["mail"] = props.get("mail", "")
        info["title"] = props.get("title", "")
        info["department"] = props.get("department", "")
        manager_dn = props.get("manager", "")
        info["manager"] = _dn_to_short_name(manager_dn) if manager_dn else ""
        info["logon_count"] = props.get("logonCount", "")
        info["account_expires"] = _account_expires_str(props.get("accountExpires"))

    # -- Computer-specific fields ----------------------------------------------
    if cls == "computer":
        info["os"] = props.get("operatingSystem", "")
        info["os_version"] = props.get("operatingSystemVersion", "")
        info["os_service_pack"] = props.get("operatingSystemServicePack", "")
        info["dns_hostname"] = props.get("dNSHostName", "")
        managed_by_dn = props.get("managedBy", "")
        info["managed_by"] = _dn_to_short_name(managed_by_dn) if managed_by_dn else ""

    # -- Group-specific fields -------------------------------------------------
    if cls == "group":
        raw_members = props.get("member", [])
        if isinstance(raw_members, str):
            raw_members = [raw_members]
        # Include implicit primaryGroupID members (Domain Users/Computers/etc.),
        # which never appear in the 'member' attribute.
        info["direct_member_count"] = (
            len(raw_members) + _primary_group_member_count(idx, sid))
        info["description"] = props.get("description", "")
        info["admin_count"] = props.get("adminCount", 0)
        managed_by_dn = props.get("managedBy", "")
        info["managed_by"] = _dn_to_short_name(managed_by_dn) if managed_by_dn else ""
        info["mail"] = props.get("mail", "")
        gt = props.get("groupType")
        if gt is not None:
            try:
                gt = int(gt)
                info["group_type"] = "Security" if gt & 0x80000000 else "Distribution"
                scope_bits = gt & 0x0000000E
                if scope_bits == 2:
                    info["group_scope"] = "Global"
                elif scope_bits == 4:
                    info["group_scope"] = "Domain Local"
                elif scope_bits == 8:
                    info["group_scope"] = "Universal"
                else:
                    info["group_scope"] = f"Unknown ({scope_bits})"
            except (ValueError, TypeError):
                pass

    if cls == "ou":
        info["description"] = props.get("description", "")
        info["gp_link"] = props.get("gPLink", "")

    if cls == "gpo":
        info["gpc_path"] = props.get("gPCFileSysPath", "")

    if cls == "trusteddomain":
        td = props.get("trustDirection")
        tt = props.get("trustType")
        ta = props.get("trustAttributes")
        info["trust_direction"] = _trust_direction_str(td)
        info["trust_type"] = _trust_type_str(tt)
        info["trust_attributes"] = ta
        info["flat_name"] = props.get("flatName", "")

    if cls == "certtemplate":
        info["display_name"] = props.get("displayName", "")
        info["name_flag"] = props.get("msPKI-Certificate-Name-Flag")
        info["enrollment_flag"] = props.get("msPKI-Enrollment-Flag")
        info["ra_signature"] = props.get("msPKI-RA-Signature")
        info["schema_version"] = props.get("msPKI-Template-Schema-Version")
        info["eku"] = props.get("pKIExtendedKeyUsage", [])
        info["app_policy"] = props.get("msPKI-Certificate-Application-Policy", [])

    if cls == "gmsa":
        info["display_name"] = props.get("displayName", "")
        info["description"] = props.get("description", "")
        info["admin_count"] = props.get("adminCount", 0)
        info["enabled"] = not bool(uac & 0x0002)
        info["uac_flags"] = _uac_flags(uac)
        info["uac_raw"] = uac
        spns = props.get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        info["spns"] = spns
        info["password_interval"] = props.get("msDS-ManagedPasswordInterval", "")
        gmsa_membership = props.get("msDS-GroupMSAMembership", "")
        info["gmsa_membership_configured"] = gmsa_membership is not None and gmsa_membership != ""

    if cls == "pki":
        info["display_name"] = props.get("displayName", "")
        info["dns_hostname"] = props.get("dNSHostName", "")
        templates = props.get("certificateTemplates", [])
        if isinstance(templates, str):
            templates = [templates]
        info["certificate_templates"] = templates
        info["flags"] = props.get("flags", "")

    if cls == "oidobject":
        info["display_name"] = props.get("displayName", "")
        info["cert_template_oid"] = props.get("msPKI-Cert-Template-OID", "")
        info["oid_group_link"] = props.get("msDS-OIDToGroupLink", "")

    # -- Azure / Entra ID object types -----------------------------------------
    if cls == "aad_user":
        info["display_name"] = props.get("displayName", "")
        info["user_principal_name"] = props.get("userPrincipalName", "")
        info["mail"] = props.get("mail", "")
        info["enabled"] = props.get("accountEnabled", True)
        info["user_type"] = props.get("userType", "")
        info["on_prem_sync"] = props.get("_onPremSyncEnabled", False)
        info["on_prem_sid"] = props.get("_onPremSid", "")
        info["tenant_id"] = props.get("tenantId", "")
        info["tenant_name"] = props.get("tenantName", "")

    if cls == "aad_group":
        info["display_name"] = props.get("displayName", "")
        info["description"] = props.get("description", "")
        info["mail"] = props.get("mail", "")
        info["security_enabled"] = props.get("securityEnabled", False)
        info["tenant_id"] = props.get("tenantId", "")

    if cls == "aad_app":
        info["display_name"] = props.get("displayName", "")
        info["app_id"] = props.get("appId", "")
        info["tenant_id"] = props.get("tenantId", "")

    if cls == "aad_sp":
        info["display_name"] = props.get("displayName", "")
        info["app_id"] = props.get("appId", "")
        info["service_principal_type"] = props.get("servicePrincipalType", "")
        info["tenant_id"] = props.get("tenantId", "")

    if cls.startswith("azure_"):
        info["display_name"] = props.get("displayName", props.get("name", ""))
        info["tenant_id"] = props.get("tenantId", "")
        if cls == "azure_vm":
            info["os_type"] = props.get("storageProfile", {}).get("osDisk", {}).get("osType", "")
            info["vm_size"] = props.get("hardwareProfile", {}).get("vmSize", "")

    # Group memberships (AD objects only — Azure uses edges)
    if not cls.startswith(("aad_", "azure_")):
        groups = idx.memberof(identifier, recursive=True)
        info["member_of"] = [
            {"name": g.get("name", ""), "sid": g.get("object_sid", "")}
            for g in groups
        ]

    # Azure edges for this object
    if idx.is_hybrid:
        az_edges = [
            e for e in idx.azure_edges + idx.hybrid_edges
            if e.get("source_id") == sid or e.get("target_id") == sid
        ]
        if az_edges:
            from lazyhound.finder.utils_pkg.azure_ingestor import _ENTRA_ROLE_TEMPLATES

            def _edge_label(e: dict) -> str:
                et = e.get("edge_type", "")
                if et in ("AZHasRole", "AZPIMEligible"):
                    p = e.get("properties", {}) or {}
                    rtid = p.get("roleTemplateId") or p.get("roleDefinitionId", "")
                    name = _ENTRA_ROLE_TEMPLATES.get(rtid, "")
                    if name:
                        return f"{et}: {name}"
                return et

            info["azure_edges"] = [
                {
                    "type": _edge_label(e),
                    "direction": "outbound" if e.get("source_id") == sid else "inbound",
                    "peer_id": e.get("target_id", "") if e.get("source_id") == sid else e.get("source_id", ""),
                    "peer_name": idx.sid_map.get(
                        e.get("target_id", "") if e.get("source_id") == sid else e.get("source_id", ""), ""
                    ),
                    "properties": e.get("properties", {}),
                }
                for e in az_edges
            ]

    # DACL summary
    dacl = obj.get("dacl", [])
    info["dacl_entry_count"] = len(dacl)

    return info


# ---------------------------------------------------------------------------
# Trust helpers
# ---------------------------------------------------------------------------
def _trust_direction_str(val: int | str | None) -> str:
    if val is None:
        return "unknown"
    try:
        val = int(val)
    except (ValueError, TypeError):
        return str(val)
    return {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(val, f"Unknown ({val})")


def _trust_type_str(val: int | str | None) -> str:
    if val is None:
        return "unknown"
    try:
        val = int(val)
    except (ValueError, TypeError):
        return str(val)
    return {1: "Windows NT", 2: "Active Directory", 3: "MIT Kerberos"}.get(val, f"Unknown ({val})")

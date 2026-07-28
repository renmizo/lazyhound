"""BloodHound CE compatible export.

Converts LazyHound's collector JSON into the SharpHound-compatible format
that BloodHound Community Edition can ingest.  Produces a ZIP containing typed
JSON files (users, groups, computers, domains, ous, gpos, containers).

Usage:
    lazyhound bloodhound-export collection.json -o bloodhound_output.zip

No additional LDAP queries are needed — this is a pure data transformation
of an existing collection JSON file.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..tier_zero import TIER_ZERO_RIDS, TIER_ZERO_SIDS, is_tier_zero_object

def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to int, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


# BloodHound CE schema version (v5 format)
BH_SCHEMA_VERSION = 5

# Well-known extended-right GUIDs → BloodHound edge names
_EXTENDED_RIGHTS: dict[str, str] = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet",
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "e6075277-72a6-4559-9571-a1a086a898a3": "ReadLAPSPassword",
    "b913d02b-1579-4eee-82ff-61dd69ad4fe6": "ReadLAPSPassword",
    "ab6a8f8f-7c09-4ef3-a08e-ac8ee3f8a986": "ReadLAPSPassword",
    "0e78295a-c6d0-4b74-b6f2-52c7563aaca4": "ReadGMSAPassword",
}

# Well-known property GUIDs → BloodHound right names
_PROPERTY_GUIDS: dict[str, str] = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "WriteMember",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "WriteSPN",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "WriteAllowedToAct",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "WriteKeyCredentialLink",
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1": "WriteGPLink",
}

# Access mask bits
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_WRITE_DACL = 0x00040000
_WRITE_OWNER = 0x00080000
_DS_CONTROL_ACCESS = 0x00000100
_DS_WRITE_PROPERTY = 0x00000020
_DS_SELF = 0x00000008

# UAC flags
_UAC_ACCOUNTDISABLE = 0x0002
_UAC_DONT_REQ_PREAUTH = 0x400000
_UAC_PASSWORD_NEVER_EXPIRES = 0x10000
_UAC_NOT_DELEGATED = 0x100000
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


def _ensure_list(val: Any) -> list:
    """Normalize a value to a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _parse_uac(raw: Any) -> int:
    """Parse userAccountControl to integer."""
    if isinstance(raw, int):
        return raw
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 0


def _is_highvalue_sid(sid: str | None, domain_sid: str) -> bool:
    """Check if a SID is Tier Zero (domain-scoped RID match + well-known SIDs)."""
    if not sid:
        return False
    if sid in TIER_ZERO_SIDS:
        return True
    if domain_sid and sid.startswith(domain_sid + "-"):
        rid = sid.rsplit("-", 1)[-1]
        try:
            return int(rid) in TIER_ZERO_RIDS
        except ValueError:
            return False
    return False


def _dn_to_bh_name(name: str, domain_upper: str) -> str:
    """Format a name for BloodHound (NAME@DOMAIN.COM)."""
    return f"{name.upper()}@{domain_upper}"


def _extract_domain_sid(objects: list[dict[str, Any]]) -> str:
    """Extract the domain SID from the collection objects."""
    for obj in objects:
        if obj.get("object_class") == "domain" and obj.get("object_sid"):
            return obj["object_sid"]
    # Fallback: find any SID and strip the RID
    for obj in objects:
        sid = obj.get("object_sid")
        if sid and sid.startswith("S-1-5-21-"):
            return sid.rsplit("-", 1)[0]
    return ""


def _convert_aces(dacl: list[dict[str, Any]], sid_map: dict[str, str]) -> list[dict[str, Any]]:
    """Convert LazyHound ACE format to BloodHound CE ACE format."""
    bh_aces = []
    for ace in dacl:
        if ace.get("inherited", False):
            continue
        if ace.get("ace_type", "").startswith("ACCESS_DENIED"):
            continue

        trustee_sid = ace.get("trustee_sid", "")
        if not trustee_sid:
            continue

        mask = ace.get("access_mask", 0)
        object_type = (ace.get("object_type") or "").lower()
        ace_type = ace.get("ace_type", "")
        is_object_ace = "OBJECT" in ace_type

        # Determine the BloodHound right type
        if mask & _GENERIC_ALL:
            bh_aces.append(_bh_ace(trustee_sid, "GenericAll"))
        elif mask & _GENERIC_WRITE:
            bh_aces.append(_bh_ace(trustee_sid, "GenericWrite"))
        elif mask & _WRITE_DACL:
            bh_aces.append(_bh_ace(trustee_sid, "WriteDacl"))
        elif mask & _WRITE_OWNER:
            bh_aces.append(_bh_ace(trustee_sid, "WriteOwner"))

        if is_object_ace and object_type:
            # Extended rights
            if mask & _DS_CONTROL_ACCESS and object_type in _EXTENDED_RIGHTS:
                bh_aces.append(_bh_ace(trustee_sid, _EXTENDED_RIGHTS[object_type]))
            # Write properties
            if mask & _DS_WRITE_PROPERTY and object_type in _PROPERTY_GUIDS:
                bh_aces.append(_bh_ace(trustee_sid, _PROPERTY_GUIDS[object_type]))
            # Self rights
            if mask & _DS_SELF and object_type in _PROPERTY_GUIDS:
                bh_aces.append(_bh_ace(trustee_sid, _PROPERTY_GUIDS[object_type]))

        # All extended rights (no specific object type, only if no generic right already emitted)
        elif not is_object_ace and mask & _DS_CONTROL_ACCESS:
            bh_aces.append(_bh_ace(trustee_sid, "AllExtendedRights"))

    return bh_aces


def _bh_ace(principal_sid: str, right: str) -> dict[str, Any]:
    """Build a single BloodHound-format ACE."""
    return {
        "PrincipalSID": principal_sid,
        "PrincipalType": "Unknown",  # resolved later if possible
        "RightName": right,
        "IsInherited": False,
    }


def _resolve_ace_principal_types(
    aces: list[dict[str, Any]],
    sid_type_map: dict[str, str],
) -> None:
    """Update ACE principal types using the SID → type mapping."""
    for ace in aces:
        sid = ace.get("PrincipalSID", "")
        if sid in sid_type_map:
            ace["PrincipalType"] = sid_type_map[sid]


def _convert_user(
    obj: dict[str, Any],
    domain_upper: str,
    domain_sid: str,
    sid_type_map: dict[str, str],
) -> dict[str, Any]:
    """Convert LazyHound user to BloodHound CE user."""
    props = obj.get("properties", {})
    sid = obj.get("object_sid", "")
    uac = _parse_uac(props.get("userAccountControl", 0))

    spns = _ensure_list(props.get("servicePrincipalName"))
    allowed_to_delegate = _ensure_list(props.get("msDS-AllowedToDelegateTo"))
    sid_history = _ensure_list(props.get("sIDHistory"))

    bh_aces = _convert_aces(obj.get("dacl", []), {})
    _resolve_ace_principal_types(bh_aces, sid_type_map)

    return {
        "ObjectIdentifier": sid,
        "PrimaryGroupSID": f"{domain_sid}-513" if domain_sid else None,
        "ContainedBy": _dn_to_container(obj.get("dn", ""), domain_upper),
        "Properties": {
            "name": _dn_to_bh_name(obj.get("name", ""), domain_upper),
            "domain": domain_upper,
            "domainsid": domain_sid,
            "distinguishedname": obj.get("dn", ""),
            "highvalue": _is_highvalue_sid(sid, domain_sid),
            "enabled": not bool(uac & _UAC_ACCOUNTDISABLE),
            "unconstraineddelegation": bool(uac & _UAC_TRUSTED_FOR_DELEGATION),
            "dontreqpreauth": bool(uac & _UAC_DONT_REQ_PREAUTH),
            "pwdneverexpires": bool(uac & _UAC_PASSWORD_NEVER_EXPIRES),
            "sensitive": bool(uac & _UAC_NOT_DELEGATED),
            "serviceprincipalnames": spns,
            "hasspn": len(spns) > 0,
            "admincount": bool(props.get("adminCount")),
            "description": props.get("description", None),
            "allowedtodelegate": allowed_to_delegate,
            "sidhistory": sid_history,
        },
        "AllowedToDelegate": allowed_to_delegate,
        "HasSIDHistory": [
            {"ObjectIdentifier": s, "ObjectType": "Unknown"}
            for s in sid_history
        ],
        "SPNTargets": [],
        "Aces": bh_aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _convert_group(
    obj: dict[str, Any],
    domain_upper: str,
    domain_sid: str,
    dn_sid_map: dict[str, str],
    sid_type_map: dict[str, str],
) -> dict[str, Any]:
    """Convert LazyHound group to BloodHound CE group."""
    props = obj.get("properties", {})
    sid = obj.get("object_sid", "")

    members_raw = _ensure_list(props.get("member"))
    members = []
    for m_dn in members_raw:
        m_sid = dn_sid_map.get(m_dn, "")
        m_type = sid_type_map.get(m_sid, "Unknown") if m_sid else "Unknown"
        if m_sid:
            members.append({"ObjectIdentifier": m_sid, "ObjectType": m_type})

    bh_aces = _convert_aces(obj.get("dacl", []), {})
    _resolve_ace_principal_types(bh_aces, sid_type_map)

    return {
        "ObjectIdentifier": sid,
        "ContainedBy": _dn_to_container(obj.get("dn", ""), domain_upper),
        "Properties": {
            "name": _dn_to_bh_name(obj.get("name", ""), domain_upper),
            "domain": domain_upper,
            "domainsid": domain_sid,
            "distinguishedname": obj.get("dn", ""),
            "highvalue": _is_highvalue_sid(sid, domain_sid),
            "admincount": bool(props.get("adminCount")),
            "description": props.get("description", None),
        },
        "Members": members,
        "Aces": bh_aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _convert_computer(
    obj: dict[str, Any],
    domain_upper: str,
    domain_sid: str,
    sid_type_map: dict[str, str],
) -> dict[str, Any]:
    """Convert LazyHound computer to BloodHound CE computer."""
    props = obj.get("properties", {})
    sid = obj.get("object_sid", "")
    uac = _parse_uac(props.get("userAccountControl", 0))

    spns = _ensure_list(props.get("servicePrincipalName"))
    allowed_to_delegate = _ensure_list(props.get("msDS-AllowedToDelegateTo"))
    allowed_to_act = _ensure_list(props.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
    sid_history = _ensure_list(props.get("sIDHistory"))

    bh_aces = _convert_aces(obj.get("dacl", []), {})
    _resolve_ace_principal_types(bh_aces, sid_type_map)

    return {
        "ObjectIdentifier": sid,
        "PrimaryGroupSID": f"{domain_sid}-515" if domain_sid else None,
        "ContainedBy": _dn_to_container(obj.get("dn", ""), domain_upper),
        "AllowedToDelegate": allowed_to_delegate,
        "AllowedToAct": [
            {"ObjectIdentifier": s, "ObjectType": sid_type_map.get(s, "Unknown")}
            for s in allowed_to_act if s
        ],
        "HasSIDHistory": [
            {"ObjectIdentifier": s, "ObjectType": "Unknown"}
            for s in sid_history
        ],
        "Properties": {
            "name": _dn_to_bh_name(obj.get("name", ""), domain_upper),
            "domain": domain_upper,
            "domainsid": domain_sid,
            "distinguishedname": obj.get("dn", ""),
            "highvalue": is_tier_zero_object(obj),
            "enabled": not bool(uac & _UAC_ACCOUNTDISABLE),
            "unconstraineddelegation": bool(uac & _UAC_TRUSTED_FOR_DELEGATION),
            "operatingsystem": props.get("operatingSystem", None),
            "serviceprincipalnames": spns,
            "haslaps": False,
            "allowedtodelegate": allowed_to_delegate,
            "sidhistory": sid_history,
        },
        "Aces": bh_aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _convert_ou(
    obj: dict[str, Any],
    domain_upper: str,
    domain_sid: str,
    child_map: dict[str, list[dict[str, Any]]],
    sid_type_map: dict[str, str],
) -> dict[str, Any]:
    """Convert LazyHound OU to BloodHound CE OU."""
    props = obj.get("properties", {})
    dn = obj.get("dn", "")
    # OUs use a GUID-based identifier (we use a hash of the DN)
    oid = obj.get("object_sid") or _dn_to_guid(dn)
    gp_link = props.get("gPLink", "")

    bh_aces = _convert_aces(obj.get("dacl", []), {})
    _resolve_ace_principal_types(bh_aces, sid_type_map)

    links = []
    if gp_link:
        links = _parse_gplink(gp_link)

    return {
        "ObjectIdentifier": oid,
        "ContainedBy": _dn_to_container(dn, domain_upper),
        "Properties": {
            "name": f"{obj.get('name', '')}@{domain_upper}",
            "domain": domain_upper,
            "domainsid": domain_sid,
            "distinguishedname": dn,
            "highvalue": False,
            "description": props.get("description", None),
        },
        "ChildObjects": child_map.get(dn.upper(), []),
        "Links": links,
        "Aces": bh_aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _convert_gpo(
    obj: dict[str, Any],
    domain_upper: str,
    domain_sid: str,
    sid_type_map: dict[str, str],
) -> dict[str, Any]:
    """Convert LazyHound GPO to BloodHound CE GPO."""
    props = obj.get("properties", {})
    dn = obj.get("dn", "")
    oid = obj.get("object_sid") or _dn_to_guid(dn)

    bh_aces = _convert_aces(obj.get("dacl", []), {})
    _resolve_ace_principal_types(bh_aces, sid_type_map)

    return {
        "ObjectIdentifier": oid,
        "ContainedBy": _dn_to_container(dn, domain_upper),
        "Properties": {
            "name": f"{props.get('displayName', obj.get('name', ''))}@{domain_upper}",
            "domain": domain_upper,
            "domainsid": domain_sid,
            "distinguishedname": dn,
            "highvalue": False,
            "gpcpath": props.get("gPCFileSysPath", ""),
        },
        "Aces": bh_aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _convert_domain(
    obj: dict[str, Any],
    domain_upper: str,
    domain_sid: str,
    trust_objects: list[dict[str, Any]],
    child_map: dict[str, list[dict[str, Any]]],
    sid_type_map: dict[str, str],
) -> dict[str, Any]:
    """Convert LazyHound domain to BloodHound CE domain."""
    props = obj.get("properties", {})
    dn = obj.get("dn", "")

    trusts = []
    for t in trust_objects:
        tp = t.get("properties", {})
        try:
            direction = int(tp.get("trustDirection") or 0)
        except (ValueError, TypeError):
            direction = 0
        try:
            trust_type = int(tp.get("trustType") or 0)
        except (ValueError, TypeError):
            trust_type = 0
        try:
            attrs = int(tp.get("trustAttributes") or 0)
        except (ValueError, TypeError):
            attrs = 0
        trusts.append({
            "TargetDomainSid": tp.get("securityIdentifier", ""),
            "TargetDomainName": t.get("name", ""),
            "TrustDirection": _bh_trust_direction(direction),
            "TrustType": _bh_trust_type(trust_type),
            "IsTransitive": not bool(attrs & 0x01),  # NON_TRANSITIVE bit
            "SidFilteringEnabled": bool(attrs & 0x04),
        })

    bh_aces = _convert_aces(obj.get("dacl", []), {})
    _resolve_ace_principal_types(bh_aces, sid_type_map)

    gp_link = props.get("gPLink", "")
    links = []
    if gp_link:
        links = _parse_gplink(gp_link)

    return {
        "ObjectIdentifier": domain_sid,
        "Properties": {
            "name": domain_upper,
            "domain": domain_upper,
            "domainsid": domain_sid,
            "distinguishedname": dn,
            "highvalue": True,
            "functionallevel": "",
            "machineaccountquota": _safe_int(props.get("ms-DS-MachineAccountQuota", 10), 10),
        },
        "ChildObjects": child_map.get(dn.upper(), []),
        "Trusts": trusts,
        "Links": links,
        "Aces": bh_aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _bh_trust_direction(direction: int) -> str:
    return {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(
        direction, "Unknown"
    )


def _bh_trust_type(trust_type: int) -> str:
    return {1: "WINDOWS_NON_ACTIVE_DIRECTORY", 2: "WINDOWS_ACTIVE_DIRECTORY", 3: "MIT"}.get(
        trust_type, "Unknown"
    )


def _dn_to_container(dn: str, domain_upper: str) -> dict[str, Any] | None:
    """Extract the parent container from a DN."""
    parts = dn.split(",", 1)
    if len(parts) < 2:
        return None
    parent_dn = parts[1]
    return {
        "ObjectIdentifier": _dn_to_guid(parent_dn),
        "ObjectType": _container_type_from_dn(parent_dn),
    }


def _container_type_from_dn(dn: str) -> str:
    """Guess the container type from a DN."""
    upper = dn.upper()
    if upper.startswith("OU="):
        return "OU"
    if upper.startswith("CN="):
        return "Container"
    if upper.startswith("DC="):
        return "Domain"
    return "Container"


def _dn_to_guid(dn: str) -> str:
    """Generate a stable identifier from a DN (hash-based)."""
    import hashlib
    return hashlib.sha256(dn.upper().encode()).hexdigest()[:36]


def _parse_gplink(gplink_str: str) -> list[dict[str, Any]]:
    """Parse a gPLink string into BloodHound Link objects."""
    import re
    links = []
    for match in re.finditer(r"\[LDAP://([^;]+);(\d+)\]", gplink_str, re.IGNORECASE):
        gpo_dn = match.group(1)
        status = int(match.group(2))
        enforced = bool(status & 2)
        links.append({
            "GUID": _dn_to_guid(gpo_dn),
            "IsEnforced": enforced,
        })
    return links


def _build_indexes(
    objects: list[dict[str, Any]],
) -> tuple[dict[str, str], dict[str, str], dict[str, list[dict[str, Any]]]]:
    """Build DN→SID, SID→Type, and parent-DN→ChildObjects maps."""
    dn_sid_map: dict[str, str] = {}
    sid_type_map: dict[str, str] = {}
    child_map: dict[str, list[dict[str, Any]]] = {}

    type_mapping = {
        "user": "User",
        "group": "Group",
        "computer": "Computer",
        "ou": "OU",
        "gpo": "GPO",
        "domain": "Domain",
        "certtemplate": "Container",
        "pki": "Container",
    }

    for obj in objects:
        dn = obj.get("dn", "")
        sid = obj.get("object_sid")
        obj_class = obj.get("object_class", "")
        bh_type = type_mapping.get(obj_class, "Unknown")

        identifier = sid or _dn_to_guid(dn)
        if dn:
            dn_sid_map[dn] = identifier
        if sid:
            sid_type_map[sid] = bh_type
        # Also map dn-based IDs
        if not sid:
            sid_type_map[identifier] = bh_type

        # Build child map (parent DN → children)
        parts = dn.split(",", 1)
        if len(parts) == 2:
            parent_dn = parts[1].upper()
            child_map.setdefault(parent_dn, []).append({
                "ObjectIdentifier": identifier,
                "ObjectType": bh_type,
            })

    return dn_sid_map, sid_type_map, child_map


# ---------------------------------------------------------------------------
# Azure / Hybrid object converters
# ---------------------------------------------------------------------------
_AZ_TYPE_MAP = {
    "aad_user": "AZUser",
    "aad_group": "AZGroup",
    "aad_app": "AZApp",
    "aad_sp": "AZServicePrincipal",
    "aad_device": "AZDevice",
    "azure_tenant": "AZTenant",
    "azure_sub": "AZSubscription",
    "azure_rg": "AZResourceGroup",
    "azure_vm": "AZVM",
    "azure_kv": "AZKeyVault",
}


def _convert_azure_object(
    obj: dict[str, Any],
    tenant_name: str,
) -> dict[str, Any]:
    """Convert an LazyHound Azure object to BloodHound CE format."""
    props = obj.get("properties", {})
    obj_id = obj.get("object_sid", "")
    obj_class = obj.get("object_class", "")
    bh_type = _AZ_TYPE_MAP.get(obj_class, "Base")

    bh_props: dict[str, Any] = {
        "name": obj.get("name", ""),
        "objectid": obj_id,
        "tenantid": props.get("tenantId", ""),
    }

    if obj_class == "aad_user":
        bh_props["displayname"] = props.get("displayName", "")
        bh_props["userprincipalname"] = props.get("userPrincipalName", "")
        bh_props["mail"] = props.get("mail", "")
        bh_props["enabled"] = props.get("accountEnabled", True)
        bh_props["usertype"] = props.get("userType", "")
        bh_props["onpremisessyncenabled"] = props.get("_onPremSyncEnabled", False)
        bh_props["onpremisessecurityidentifier"] = props.get("_onPremSid", "")

    elif obj_class == "aad_group":
        bh_props["displayname"] = props.get("displayName", "")
        bh_props["description"] = props.get("description", "")
        bh_props["securityenabled"] = props.get("securityEnabled", False)

    elif obj_class == "aad_app":
        bh_props["displayname"] = props.get("displayName", "")
        bh_props["appid"] = props.get("appId", "")

    elif obj_class == "aad_sp":
        bh_props["displayname"] = props.get("displayName", "")
        bh_props["appid"] = props.get("appId", "")
        bh_props["serviceprincipaltype"] = props.get("servicePrincipalType", "")

    return {
        "ObjectIdentifier": obj_id,
        "Properties": bh_props,
        "Kind": bh_type,
        "Aces": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _convert_hybrid_edges(
    hybrid_edges: list[dict[str, Any]],
    sid_type_map: dict[str, str],
) -> list[dict[str, Any]]:
    """Convert hybrid edges to BloodHound relationship format.

    BloodHound CE recognises ``SyncedToEntraUser`` and ``SyncedToADUser``
    edges natively (v5.13+).
    """
    bh_edges = []
    for edge in hybrid_edges:
        edge_type = edge.get("edge_type", "")
        if edge_type not in ("SyncedToEntraUser", "SyncedToADUser"):
            continue
        bh_edges.append({
            "SourceID": edge["source_id"],
            "SourceType": sid_type_map.get(edge["source_id"], "Base"),
            "TargetID": edge["target_id"],
            "TargetType": sid_type_map.get(edge["target_id"], "Base"),
            "RelType": edge_type,
            "Properties": edge.get("properties", {}),
        })
    return bh_edges


def convert(collection: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Convert an LazyHound collection dict to BloodHound CE typed arrays.

    Returns a dict with keys: users, groups, computers, domains, ous, gpos,
    and optionally azure_objects and relationships (for hybrid collections).
    """
    objects = collection.get("objects", [])
    meta = collection.get("meta", {})
    domain = meta.get("domain", "unknown.local")
    domain_upper = domain.upper()
    domain_sid = _extract_domain_sid(objects)

    dn_sid_map, sid_type_map, child_map = _build_indexes(objects)

    # Also add well-known SIDs to the sid_map
    bh_sid_map = collection.get("sid_map", {})
    for sid, name in bh_sid_map.items():
        if sid not in sid_type_map:
            sid_type_map[sid] = "Unknown"

    result: dict[str, list[dict[str, Any]]] = {
        "users": [],
        "groups": [],
        "computers": [],
        "domains": [],
        "ous": [],
        "gpos": [],
    }

    trust_objects = [o for o in objects if o.get("object_class") == "trusteddomain"]

    for obj in objects:
        cls = obj.get("object_class", "")

        if cls == "user":
            result["users"].append(
                _convert_user(obj, domain_upper, domain_sid, sid_type_map)
            )
        elif cls == "group":
            result["groups"].append(
                _convert_group(obj, domain_upper, domain_sid, dn_sid_map, sid_type_map)
            )
        elif cls == "computer":
            result["computers"].append(
                _convert_computer(obj, domain_upper, domain_sid, sid_type_map)
            )
        elif cls == "domain":
            result["domains"].append(
                _convert_domain(
                    obj, domain_upper, domain_sid, trust_objects, child_map, sid_type_map
                )
            )
        elif cls == "ou":
            result["ous"].append(
                _convert_ou(obj, domain_upper, domain_sid, child_map, sid_type_map)
            )
        elif cls == "gpo":
            result["gpos"].append(
                _convert_gpo(obj, domain_upper, domain_sid, sid_type_map)
            )
        # trusteddomain, certtemplate, pki are handled inline (trusts in domain)

    # Azure / Hybrid data (if present)
    azure_objects = collection.get("azure_objects", [])
    hybrid_edges = collection.get("hybrid_edges", [])

    if azure_objects:
        tenant_name = meta.get("azure_stats", {}).get("tenant_name", "")
        az_objs = []
        for az_obj in azure_objects:
            bh_obj = _convert_azure_object(az_obj, tenant_name)
            az_objs.append(bh_obj)
            # Register in sid_type_map for relationship resolution
            obj_id = az_obj.get("object_sid", "")
            if obj_id:
                sid_type_map[obj_id] = _AZ_TYPE_MAP.get(
                    az_obj.get("object_class", ""), "Base"
                )
        result["azure"] = az_objs

    if hybrid_edges:
        result["relationships"] = _convert_hybrid_edges(hybrid_edges, sid_type_map)

    return result


def _wrap_bh_json(data_type: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap items in the BloodHound CE JSON envelope."""
    return {
        "data": items,
        "meta": {
            "methods": 0,
            "type": data_type,
            "count": len(items),
            "version": BH_SCHEMA_VERSION,
        },
    }


def export_zip(collection: dict[str, Any], output_path: str | Path) -> Path:
    """Convert and write a BloodHound CE compatible ZIP.

    Args:
        collection: LazyHound collection dict (loaded from JSON).
        output_path: Path for the output ZIP file.

    Returns:
        Path to the written ZIP file.
    """
    converted = convert(collection)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for data_type, items in converted.items():
            if not items:
                continue
            filename = f"{ts}_{data_type}.json"
            content = json.dumps(_wrap_bh_json(data_type, items), indent=2, default=str)
            zf.writestr(filename, content)

    return output


# ---------------------------------------------------------------------------
# BloodHound CE Import — convert BH CE ZIP/JSON back to LazyHound format
# ---------------------------------------------------------------------------

# Reverse mapping: BH type string → LazyHound object_class
_BH_TYPE_TO_CLASS: dict[str, str] = {
    "users": "user",
    "groups": "group",
    "computers": "computer",
    "domains": "domain",
    "ous": "ou",
    "gpos": "gpo",
}

# Reverse ACE right → (access_mask, object_type_guid | None)
_BH_RIGHT_TO_ACE: dict[str, tuple[int, str | None]] = {
    "GenericAll": (_GENERIC_ALL, None),
    "GenericWrite": (_GENERIC_WRITE, None),
    "WriteDacl": (_WRITE_DACL, None),
    "WriteOwner": (_WRITE_OWNER, None),
    "AllExtendedRights": (_DS_CONTROL_ACCESS, None),
    "GetChanges": (_DS_CONTROL_ACCESS, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
    "GetChangesAll": (_DS_CONTROL_ACCESS, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
    "GetChangesInFilteredSet": (_DS_CONTROL_ACCESS, "89e95b76-444d-4c62-991a-0facbeda640c"),
    "ForceChangePassword": (_DS_CONTROL_ACCESS, "00299570-246d-11d0-a768-00aa006e0529"),
    "WriteMember": (_DS_WRITE_PROPERTY, "bf9679c0-0de6-11d0-a285-00aa003049e2"),
    "WriteSPN": (_DS_WRITE_PROPERTY, "f3a64788-5306-11d1-a9c5-0000f80367c1"),
    "WriteAllowedToAct": (_DS_WRITE_PROPERTY, "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"),
    "WriteKeyCredentialLink": (_DS_WRITE_PROPERTY, "5b47d60f-6090-40b2-9f37-2a4de88f3063"),
    "WriteGPLink": (_DS_WRITE_PROPERTY, "f30e3bbe-9ff0-11d1-b603-0000f80367c1"),
    "ReadLAPSPassword": (_DS_CONTROL_ACCESS, "e6075277-72a6-4559-9571-a1a086a898a3"),
    "ReadGMSAPassword": (_DS_CONTROL_ACCESS, "0e78295a-c6d0-4b74-b6f2-52c7563aaca4"),
    # ADCS rights
    "Enroll": (_DS_CONTROL_ACCESS, "0e10c968-78fb-11d2-90d4-00c04f79dc55"),
    "AutoEnroll": (_DS_CONTROL_ACCESS, "a05b8cc2-17bc-4802-a710-e7c15ab866a2"),
    "ManageCA": (0x01, None),            # CA-specific; matches analyzer ESC7 check
    "ManageCertificates": (0x02, None),
}


def _import_aces(bh_aces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert BloodHound CE ACEs back to LazyHound DACL format."""
    dacl: list[dict[str, Any]] = []
    for ace in bh_aces:
        right = ace.get("RightName", "")
        principal_sid = ace.get("PrincipalSID", "")
        inherited = ace.get("IsInherited", False)
        if not principal_sid or not right:
            continue
        mapping = _BH_RIGHT_TO_ACE.get(right)
        if not mapping:
            continue
        mask, obj_type = mapping
        entry: dict[str, Any] = {
            "trustee_sid": principal_sid,
            "access_mask": mask,
            "ace_type": "ACCESS_ALLOWED_OBJECT_ACE" if obj_type else "ACCESS_ALLOWED_ACE",
            "inherited": inherited,
        }
        if obj_type:
            entry["object_type"] = obj_type
        dacl.append(entry)
    return dacl


def _bh_epoch_to_iso(val: Any) -> str:
    """BloodHound stores AD timestamps (pwdlastset, lastlogon, whencreated) as
    Unix epoch seconds, with -1/0 meaning never/unset. Convert to an ISO-8601 UTC
    string (parsed downstream by _filetime_to_datetime / _parse_when_created);
    return '' for never/unset/invalid."""
    try:
        epoch = int(val)
    except (TypeError, ValueError):
        return ""
    if epoch <= 0:
        return ""
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(sep=" ")
    except (OSError, OverflowError, ValueError):
        return ""


def _import_user(bh_obj: dict[str, Any], domain: str) -> dict[str, Any]:
    """Convert a BloodHound CE user back to LazyHound format."""
    props = bh_obj.get("Properties", {})
    sid = bh_obj.get("ObjectIdentifier", "")

    # Reconstruct UAC from boolean flags
    uac = 0x200  # NORMAL_ACCOUNT baseline
    if not props.get("enabled", True):
        uac |= _UAC_ACCOUNTDISABLE
    if props.get("dontreqpreauth", False):
        uac |= _UAC_DONT_REQ_PREAUTH
    if props.get("pwdneverexpires", False):
        uac |= _UAC_PASSWORD_NEVER_EXPIRES
    if props.get("sensitive", False):
        uac |= _UAC_NOT_DELEGATED
    if props.get("unconstraineddelegation", False):
        uac |= _UAC_TRUSTED_FOR_DELEGATION

    return {
        "dn": props.get("distinguishedname", ""),
        "name": (props.get("name", "") or "").split("@")[0],
        "object_sid": sid,
        "object_class": "user",
        "owner_sid": "",
        "properties": {
            "userAccountControl": uac,
            "sAMAccountName": props.get("samaccountname", ""),
            "servicePrincipalName": props.get("serviceprincipalnames", []),
            "msDS-AllowedToDelegateTo": props.get("allowedtodelegate", []),
            "sIDHistory": props.get("sidhistory", []),
            "adminCount": 1 if props.get("admincount", False) else 0,
            "description": props.get("description", ""),
            "pwdLastSet": _bh_epoch_to_iso(props.get("pwdlastset")),
            "lastLogonTimestamp": _bh_epoch_to_iso(
                props.get("lastlogontimestamp") or props.get("lastlogon")),
            "whenCreated": _bh_epoch_to_iso(props.get("whencreated")),
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_group(bh_obj: dict[str, Any], domain: str) -> dict[str, Any]:
    """Convert a BloodHound CE group back to LazyHound format."""
    props = bh_obj.get("Properties", {})
    sid = bh_obj.get("ObjectIdentifier", "")

    # Collect member DNs from Members array (we store SIDs since we may not have DNs)
    member_sids = [
        m.get("ObjectIdentifier", "")
        for m in bh_obj.get("Members", [])
        if m.get("ObjectIdentifier")
    ]

    return {
        "dn": props.get("distinguishedname", ""),
        "name": (props.get("name", "") or "").split("@")[0],
        "object_sid": sid,
        "object_class": "group",
        "owner_sid": "",
        "properties": {
            "member": member_sids,  # SIDs instead of DNs (resolved later)
            "adminCount": 1 if props.get("admincount", False) else 0,
            "description": props.get("description", ""),
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_computer(bh_obj: dict[str, Any], domain: str) -> dict[str, Any]:
    """Convert a BloodHound CE computer back to LazyHound format."""
    props = bh_obj.get("Properties", {})
    sid = bh_obj.get("ObjectIdentifier", "")

    uac = 0x1000  # WORKSTATION_TRUST_ACCOUNT baseline
    if not props.get("enabled", True):
        uac |= _UAC_ACCOUNTDISABLE
    if props.get("unconstraineddelegation", False):
        uac |= _UAC_TRUSTED_FOR_DELEGATION

    allowed_to_act = [
        a.get("ObjectIdentifier", "")
        for a in bh_obj.get("AllowedToAct", [])
        if a.get("ObjectIdentifier")
    ]

    return {
        "dn": props.get("distinguishedname", ""),
        "name": (props.get("name", "") or "").split("@")[0],
        "object_sid": sid,
        "object_class": "computer",
        "owner_sid": "",
        "properties": {
            "userAccountControl": uac,
            "sAMAccountName": props.get("samaccountname", ""),
            "operatingSystem": props.get("operatingsystem", ""),
            "servicePrincipalName": props.get("serviceprincipalnames", []),
            "msDS-AllowedToDelegateTo": props.get("allowedtodelegate", []),
            "msDS-AllowedToActOnBehalfOfOtherIdentity": allowed_to_act,
            "sIDHistory": props.get("sidhistory", []),
            "pwdLastSet": _bh_epoch_to_iso(props.get("pwdlastset")),
            "lastLogonTimestamp": _bh_epoch_to_iso(
                props.get("lastlogontimestamp") or props.get("lastlogon")),
            "whenCreated": _bh_epoch_to_iso(props.get("whencreated")),
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_domain(
    bh_obj: dict[str, Any],
    domain: str,
    gpo_guid_to_dn: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Convert a BloodHound CE domain back to LazyHound format."""
    props = bh_obj.get("Properties", {})
    sid = bh_obj.get("ObjectIdentifier", "")
    gpo_map = gpo_guid_to_dn or {}

    # Reconstruct gPLink from Links array, same as _import_ou
    gplink_parts = []
    for link in bh_obj.get("Links", []):
        guid = link.get("GUID", "")
        enforced = link.get("IsEnforced", False)
        status = 2 if enforced else 0
        if guid:
            dn_or_guid = gpo_map.get(guid, guid)
            gplink_parts.append(f"[LDAP://{dn_or_guid};{status}]")
    gplink_str = "".join(gplink_parts)

    return {
        "dn": props.get("distinguishedname", ""),
        "name": (props.get("name", "") or "").split("@")[0],
        "object_sid": sid,
        "object_class": "domain",
        "owner_sid": "",
        "properties": {
            "ms-DS-MachineAccountQuota": props.get("machineaccountquota", 10),
            **({"gPLink": gplink_str} if gplink_str else {}),
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_ou(
    bh_obj: dict[str, Any],
    domain: str,
    gpo_guid_to_dn: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Convert a BloodHound CE OU back to LazyHound format."""
    props = bh_obj.get("Properties", {})
    gpo_map = gpo_guid_to_dn or {}

    # Reconstruct gPLink from Links array, using real GPO DNs when available
    gplink_parts = []
    for link in bh_obj.get("Links", []):
        guid = link.get("GUID", "")
        enforced = link.get("IsEnforced", False)
        status = 2 if enforced else 0
        if guid:
            # Prefer real DN over hash-based GUID for graph builder compatibility
            dn_or_guid = gpo_map.get(guid, guid)
            gplink_parts.append(f"[LDAP://{dn_or_guid};{status}]")
    gplink_str = "".join(gplink_parts)

    return {
        "dn": props.get("distinguishedname", ""),
        "name": (props.get("name", "") or "").split("@")[0],
        "object_sid": bh_obj.get("ObjectIdentifier", ""),
        "object_class": "ou",
        "owner_sid": "",
        "properties": {
            "description": props.get("description", ""),
            "gPLink": gplink_str,
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_certtemplate(bh_obj: dict[str, Any], domain: str) -> dict[str, Any]:
    """Convert a BloodHound CE certificate template to LazyHound format.

    BloodHound stores parsed booleans/enums; the analyzer's ADCS checks read
    the raw msPKI-* flags, so we synthesise them here.
    """
    p = bh_obj.get("Properties", {})
    name_flag = 0x1 if p.get("enrolleesuppliessubject") else 0
    enroll_flag = 0
    if p.get("requiresmanagerapproval"):
        enroll_flag |= 0x2          # PEND_ALL_REQUESTS (manager approval)
    if p.get("nosecurityextension"):
        enroll_flag |= 0x80000      # CT_FLAG_NO_SECURITY_EXTENSION
    ekus = p.get("ekus") or p.get("effectiveekus") or []
    try:
        ra_sig = int(p.get("authorizedsignatures", 0) or 0)
    except (ValueError, TypeError):
        ra_sig = 0
    return {
        "dn": p.get("distinguishedname", ""),
        "name": (p.get("name", "") or "").split("@")[0],
        "object_sid": bh_obj.get("ObjectIdentifier", ""),
        "object_class": "certtemplate",
        "owner_sid": "",
        "properties": {
            "msPKI-Certificate-Name-Flag": name_flag,
            "msPKI-Enrollment-Flag": enroll_flag,
            "msPKI-RA-Signature": ra_sig,
            "msPKI-Template-Schema-Version": p.get("schemaversion", 0),
            "pKIExtendedKeyUsage": ekus,
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_enterpriseca(bh_obj: dict[str, Any], domain: str) -> dict[str, Any]:
    """Convert a BloodHound CE enterprise CA to LazyHound 'pki' format."""
    p = bh_obj.get("Properties", {})
    try:
        flags = int(p.get("flags", 0) or 0)
    except (ValueError, TypeError):
        flags = 0
    return {
        "dn": p.get("distinguishedname", ""),
        "name": (p.get("name", "") or "").split("@")[0],
        "object_sid": bh_obj.get("ObjectIdentifier", ""),
        "object_class": "pki",
        "owner_sid": "",
        "properties": {
            "flags": flags,
            "dNSHostName": p.get("dnshostname", ""),
            "caName": p.get("caname", ""),
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_gpo(bh_obj: dict[str, Any], domain: str) -> dict[str, Any]:
    """Convert a BloodHound CE GPO back to LazyHound format."""
    props = bh_obj.get("Properties", {})

    return {
        "dn": props.get("distinguishedname", ""),
        "name": (props.get("name", "") or "").split("@")[0],
        "object_sid": bh_obj.get("ObjectIdentifier", ""),
        "object_class": "gpo",
        "owner_sid": "",
        "properties": {
            "displayName": props.get("name", "").split("@")[0] if props.get("name") else "",
            "gPCFileSysPath": props.get("gpcpath", ""),
        },
        "dacl": _import_aces(bh_obj.get("Aces", [])),
    }


def _import_trusts(bh_domain: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    """Extract trust objects from a BH domain's Trusts array."""
    trust_objs: list[dict[str, Any]] = []
    for t in bh_domain.get("Trusts", []):
        direction_str = t.get("TrustDirection", "")
        direction_map = {"Disabled": 0, "Inbound": 1, "Outbound": 2, "Bidirectional": 3}
        direction = direction_map.get(direction_str, 0)

        type_str = t.get("TrustType", "")
        type_map = {"WINDOWS_NON_ACTIVE_DIRECTORY": 1, "WINDOWS_ACTIVE_DIRECTORY": 2, "MIT": 3}
        trust_type = type_map.get(type_str, 2)

        attrs = 0
        if not t.get("IsTransitive", True):
            attrs |= 0x01  # NON_TRANSITIVE
        if t.get("SidFilteringEnabled", False):
            attrs |= 0x04

        trust_objs.append({
            "dn": "",
            "name": t.get("TargetDomainName", ""),
            "object_sid": t.get("TargetDomainSid", ""),
            "object_class": "trusteddomain",
            "owner_sid": "",
            "properties": {
                "trustDirection": direction,
                "trustType": trust_type,
                "trustAttributes": attrs,
                "securityIdentifier": t.get("TargetDomainSid", ""),
            },
            "dacl": [],
        })
    return trust_objs


# BloodHound local-group RID -> lazyhound lateral-movement edge type
_LOCAL_GROUP_RID_EDGE = {
    "544": "AdminTo",       # Administrators
    "555": "CanRDP",        # Remote Desktop Users
    "562": "ExecuteDCOM",   # Distributed COM Users
    "580": "CanPSRemote",   # Remote Management Users
}
# Legacy BloodHound per-group fields -> edge type
_LEGACY_LOCALGROUP_FIELDS = {
    "LocalAdmins": "AdminTo",
    "RemoteDesktopUsers": "CanRDP",
    "DcomUsers": "ExecuteDCOM",
    "PSRemoteUsers": "CanPSRemote",
}


def _bh_results(block: Any) -> list:
    """Normalize a BloodHound member/session block to a list of result dicts."""
    if isinstance(block, dict):
        return block.get("Results", []) or []
    if isinstance(block, list):
        return block
    return []


def _extract_bh_network_data(bh_computers: list[dict[str, Any]],
                             sid_map: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """Extract Sessions and local-group memberships from BH computer objects.

    Returns (sessions, local_group_members) in lazyhound's schema:
      sessions:            {username, target_host, user_sid}
      local_group_members: {edge_type, member_sid, member_name, target_host}
    Names are resolved via sid_map so the analyzer's host/user lookups match.
    """
    sessions: list[dict] = []
    local_group_members: list[dict] = []
    for c in bh_computers:
        comp_sid = c.get("ObjectIdentifier", "")
        comp_name = (sid_map.get(comp_sid)
                     or (c.get("Properties", {}) or {}).get("name", "")
                     or comp_sid)

        for key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
            for s in _bh_results(c.get(key)):
                usid = s.get("UserSID") or s.get("UserId") or ""
                if not usid:
                    continue
                csid = s.get("ComputerSID") or comp_sid
                host = sid_map.get(csid) or comp_name
                sessions.append({
                    "username": sid_map.get(usid, usid),
                    "target_host": host,
                    "user_sid": usid,
                })

        for lg in (c.get("LocalGroups") or []):
            gid = lg.get("ObjectIdentifier", "") or ""
            edge = _LOCAL_GROUP_RID_EDGE.get(gid.rsplit("-", 1)[-1] if gid else "")
            if not edge:
                continue
            for m in _bh_results(lg):
                msid = m.get("ObjectIdentifier") or ""
                if msid:
                    local_group_members.append({
                        "edge_type": edge, "member_sid": msid,
                        "member_name": sid_map.get(msid, msid), "target_host": comp_name,
                    })

        for field, edge in _LEGACY_LOCALGROUP_FIELDS.items():
            for m in _bh_results(c.get(field)):
                msid = m.get("ObjectIdentifier") or m.get("MemberId") or ""
                if msid:
                    local_group_members.append({
                        "edge_type": edge, "member_sid": msid,
                        "member_name": sid_map.get(msid, msid), "target_host": comp_name,
                    })

    return sessions, local_group_members


def import_bloodhound(
    input_path: str | Path,
    output_path: str | Path | None = None,
) -> Path:
    """Import a BloodHound CE ZIP or JSON file into LazyHound collection format.

    Supports:
    - BloodHound CE ZIP exports (containing typed JSON files)
    - Individual BH CE JSON files (users.json, groups.json, etc.)

    Returns:
        Path to the written LazyHound collection JSON file.
    """
    inp = Path(input_path)
    if not inp.exists():
        raise FileNotFoundError(f"BloodHound file not found: {inp}")

    # Load BH data keyed by type
    bh_data: dict[str, list[dict[str, Any]]] = {}

    if inp.suffix.lower() == ".zip" or zipfile.is_zipfile(str(inp)):
        try:
            with zipfile.ZipFile(inp, "r") as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    raw = json.loads(zf.read(name))
                    data_type = raw.get("meta", {}).get("type", "")
                    if not data_type:
                        # Try to infer from filename
                        lower = name.lower()
                        for t in ("users", "groups", "computers", "domains", "ous", "gpos"):
                            if t in lower:
                                data_type = t
                                break
                    if data_type:
                        items = raw.get("data", [])
                        bh_data.setdefault(data_type, []).extend(items)
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Corrupted or invalid ZIP file: {inp} — {exc}") from exc
    else:
        # Single JSON file
        with inp.open() as f:
            raw = json.load(f)
        data_type = raw.get("meta", {}).get("type", "")
        if data_type:
            bh_data[data_type] = raw.get("data", [])
        elif isinstance(raw, list):
            # Bare array of BH objects without envelope — infer type per object
            _type_hints = {
                "user": "users", "group": "groups", "computer": "computers",
                "domain": "domains", "ou": "ous", "gpo": "gpos",
            }
            for item in raw:
                if not isinstance(item, dict):
                    continue
                obj_type = (
                    item.get("Properties", {}).get("objectclass", "")
                    or item.get("ObjectType", "")
                ).lower()
                mapped = _type_hints.get(obj_type, "")
                if mapped:
                    bh_data.setdefault(mapped, []).append(item)
                else:
                    import logging
                    logging.getLogger(__name__).warning(
                        "Skipping bare-array object with unrecognised type %r", obj_type
                    )

    if not bh_data:
        raise ValueError("No valid BloodHound CE data found in the input file.")

    # Detect domain from domain objects or properties
    domain = "unknown.local"
    domain_sid = ""
    for d in bh_data.get("domains", []):
        p = d.get("Properties", {})
        if p.get("name"):
            domain = p["name"].lower()
        if d.get("ObjectIdentifier"):
            domain_sid = d["ObjectIdentifier"]
        break

    # If no domain object, try to extract from any object's Properties.domain
    if domain == "unknown.local":
        for type_key, items in bh_data.items():
            for item in items:
                d_name = item.get("Properties", {}).get("domain", "")
                if d_name:
                    domain = d_name.lower()
                    break
            if domain != "unknown.local":
                break

    # Build a GUID → DN map from GPOs so OU gPLink reconstruction can use real DNs
    gpo_guid_to_dn: dict[str, str] = {}
    for gpo_obj in bh_data.get("gpos", []):
        gpo_dn = gpo_obj.get("Properties", {}).get("distinguishedname", "")
        gpo_oid = gpo_obj.get("ObjectIdentifier", "")
        if gpo_oid and gpo_dn:
            gpo_guid_to_dn[gpo_oid] = gpo_dn

    # Convert each type
    objects: list[dict[str, Any]] = []
    sid_map: dict[str, str] = {}

    converters = {
        "users": _import_user,
        "groups": _import_group,
        "computers": _import_computer,
        "domains": _import_domain,
        "ous": _import_ou,
        "gpos": _import_gpo,
        "certtemplates": _import_certtemplate,
        "enterprisecas": _import_enterpriseca,
    }

    for data_type, items in bh_data.items():
        converter = converters.get(data_type)
        if not converter:
            continue
        for bh_obj in items:
            if data_type in ("ous", "domains"):
                obj = converter(bh_obj, domain, gpo_guid_to_dn=gpo_guid_to_dn)
            else:
                obj = converter(bh_obj, domain)
            objects.append(obj)

            # Build sid_map entry
            sid = obj.get("object_sid", "")
            name = obj.get("name", "")
            if sid and name:
                sid_map[sid] = name

    # Extract trust objects from domain entries
    for d in bh_data.get("domains", []):
        trust_objs = _import_trusts(d, domain)
        objects.extend(trust_objs)
        for t in trust_objs:
            if t["object_sid"] and t["name"]:
                sid_map[t["object_sid"]] = t["name"]

    # Build the LazyHound collection
    collection: dict[str, Any] = {
        "meta": {
            "domain": domain,
            "dc": "",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collection_method": "bloodhound-import",
            "object_count": len(objects),
        },
        "objects": objects,
        "sid_map": sid_map,
    }

    # Sessions + local-group memberships (HasSession / AdminTo / CanRDP / ...)
    sessions, local_group_members = _extract_bh_network_data(
        bh_data.get("computers", []), sid_map)
    if sessions:
        collection["sessions"] = sessions
    if local_group_members:
        collection["local_group_members"] = local_group_members

    # Write output
    if output_path is None:
        output_path = inp.parent / (inp.stem + ".adpf.json")
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        json.dump(collection, f, indent=2, default=str)

    return out


def export_from_file(input_path: str | Path, output_path: str | Path | None = None) -> Path:
    """Load a collection JSON file and export as BloodHound CE ZIP.

    Args:
        input_path: Path to LazyHound collection JSON.
        output_path: Path for output ZIP (default: same dir, .bh.zip suffix).

    Returns:
        Path to the written ZIP file.
    """
    inp = Path(input_path)
    if not inp.exists():
        raise FileNotFoundError(f"Collection file not found: {inp}")

    with inp.open() as f:
        collection = json.load(f)

    if output_path is None:
        output_path = inp.parent / (inp.stem + ".bh.zip")

    return export_zip(collection, output_path)

"""Reconstruct AzureHound-format JSON from a lazyhound collection.

Inverse of azure_ingestor: azure objects -> {kind,data} entries; flat
azure_edges -> AzureHound container entries. Symmetric with bh_converter.export_zip.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .azure_ingestor import (
    _KIND_TO_CLASS, _OWNER_TARGET_FIELD,
    _KIND_SUB_ROLE, _KIND_RG_ROLE, _KIND_VM_ROLE, _KIND_KV_ROLE,
)

AZUREHOUND_SCHEMA_VERSION = "v2.1.10"   # validated against entra_sampledata

# Single source of truth: invert the ingestor's map.
_CLASS_TO_KIND = {v: k for k, v in _KIND_TO_CLASS.items()}

_CLASS_TO_OWNER_KIND = {
    "aad_group": "AZGroupOwner",
    "aad_app": "AZAppOwner",
    "aad_sp": "AZServicePrincipalOwner",
    "aad_device": "AZDeviceOwner",
}
_CLASS_TO_RM_ROLE_KIND = {
    "azure_sub": _KIND_SUB_ROLE,
    "azure_rg": _KIND_RG_ROLE,
    "azure_vm": _KIND_VM_ROLE,
    "azure_kv": _KIND_KV_ROLE,
}
# Edges the ingestor re-derives from object properties (not from azurehound
# relationship entries), so exporting them would duplicate on re-ingest.
_DERIVED_EDGE_TYPES = {"AZRunsAs", "AZManagedIdentity"}

# Edge labels produced by the ingestor's AzureRM parsing.
_ARM_ROLE_LABELS = {
    "AZOwner", "AZContributor", "AZUserAccessAdministrator", "AZVMContributor",
    "AZKeyVaultContributor", "AZKeyVaultAdministrator", "AZVMAdminLogin",
    "AZAvereContributor", "AZRoleAssignment",
}


@dataclass
class ExportResult:
    path: Path
    entries: int
    degraded: int


def _azure_objects(collection: dict) -> list[dict]:
    return [o for o in collection.get("objects", [])
            if o.get("object_class") in _CLASS_TO_KIND]


def _object_entry(obj: dict) -> dict | None:
    kind = _CLASS_TO_KIND.get(obj.get("object_class", ""))
    oid = obj.get("object_sid", "")
    if not kind or not oid:
        return None
    data = {k: v for k, v in (obj.get("properties") or {}).items()
            if not k.startswith("_")}
    data.setdefault("id", oid)
    return {"kind": kind, "data": data}


def _class_of(obj_by_id: dict, sid: str) -> str:
    obj = obj_by_id.get(sid)
    return obj.get("object_class", "") if obj else ""


def _reconstruct_edges(edges: list[dict], obj_by_id: dict) -> tuple[list[dict], int]:
    """Re-aggregate flat azure_edges into AzureHound container entries.
    Returns (entries, degraded_count). Excludes SyncedTo* (lazyhound-synthetic)."""
    entries: list[dict] = []
    degraded = 0

    members: dict[str, list[str]] = {}        # group -> [member,...]
    owners: dict[str, list[str]] = {}         # resource -> [owner,...]
    role_assignments: list[dict] = []         # Entra AZHasRole
    pim_assignments: list[dict] = []          # AZPIMEligible
    rm_roles: dict[str, list[dict]] = {}      # resource -> [assignment item,...]

    for e in edges:
        et = e.get("edge_type", "")
        src = e.get("source_id", "")
        tgt = e.get("target_id", "")
        props = e.get("properties") or {}
        # Intentionally not exported: lazyhound-synthetic bridges and edges the
        # ingestor re-derives from object properties (AZRunsAs/AZManagedIdentity).
        if et.startswith("SyncedTo") or et in _DERIVED_EDGE_TYPES:
            continue
        # Malformed edge (missing endpoints/type): count, never crash.
        if not et or not src or not tgt:
            degraded += 1
            continue
        if et == "AZMemberOf":
            members.setdefault(tgt, []).append(src)
        elif et == "AZOwns":
            owners.setdefault(tgt, []).append(src)
        elif et == "AZHasRole":
            role_assignments.append({
                "principalId": src, "directoryScopeId": tgt,
                "roleDefinitionId": props.get("roleDefinitionId", "")})
        elif et == "AZPIMEligible":
            pim_assignments.append({
                "principalId": src, "directoryScopeId": tgt,
                "roleDefinitionId": props.get("roleTemplateId", "")})
        elif et == "AZKeyVaultAccessPolicy":
            entries.append({"kind": "AZKeyVaultAccessPolicy", "data": {
                "keyVaultId": tgt,
                "accessPolicy": {"objectId": src,
                                 "permissions": props.get("permissions", {})}}})
        elif et == "AZAppRoleAssignment":
            entries.append({"kind": "AZAppRoleAssignment", "data": {
                "principalId": src, "resourceId": tgt,
                "appRoleId": props.get("appRoleId", "")}})
        elif et in _ARM_ROLE_LABELS:
            rm_roles.setdefault(tgt, []).append({
                "roleAssignment": {"properties": {
                    "principalId": src,
                    "roleDefinitionId": props.get("roleDefinitionId", "")}},
                "resourceId": tgt})
        else:
            # Genuinely unknown edge type — count so nothing vanishes silently.
            degraded += 1

    for gid, mids in members.items():
        entries.append({"kind": "AZGroupMember",
                        "data": {"groupId": gid,
                                 "members": [{"member": m} for m in mids]}})
    for tgt, oids in owners.items():
        kind = _CLASS_TO_OWNER_KIND.get(_class_of(obj_by_id, tgt))
        if not kind:
            degraded += 1
            continue
        entries.append({"kind": kind,
                        "data": {_OWNER_TARGET_FIELD[kind]: tgt,
                                 "owners": [{"owner": o} for o in oids]}})
    if role_assignments:
        entries.append({"kind": "AZRoleAssignment",
                        "data": {"roleAssignments": role_assignments}})
    if pim_assignments:
        entries.append({"kind": "AZRoleEligibilityScheduleInstance",
                        "data": {"roleAssignments": pim_assignments}})
    for resid, items in rm_roles.items():
        kind = _CLASS_TO_RM_ROLE_KIND.get(_class_of(obj_by_id, resid))
        if not kind:
            degraded += 1
            continue
        entries.append({"kind": kind, "data": {"roleAssignments": items}})
    return entries, degraded


def build_azurehound_payload(collection: dict) -> tuple[dict, int]:
    objs = _azure_objects(collection)
    obj_by_id = {o["object_sid"]: o for o in objs}
    degraded = 0

    entries: list[dict] = []
    for o in objs:
        entry = _object_entry(o)
        if entry is None:
            degraded += 1
            continue
        entries.append(entry)

    edge_entries, edge_degraded = _reconstruct_edges(
        collection.get("azure_edges", []), obj_by_id)
    entries.extend(edge_entries)
    degraded += edge_degraded

    # deterministic ordering: stable regardless of dict/iteration order
    entries.sort(key=lambda e: (e["kind"], json.dumps(e["data"], sort_keys=True)))

    payload = {
        "meta": {"type": "azure", "count": len(entries),
                 "version": AZUREHOUND_SCHEMA_VERSION},
        "data": entries,
    }
    return payload, degraded


def export_azurehound(collection: dict, output_path) -> ExportResult:
    payload, degraded = build_azurehound_payload(collection)
    path = Path(output_path)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return ExportResult(path=path, entries=len(payload["data"]), degraded=degraded)

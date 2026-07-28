"""AzureHound data ingestor.

Parses AzureHound JSON output files (``azurehound list -o output.json``),
normalises the data into LazyHound's collection schema, and optionally
merges it with an existing AD collection to produce a unified hybrid dataset.

The hybrid dataset enables cross-realm attack path analysis by linking
Entra ID users to their on-premises AD counterparts via
``SyncedToEntraUser`` / ``SyncedToADUser`` edges.

Usage::

    lazyhound ingest-azurehound \\
        --azurehound-file azurehound-output.json \\
        --collection corp.local_dconly.json \\
        --output corp.local_hybrid.json
"""

from __future__ import annotations

import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AzureHound ``kind`` values we ingest
# ---------------------------------------------------------------------------
# Identity objects
_KIND_USER = "AZUser"
_KIND_GROUP = "AZGroup"
_KIND_APP = "AZApp"
_KIND_SERVICE_PRINCIPAL = "AZServicePrincipal"
_KIND_DEVICE = "AZDevice"

# Relationships
_KIND_GROUP_MEMBER = "AZGroupMember"
_KIND_GROUP_OWNER = "AZGroupOwner"
_KIND_APP_OWNER = "AZAppOwner"
_KIND_SP_OWNER = "AZServicePrincipalOwner"
_KIND_DEVICE_OWNER = "AZDeviceOwner"

# Roles
_KIND_ROLE = "AZRole"
_KIND_ROLE_ASSIGNMENT = "AZRoleAssignment"

# Azure resources
_KIND_TENANT = "AZTenant"
_KIND_SUBSCRIPTION = "AZSubscription"
_KIND_RESOURCE_GROUP = "AZResourceGroup"
_KIND_VM = "AZVM"
_KIND_KEY_VAULT = "AZKeyVault"
_KIND_KV_ACCESS_POLICY = "AZKeyVaultAccessPolicy"

# Role-based resource assignments
_KIND_SUB_ROLE = "AZSubscriptionRoleAssignment"
_KIND_RG_ROLE = "AZResourceGroupRoleAssignment"
_KIND_VM_ROLE = "AZVMRoleAssignment"
_KIND_KV_ROLE = "AZKeyVaultRoleAssignment"

# App role assignments & PIM
_KIND_APP_ROLE_ASSIGNMENT = "AZAppRoleAssignment"
_KIND_PIM_ELIGIBLE = "AZRoleEligibilityScheduleInstance"

# Tenant policy / config objects (collected by lazyhound's Entra collector,
# not standard AzureHound)
_KIND_CA_POLICY = "AZConditionalAccessPolicy"
_KIND_DOMAIN = "AZDomain"
_KIND_XTENANT = "AZCrossTenantPartner"

# Kinds that produce node objects
_NODE_KINDS = {
    _KIND_USER, _KIND_GROUP, _KIND_APP, _KIND_SERVICE_PRINCIPAL,
    _KIND_DEVICE, _KIND_TENANT, _KIND_SUBSCRIPTION,
    _KIND_RESOURCE_GROUP, _KIND_VM, _KIND_KEY_VAULT, _KIND_CA_POLICY,
    _KIND_DOMAIN, _KIND_XTENANT,
}

# Kinds that produce edges/relationships
_EDGE_KINDS = {
    _KIND_GROUP_MEMBER, _KIND_GROUP_OWNER, _KIND_APP_OWNER,
    _KIND_SP_OWNER, _KIND_DEVICE_OWNER, _KIND_ROLE,
    _KIND_ROLE_ASSIGNMENT, _KIND_SUB_ROLE, _KIND_RG_ROLE,
    _KIND_VM_ROLE, _KIND_KV_ROLE, _KIND_KV_ACCESS_POLICY,
    _KIND_APP_ROLE_ASSIGNMENT, _KIND_PIM_ELIGIBLE,
}

# Map AzureHound kind → lazyhound finder object_class
_KIND_TO_CLASS: dict[str, str] = {
    _KIND_USER: "aad_user",
    _KIND_GROUP: "aad_group",
    _KIND_APP: "aad_app",
    _KIND_SERVICE_PRINCIPAL: "aad_sp",
    _KIND_DEVICE: "aad_device",
    _KIND_TENANT: "azure_tenant",
    _KIND_SUBSCRIPTION: "azure_sub",
    _KIND_RESOURCE_GROUP: "azure_rg",
    _KIND_VM: "azure_vm",
    _KIND_KEY_VAULT: "azure_kv",
    _KIND_CA_POLICY: "aad_ca_policy",
    _KIND_DOMAIN: "aad_domain",
    _KIND_XTENANT: "aad_xtenant_partner",
}

# Well-known Entra directory role template IDs → display names
_ENTRA_ROLE_TEMPLATES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "7698a772-787b-4ac8-901f-60d6b08affd2": "Cloud Device Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "44367163-eba1-44c3-98af-f5787879f96a": "Dynamics 365 Administrator",
    "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b": "Enterprise Administrator (Entra Connect)",
}

# High-value Entra roles (compromise = tenant takeover or near-equivalent)
_HIGHVALUE_ENTRA_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
}

# Canonical display name per high-value role template id.
_HIGHVALUE_ENTRA_ROLE_NAMES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
}

# Accurate, role-specific consequence — what holding the role actually grants.
# Keyed by role template id so wording is stable regardless of AzureHound's
# roleName string. "Direct" roles == immediate takeover; the others state the
# concrete escalation rather than a blanket "full tenant control".
_ENTRA_ROLE_IMPACT = {
    "62e90394-69f5-4237-9190-012177145e10":
        "grants full control of the Entra tenant and all Microsoft 365 services",
    "e8611ab8-c189-46e8-94e1-60213ab1f814":
        "can assign any Entra role — including Global Administrator — to any "
        "principal, i.e. full tenant takeover",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13":
        "can reset credentials and MFA for any user including Global "
        "Administrators, i.e. full tenant takeover",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3":
        "can add credentials to any service principal; where a privileged app "
        "exists this escalates to Global Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7":
        "can add credentials to any service principal; where a privileged app "
        "exists this escalates to Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d":
        "controls tenant-wide security and Conditional Access policy and can "
        "weaken or bypass MFA and access controls",
}


def entra_role_info(template_id: str, role_name: str = "") -> tuple[str, str]:
    """Return (canonical role name, accurate impact clause) for a role.

    Falls back to the supplied ``role_name`` and a generic clause for roles
    not in the high-value table."""
    name = _HIGHVALUE_ENTRA_ROLE_NAMES.get(template_id) or role_name or "a privileged role"
    impact = _ENTRA_ROLE_IMPACT.get(
        template_id, "grants privileged control over the Entra tenant")
    return name, impact


# ---------------------------------------------------------------------------
# Parsing AzureHound output
# ---------------------------------------------------------------------------
def load_azurehound_file(path: str | Path) -> list[dict[str, Any]]:
    """Load an AzureHound JSON output file.

    AzureHound produces either:
      - A JSON array of ``{kind, data}`` objects, or
      - Newline-delimited JSON (NDJSON) where each line is ``{kind, data}``.

    Returns a list of raw ``{kind, data}`` dicts.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"AzureHound file not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    text = text.strip()

    if not text:
        return []

    # Try JSON array first
    if text.startswith("["):
        try:
            entries = json.loads(text)
            if isinstance(entries, list):
                return entries
        except json.JSONDecodeError:
            pass

    # Real AzureHound output is a wrapped object: {"meta": {...}, "data": [ ... ]}
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                if isinstance(obj.get("data"), list):
                    return obj["data"]
                if "kind" in obj:  # a single {kind, data} entry
                    return [obj]
        except json.JSONDecodeError:
            pass

    # Try NDJSON (one JSON object per line)
    entries: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                entries.append(obj)
        except json.JSONDecodeError:
            logger.debug("Skipping malformed JSON at line %d", lineno)
    return entries


def _extract_id(data: dict[str, Any]) -> str:
    """Extract the primary identifier from an AzureHound data object.

    AzureHound uses ``id`` for most objects, but some use other keys
    (cross-tenant access partners are keyed only by ``tenantId``).
    """
    return str(data.get("id") or data.get("objectId") or data.get("tenantId") or "")


def _extract_name(data: dict[str, Any], kind: str) -> str:
    """Extract a display name from an AzureHound data object."""
    if kind == _KIND_USER:
        return (
            data.get("userPrincipalName")
            or data.get("displayName")
            or data.get("mail")
            or _extract_id(data)
        )
    if kind == _KIND_SERVICE_PRINCIPAL:
        return data.get("displayName") or data.get("appDisplayName") or _extract_id(data)
    return data.get("displayName") or data.get("name") or _extract_id(data)


# ---------------------------------------------------------------------------
# Normalisation to LazyHound schema
# ---------------------------------------------------------------------------
def _normalise_node(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Convert an AzureHound node entry to LazyHound object format.

    Returns None if the entry is not a recognised node kind.
    """
    kind = entry.get("kind", "")
    if kind not in _KIND_TO_CLASS:
        return None

    data = entry.get("data", {})
    obj_id = _extract_id(data)
    if not obj_id:
        return None

    obj_class = _KIND_TO_CLASS[kind]
    name = _extract_name(data, kind)
    tenant_id = data.get("tenantId", "")
    tenant_name = data.get("tenantName", "")

    # Build properties — keep all raw data as properties for query flexibility
    properties: dict[str, Any] = {}
    for key, val in data.items():
        if val is None or val == "" or val == []:
            continue
        properties[key] = val

    # Add tenant info
    if tenant_id:
        properties["tenantId"] = tenant_id
    if tenant_name:
        properties["tenantName"] = tenant_name

    # Mark synced users
    if kind == _KIND_USER:
        properties["_onPremSyncEnabled"] = bool(data.get("onPremisesSyncEnabled"))
        properties["_onPremSid"] = data.get("onPremisesSecurityIdentifier") or ""

    return {
        "dn": f"AZ://{obj_class}/{obj_id}",
        "name": name,
        "object_sid": obj_id,
        "object_class": obj_class,
        "owner_sid": None,
        "properties": properties,
        "dacl": [],
    }


# AzureRM built-in role definition GUIDs -> escalation-relevant edge labels
_AZURERM_ROLE_LABELS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "AZOwner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "AZContributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "AZUserAccessAdministrator",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "AZVMContributor",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "AZKeyVaultAdministrator",
}


def _azurerm_edge_label(role_definition_id: str) -> str:
    """Map an AzureRM roleDefinitionId (full ARM path) to a specific edge label."""
    guid = (role_definition_id or "").rsplit("/", 1)[-1].lower()
    return _AZURERM_ROLE_LABELS.get(guid, "AZRoleAssignment")


def _member_node_id(m):
    """Extract an object id from a member/owner payload (dict or raw id)."""
    if isinstance(m, dict):
        return m.get("id") or _extract_id(m)
    return str(m) if m else ""


_ROLE_SUFFIX_LABELS = [
    # Resource-specific variants must precede the generic "Contributor".
    ("VMContributor", "AZVMContributor"),
    ("KVContributor", "AZKeyVaultContributor"),
    ("AvereContributor", "AZAvereContributor"),
    ("AdminLogin", "AZVMAdminLogin"),
    ("UserAccessAdmin", "AZUserAccessAdministrator"),
    ("Contributor", "AZContributor"),
    ("Owner", "AZOwner"),
    ("RoleAssignment", "AZRoleAssignment"),
]

_OWNER_TARGET_FIELD = {
    "AZGroupOwner": "groupId",
    "AZAppOwner": "appId",
    "AZServicePrincipalOwner": "servicePrincipalId",
    "AZDeviceOwner": "deviceId",
}

# Kinds with dedicated branches below — excluded from generic suffix matching.
_SPECIFIC_EDGE_KINDS = {
    "AZGroupMember", "AZRoleAssignment", "AZKeyVaultAccessPolicy",
    "AZAppRoleAssignment", "AZRoleEligibilityScheduleInstance",
} | set(_OWNER_TARGET_FIELD)


def _azurerm_kind_label(kind: str) -> str:
    """Map a per-(resource,role) AzureRM kind (AZVMContributor, AZSubscriptionOwner,
    AZKeyVaultUserAccessAdmin, ...) to an escalation edge label."""
    if not kind.startswith("AZ") or kind in _SPECIFIC_EDGE_KINDS:
        return ""
    for suffix, label in _ROLE_SUFFIX_LABELS:
        if kind.endswith(suffix):
            return label
    return ""


def _first_list(data: dict) -> list:
    for v in data.values():
        if isinstance(v, list):
            return v
    return []


def _principal_and_role_from_item(item: dict):
    for v in item.values():
        if isinstance(v, dict) and isinstance(v.get("properties"), dict):
            props = v["properties"]
            return props.get("principalId", ""), props.get("roleDefinitionId", "")
    return "", ""


def _resource_id_from_item(item: dict) -> str:
    for v in item.values():
        if isinstance(v, str) and v.startswith("/"):
            return v
    return ""


def _edge(edge_type: str, src: str, dst: str, props=None) -> dict[str, Any]:
    return {"edge_type": edge_type, "source_id": src, "target_id": dst,
            "properties": props or {}}


def _normalise_edges(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert an AzureHound relationship entry into zero or more edges.

    Matches the real AzureHound container-with-list shapes (members[]/owners[]/
    roleAssignments[]) and the per-(resource, role) AzureRM kinds.
    """
    kind = entry.get("kind", "")
    data = entry.get("data", {}) or {}
    edges: list[dict[str, Any]] = []

    if kind == _KIND_GROUP_MEMBER:
        gid = data.get("groupId", "")
        for m in data.get("members") or []:
            mid = _member_node_id(m.get("member") if isinstance(m, dict) else m)
            if mid and gid:
                edges.append(_edge("AZMemberOf", mid, gid))

    elif kind in _OWNER_TARGET_FIELD:
        tgt = data.get(_OWNER_TARGET_FIELD[kind], "")
        for o in data.get("owners") or []:
            oid = _member_node_id(o.get("owner") if isinstance(o, dict) else o)
            if oid and tgt:
                edges.append(_edge("AZOwns", oid, tgt))

    elif kind == _KIND_ROLE_ASSIGNMENT:  # Entra directory role assignments
        for a in data.get("roleAssignments") or []:
            if not isinstance(a, dict):
                continue
            pid = a.get("principalId", "")
            rtid = a.get("roleDefinitionId", "") or data.get("roleDefinitionId", "")
            if pid:
                edges.append(_edge("AZHasRole", pid, a.get("directoryScopeId", "/"),
                                   {"roleTemplateId": rtid, "roleDefinitionId": rtid}))

    elif kind == _KIND_KV_ACCESS_POLICY:
        ap = data.get("accessPolicy", data)
        src = ap.get("objectId", "") if isinstance(ap, dict) else ""
        tgt = data.get("keyVaultId", "")
        if src and tgt:
            edges.append(_edge("AZKeyVaultAccessPolicy", src, tgt,
                               {"permissions": ap.get("permissions", {})
                                if isinstance(ap, dict) else {}}))

    elif kind == _KIND_APP_ROLE_ASSIGNMENT:
        src = data.get("principalId", "")
        tgt = data.get("resourceId", "")
        if src and tgt:
            edges.append(_edge("AZAppRoleAssignment", src, tgt,
                               {"appRoleId": data.get("appRoleId", "")}))

    elif kind == _KIND_PIM_ELIGIBLE:
        for a in (data.get("roleAssignments") or [data]):
            if not isinstance(a, dict):
                continue
            pid = a.get("principalId", "")
            if pid:
                edges.append(_edge("AZPIMEligible", pid, a.get("directoryScopeId", "/"),
                                   {"roleTemplateId": a.get("roleDefinitionId", "")
                                    or data.get("roleDefinitionId", "")}))

    else:
        label = _azurerm_kind_label(kind)
        if label:
            for item in _first_list(data):
                if not isinstance(item, dict):
                    continue
                pid, rdid = _principal_and_role_from_item(item)
                resid = _resource_id_from_item(item)
                if pid and resid:
                    final = _azurerm_edge_label(rdid) if (label == "AZRoleAssignment" and rdid) else label
                    edges.append(_edge(final, pid, resid, {"roleDefinitionId": rdid}))

    return [e for e in edges if e["source_id"] and e["target_id"]]


def _normalise_edge(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Back-compat shim: first edge for an entry, or None."""
    edges = _normalise_edges(entry)
    return edges[0] if edges else None


def _tenant_primary_domain(tenant_data: dict[str, Any]) -> str:
    """Best FQDN for a tenant from AZTenant.verifiedDomains: the default domain
    (e.g. mydomain.local), else the initial *.onmicrosoft.com, else the first."""
    doms = tenant_data.get("verifiedDomains") or []
    if not isinstance(doms, list):
        return ""
    names = [d.get("name", "") for d in doms if isinstance(d, dict) and d.get("name")]
    default = next((d.get("name", "") for d in doms
                    if isinstance(d, dict) and d.get("isDefault")), "")
    initial = next((d.get("name", "") for d in doms
                    if isinstance(d, dict) and d.get("isInitial")), "")
    return (default or initial or (names[0] if names else "")).lower()


# ---------------------------------------------------------------------------
# Ingestion pipeline
# ---------------------------------------------------------------------------
class AzureHoundIngestor:
    """Parse, normalise, and merge AzureHound data."""

    def __init__(self) -> None:
        self.azure_objects: list[dict[str, Any]] = []
        self.azure_edges: list[dict[str, Any]] = []
        self.azure_sid_map: dict[str, str] = {}
        self.role_definitions: dict[str, dict[str, Any]] = {}
        self._raw_count = 0
        self._tenant_id: str = ""
        self._tenant_name: str = ""
        self._tenant_domain: str = ""

    def load(self, path: str | Path) -> None:
        """Load and parse an AzureHound output file."""
        entries = load_azurehound_file(path)
        self._raw_count = len(entries)

        for entry in entries:
            kind = entry.get("kind", "")
            data = entry.get("data", {})

            # Capture tenant info
            if kind == _KIND_TENANT:
                self._tenant_id = _extract_id(data)
                self._tenant_name = data.get("displayName", "")
                self._tenant_domain = _tenant_primary_domain(data)

            # Store role definitions for later enrichment
            if kind == _KIND_ROLE:
                role_id = _extract_id(data)
                if role_id:
                    self.role_definitions[role_id] = data

            # Process nodes
            if kind in _NODE_KINDS:
                node = _normalise_node(entry)
                if node:
                    self.azure_objects.append(node)
                    self.azure_sid_map[node["object_sid"]] = node["name"]

            # Process edges (real AzureHound entries can yield many per kind)
            self.azure_edges.extend(_normalise_edges(entry))

        self._derive_identity_edges()

        print(
            f"[+] Parsed {self._raw_count} AzureHound entries: "
            f"{len(self.azure_objects)} objects, {len(self.azure_edges)} edges",
            file=sys.stderr,
        )
        if self._tenant_name:
            print(f"    Tenant: {self._tenant_name} ({self._tenant_id})", file=sys.stderr)

    def _derive_identity_edges(self) -> None:
        """Derive App->SP (AZRunsAs) and resource->managed-identity edges.

        - App registration -> its Service Principal (matched by appId): whoever
          controls the app can add credentials and authenticate as the SP.
        - VM/automation resource -> its managed identity SP (system- and
          user-assigned): compromising the resource lets you act as the MI and
          inherit its role assignments.
        """
        appid_to_sp: dict[str, str] = {}
        for o in self.azure_objects:
            if o.get("object_class") == "aad_sp":
                aid = o.get("properties", {}).get("appId")
                if aid:
                    appid_to_sp[aid] = o["object_sid"]

        for o in self.azure_objects:
            cls = o.get("object_class")
            sid = o.get("object_sid", "")
            props = o.get("properties", {})
            if cls == "aad_app":
                sp = appid_to_sp.get(props.get("appId"))
                if sp and sp != sid:
                    self.azure_edges.append({
                        "edge_type": "AZRunsAs", "source_id": sid,
                        "target_id": sp, "properties": {}})
            ident = props.get("identity")
            if isinstance(ident, dict):
                mis = []
                if ident.get("principalId"):
                    mis.append(ident["principalId"])
                ua = ident.get("userAssignedIdentities")
                if isinstance(ua, dict):
                    for v in ua.values():
                        if isinstance(v, dict) and v.get("principalId"):
                            mis.append(v["principalId"])
                for mi in mis:
                    if mi and mi != sid:
                        self.azure_edges.append({
                            "edge_type": "AZManagedIdentity", "source_id": sid,
                            "target_id": mi, "properties": {}})

    def _enrich_role_edges(self) -> None:
        """Resolve role definition IDs to human-readable names."""
        for edge in self.azure_edges:
            if edge["edge_type"] not in ("AZHasRole", "AZPIMEligible"):
                continue
            props = edge.get("properties", {})
            role_def_id = props.get("roleDefinitionId", "")

            # Try template ID first (for directory roles)
            template_id = props.get("roleTemplateId", "")
            if template_id and template_id in _ENTRA_ROLE_TEMPLATES:
                props["roleName"] = _ENTRA_ROLE_TEMPLATES[template_id]
                props["isHighValue"] = template_id in _HIGHVALUE_ENTRA_ROLES
                continue

            # Try role definitions from collection
            if role_def_id and role_def_id in self.role_definitions:
                role_data = self.role_definitions[role_def_id]
                props["roleName"] = role_data.get("displayName", "")
                template = role_data.get("templateId", "")
                props["isHighValue"] = template in _HIGHVALUE_ENTRA_ROLES

    def detect_synced_users(
        self, ad_collection: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Match Entra users to AD users via onPremisesSecurityIdentifier.

        Returns a list of hybrid edge dicts (SyncedToEntraUser / SyncedToADUser).
        """
        hybrid_edges: list[dict[str, Any]] = []

        # Build AD SID→object map
        ad_sid_map: dict[str, dict[str, Any]] = {}
        for obj in ad_collection.get("objects", []):
            sid = obj.get("object_sid")
            if sid and obj.get("object_class") in ("user", "computer"):
                ad_sid_map[sid] = obj

        synced_count = 0
        for az_obj in self.azure_objects:
            if az_obj["object_class"] != "aad_user":
                continue
            props = az_obj.get("properties", {})
            on_prem_sid = props.get("_onPremSid", "")
            if not on_prem_sid or not props.get("_onPremSyncEnabled"):
                continue

            ad_obj = ad_sid_map.get(on_prem_sid)
            if not ad_obj:
                continue

            synced_count += 1
            entra_id = az_obj["object_sid"]
            ad_sid = ad_obj["object_sid"]

            # Bidirectional edges
            hybrid_edges.append({
                "edge_type": "SyncedToEntraUser",
                "source_id": ad_sid,
                "target_id": entra_id,
                "properties": {
                    "ad_name": ad_obj.get("name", ""),
                    "entra_name": az_obj.get("name", ""),
                    "on_prem_sid": on_prem_sid,
                },
            })
            hybrid_edges.append({
                "edge_type": "SyncedToADUser",
                "source_id": entra_id,
                "target_id": ad_sid,
                "properties": {
                    "ad_name": ad_obj.get("name", ""),
                    "entra_name": az_obj.get("name", ""),
                    "on_prem_sid": on_prem_sid,
                },
            })

        print(
            f"[+] Hybrid sync detection: {synced_count} synced user(s) found, "
            f"{len(hybrid_edges)} edges generated",
            file=sys.stderr,
        )
        return hybrid_edges

    def merge(self, ad_collection: dict[str, Any]) -> dict[str, Any]:
        """Merge Azure data into an existing AD collection.

        Adds ``azure_objects``, ``azure_edges``, and ``hybrid_edges`` keys.
        Updates ``meta`` and ``sid_map``.
        """
        self._enrich_role_edges()
        hybrid_edges = self.detect_synced_users(ad_collection)

        # Fold Azure objects into the unified objects list so they are graph
        # nodes (tenants become Tier Zero, etc.), and unify all edges into
        # azure_edges (AZ* + hybrid SyncedTo*) so the attack graph and the
        # azure/hybrid checks see one consistent set.
        ad_collection.setdefault("objects", []).extend(self.azure_objects)
        ad_collection["azure_objects"] = self.azure_objects  # back-compat
        ad_collection["azure_edges"] = list(self.azure_edges) + list(hybrid_edges)
        ad_collection["hybrid_edges"] = hybrid_edges

        # Merge SID maps
        existing_sid_map = ad_collection.get("sid_map", {})
        existing_sid_map.update(self.azure_sid_map)
        ad_collection["sid_map"] = existing_sid_map

        # Update meta
        meta = ad_collection.get("meta", {})
        existing_method = meta.get("collection_method", "DCOnly")
        meta["collection_method"] = f"{existing_method}+AzureHound"
        meta["azure_stats"] = {
            "raw_entries": self._raw_count,
            "azure_objects": len(self.azure_objects),
            "azure_edges": len(self.azure_edges),
            "hybrid_edges": len(hybrid_edges),
            "synced_users": len(hybrid_edges) // 2,
            "tenant_id": self._tenant_id,
            "tenant_name": self._tenant_name,
            "tenant_domain": self._tenant_domain,
        }
        meta["azure_ingested_at"] = datetime.now(timezone.utc).isoformat()
        ad_collection["meta"] = meta

        return ad_collection

    def to_standalone(self) -> dict[str, Any]:
        """Produce a standalone Azure-only collection (no AD merge)."""
        self._enrich_role_edges()
        return {
            "meta": {
                "domain": self._tenant_domain or self._tenant_name or self._tenant_id or "azure",
                "dc": "AzureHound",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "collection_method": "AzureHound",
                "object_count": len(self.azure_objects),
                "azure_stats": {
                    "raw_entries": self._raw_count,
                    "azure_objects": len(self.azure_objects),
                    "azure_edges": len(self.azure_edges),
                    "tenant_id": self._tenant_id,
                    "tenant_name": self._tenant_name,
                    "tenant_domain": self._tenant_domain,
                },
            },
            "sid_map": dict(self.azure_sid_map),
            "objects": self.azure_objects,
            "azure_objects": self.azure_objects,
            "azure_edges": self.azure_edges,
            "hybrid_edges": [],
        }


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------
def get_synced_users(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return synced user pairs from a hybrid collection.

    Each entry has: ad_sid, ad_name, entra_id, entra_name, on_prem_sid.
    """
    results = []
    for edge in data.get("hybrid_edges", []):
        if edge.get("edge_type") != "SyncedToEntraUser":
            continue
        props = edge.get("properties", {})
        results.append({
            "ad_sid": edge["source_id"],
            "ad_name": props.get("ad_name", ""),
            "entra_id": edge["target_id"],
            "entra_name": props.get("entra_name", ""),
            "on_prem_sid": props.get("on_prem_sid", ""),
        })
    return results


def get_azure_roles(data: dict[str, Any], *, high_value_only: bool = False) -> list[dict[str, Any]]:
    """Return all Entra directory role assignments from a hybrid collection.

    Each entry has: principal_id, principal_name, role_name, is_high_value,
    scope, edge_type (AZHasRole or AZPIMEligible).
    """
    sid_map = data.get("sid_map", {})
    results = []
    for edge in data.get("azure_edges", []):
        if edge["edge_type"] not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {})
        role_name = props.get("roleName", "")
        if not role_name:
            continue
        results.append({
            "principal_id": edge["source_id"],
            "principal_name": sid_map.get(edge["source_id"], edge["source_id"]),
            "role_name": role_name,
            "is_high_value": props.get("isHighValue", False),
            "scope": edge["target_id"],
            "assignment_type": "Eligible (PIM)" if edge["edge_type"] == "AZPIMEligible" else "Active",
        })
    if high_value_only:
        results = [r for r in results if r["is_high_value"]]
    # Sort: high-value first, then by role name
    results.sort(key=lambda r: (not r["is_high_value"], r["role_name"], r["principal_name"]))
    return results


def get_azure_paths_to_highvalue(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Find AD users that have (via sync) high-value Entra roles.

    This is the key hybrid attack path: compromise an AD user whose synced
    Entra identity holds Global Admin or similar.

    Returns list of: ad_sid, ad_name, entra_id, entra_name, role_name.
    """
    # Build entra_id → role assignments
    role_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in data.get("azure_edges", []):
        if edge["edge_type"] not in ("AZHasRole", "AZPIMEligible"):
            continue
        props = edge.get("properties", {})
        if props.get("isHighValue"):
            role_map[edge["source_id"]].append({
                "role_name": props.get("roleName", ""),
                "assignment_type": "Eligible (PIM)" if edge["edge_type"] == "AZPIMEligible" else "Active",
            })

    if not role_map:
        return []

    results = []
    for edge in data.get("hybrid_edges", []):
        if edge["edge_type"] != "SyncedToEntraUser":
            continue
        entra_id = edge["target_id"]
        if entra_id not in role_map:
            continue
        props = edge.get("properties", {})
        for role in role_map[entra_id]:
            results.append({
                "ad_sid": edge["source_id"],
                "ad_name": props.get("ad_name", ""),
                "entra_id": entra_id,
                "entra_name": props.get("entra_name", ""),
                "role_name": role["role_name"],
                "assignment_type": role["assignment_type"],
            })

    return results

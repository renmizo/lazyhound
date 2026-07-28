"""Renderer-agnostic graph model for attack-path visualization."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    OU = "ou"
    DOMAIN = "domain"
    GPO = "gpo"
    CERT = "cert"
    TRUST = "trust"
    # Entra ID / Azure
    AAD_USER = "aad_user"
    AAD_GROUP = "aad_group"
    AAD_APP = "aad_app"
    AAD_SP = "aad_sp"
    AAD_DEVICE = "aad_device"
    AZ_TENANT = "az_tenant"
    AZ_RESOURCE = "az_resource"
    UNKNOWN = "unknown"


_CLASS_MAP = {
    "user": NodeType.USER,
    "group": NodeType.GROUP,
    "computer": NodeType.COMPUTER,
    "ou": NodeType.OU,
    "organizationalunit": NodeType.OU,
    "domain": NodeType.DOMAIN,
    "gpo": NodeType.GPO,
    "grouppolicycontainer": NodeType.GPO,
    "trusteddomain": NodeType.TRUST,
    "certtemplate": NodeType.CERT,
    "pki": NodeType.CERT,
    "pkicertificatetemplate": NodeType.CERT,
    "pkienrollmentservice": NodeType.CERT,
    # Entra ID / Azure
    "aad_user": NodeType.AAD_USER,
    "aad_group": NodeType.AAD_GROUP,
    "aad_app": NodeType.AAD_APP,
    "aad_sp": NodeType.AAD_SP,
    "aad_device": NodeType.AAD_DEVICE,
    "azure_tenant": NodeType.AZ_TENANT,
    "azure_sub": NodeType.AZ_RESOURCE,
    "azure_rg": NodeType.AZ_RESOURCE,
    "azure_vm": NodeType.AZ_RESOURCE,
    "azure_kv": NodeType.AZ_RESOURCE,
}


def node_type_for(object_class: str | None) -> NodeType:
    return _CLASS_MAP.get((object_class or "").lower(), NodeType.UNKNOWN)


def sanitize_id(identifier: str) -> str:
    """Stable, renderer-safe node id (alnum + underscore)."""
    return "n_" + re.sub(r"[^A-Za-z0-9]", "_", identifier or "")


# Shared visual palette (BloodHound-inspired) used by the dot + mermaid renderers.
PALETTE: dict[NodeType, str] = {
    NodeType.USER: "#5599e6",
    NodeType.GROUP: "#e6b94d",
    NodeType.COMPUTER: "#2fb6a8",
    NodeType.OU: "#8a7fbf",
    NodeType.DOMAIN: "#6abf69",
    NodeType.GPO: "#e6884d",
    NodeType.CERT: "#c45fb5",
    NodeType.TRUST: "#b08968",
    NodeType.AAD_USER: "#3fb5e6",
    NodeType.AAD_GROUP: "#e6cf4d",
    NodeType.AAD_APP: "#7a9fe6",
    NodeType.AAD_SP: "#7a9fe6",
    NodeType.AAD_DEVICE: "#5fb0c4",
    NodeType.AZ_TENANT: "#2d6fb3",
    NodeType.AZ_RESOURCE: "#4d8fd6",
    NodeType.UNKNOWN: "#8a8a8a",
}
TIER_ZERO_FILL = "#d9342b"
OWNED_RING = "#f5c518"


# Human-readable descriptions for attack-graph edge primitives, so a diagram
# arrow reads "can read LAPS password" instead of the raw "ReadLAPSPassword".
EDGE_DESCRIPTIONS: dict[str, str] = {
    # Group / containment / ownership
    "MemberOf": "member of",
    "Owns": "owns",
    "Contains": "contains",
    # ACL abuse
    "GenericAll": "full control (GenericAll)",
    "GenericWrite": "can modify (GenericWrite)",
    "WriteDACL": "can rewrite permissions (WriteDacl)",
    "WriteOwner": "can take ownership (WriteOwner)",
    "AllExtendedRights": "all extended rights",
    "ForceChangePassword": "can reset password",
    "AddMember": "can add members",
    "AddSelf": "can add self to group",
    "WriteSPN": "can set SPN (targeted Kerberoast)",
    "WriteShadowCredentials": "can add shadow credentials",
    "AddKeyCredentialLink": "can add shadow credentials",
    "ReadLAPSPassword": "can read LAPS password",
    "ReadGMSAPassword": "can read gMSA password",
    # Replication
    "DCSync": "can DCSync (replicate secrets)",
    "GetChanges": "can DCSync (replicate secrets)",
    "GetChangesAll": "can DCSync (replicate secrets)",
    # Delegation
    "AllowedToDelegate": "constrained delegation to",
    "AllowedToAct": "resource-based delegation — can act on",
    "CoerceToTGT": "can coerce authentication → TGT",
    # Network / sessions
    "HasSession": "has an active session on",
    "AdminTo": "is local admin on",
    "CanRDP": "can RDP to",
    "CanPSRemote": "can PowerShell-remote to",
    "ExecuteDCOM": "can DCOM-execute on",
    # GPO / trust / SID history
    "GPLink": "GPO is linked to",
    "TrustedBy": "is trusted by",
    "HasSIDHistory": "has SID history of",
    # ADCS
    "GoldenCert": "can forge certificates (Golden Cert)",
    # Azure / Entra
    "SyncedToEntraUser": "is synced to Entra (Entra Connect)",
    "SyncedToADUser": "is synced from Entra",
    "AZHasRole": "holds Entra role",
    "AZPIMEligible": "is PIM-eligible for Entra role",
    "AZMemberOf": "member of (Entra)",
    "AZOwns": "owns (Entra)",
    "AZRunsAs": "runs as",
    "AZManagedIdentity": "uses managed identity",
    "AZContributor": "Contributor on",
    "AZOwner": "Owner on",
    "AZVMContributor": "VM Contributor on",
    "AZUserAccessAdministrator": "User Access Administrator on",
    "AZKeyVaultContributor": "Key Vault Contributor on",
    "AZKeyVaultAdministrator": "Key Vault Administrator on",
    "AZGlobalAdmin": "Global Administrator over",
    "AZRoleAssignment": "has Azure role on",
    "AZSubscriptionOwner": "Subscription Owner on",
}


def humanize_edge(label: str) -> str:
    """Turn an edge primitive into a readable phrase. Handles 'PREFIX: detail'
    (e.g. 'AZHasRole: Global Administrator'), WriteProperty:* and ADCS* variants;
    falls back to the raw label for anything unmapped."""
    if not label:
        return ""
    if ": " in label:
        prefix, detail = label.split(": ", 1)
        base = EDGE_DESCRIPTIONS.get(prefix)
        if base:
            return f"{base}: {detail}"
    if label in EDGE_DESCRIPTIONS:
        return EDGE_DESCRIPTIONS[label]
    if label.startswith("WriteProperty:"):
        return f"can write {label.split(':', 1)[1]}"
    if label.startswith("ADCS"):
        return f"ADCS abuse ({label})"
    if label.startswith("TrustedBy"):
        return "is trusted by" + (" (SID-filtered)" if "SID-filtered" in label else "")
    return label


@dataclass
class VisualNode:
    id: str
    label: str
    ntype: NodeType
    tier_zero: bool = False
    owned: bool = False
    is_target: bool = False


@dataclass
class VisualEdge:
    src: str
    dst: str
    label: str = ""
    weight: float = 1.0


@dataclass
class VisualGraph:
    kind: str
    title: str
    subtitle: str = ""
    nodes: dict[str, VisualNode] = field(default_factory=dict)
    edges: list[VisualEdge] = field(default_factory=list)
    direction: str = "LR"

"""Native Entra (Microsoft Graph) collection.

Authenticates with a bearer token (see azure_auth) and pulls Entra objects and
relationships, emitting them as AzureHound-format ``{kind, data}`` entries — the
exact shape lazyhound's AzureHoundIngestor already parses. This is the live
equivalent of ``collect azure <file>`` import: it actively connects to Graph and
pulls a collection.

Vertical slice (service-principal auth): tenant, users, groups + memberships,
service principals, and Entra directory-role assignments. AzureRM (subscriptions
/ VMs / Key Vaults) and the remaining object/edge types layer on as later work.
"""
from __future__ import annotations

import logging

import requests

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 60


class AzureCollectError(Exception):
    """Raised when a Graph request fails."""


class GraphClient:
    """Minimal paginating Microsoft Graph client."""

    def __init__(self, token: str, session=None, base: str = GRAPH_BASE):
        self.token = token
        self.sess = session or requests
        self.base = base

    def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        """GET a Graph collection, following ``@odata.nextLink`` to the end."""
        url = path if path.startswith("http") else f"{self.base}/{path}"
        headers = {"Authorization": f"Bearer {self.token}",
                   "ConsistencyLevel": "eventual"}
        out: list[dict] = []
        while url:
            resp = self.sess.get(url, headers=headers, params=params,
                                 timeout=_TIMEOUT)
            params = None  # only the first request carries query params
            if resp.status_code != 200:
                body = _safe_json(resp)
                err = body.get("error", {})
                msg = err.get("message", f"HTTP {resp.status_code}") \
                    if isinstance(err, dict) else str(err)
                raise AzureCollectError(f"Graph {url}: {msg}")
            body = resp.json()
            out.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
        return out


def _safe_json(resp) -> dict:
    try:
        return resp.json()
    except Exception:  # pragma: no cover - defensive
        return {}


_USER_SELECT = ("id,displayName,userPrincipalName,accountEnabled,"
                "onPremisesSyncEnabled,onPremisesSecurityIdentifier")


def collect_entra(gc: GraphClient) -> list[dict]:
    """Collect the Entra core and return AzureHound-format entries."""
    entries: list[dict] = []

    for org in gc.get_all("organization"):
        entries.append({"kind": "AZTenant", "data": org})

    for user in gc.get_all("users", params={"$select": _USER_SELECT}):
        entries.append({"kind": "AZUser", "data": user})

    for group in gc.get_all("groups"):
        entries.append({"kind": "AZGroup", "data": group})
        members = gc.get_all(f"groups/{group['id']}/members",
                             params={"$select": "id"})
        if members:
            entries.append({"kind": "AZGroupMember", "data": {
                "groupId": group["id"],
                "members": [{"member": {"id": m["id"]}} for m in members
                            if m.get("id")]}})
        owners = gc.get_all(f"groups/{group['id']}/owners",
                            params={"$select": "id"})
        if owners:
            entries.append({"kind": "AZGroupOwner", "data": {
                "groupId": group["id"],
                "owners": [{"owner": {"id": o["id"]}} for o in owners
                           if o.get("id")]}})

    for sp in gc.get_all("servicePrincipals"):
        entries.append({"kind": "AZServicePrincipal", "data": sp})
        sp_owners = gc.get_all(f"servicePrincipals/{sp['id']}/owners",
                               params={"$select": "id"})
        if sp_owners:
            entries.append({"kind": "AZServicePrincipalOwner", "data": {
                "servicePrincipalId": sp["id"],
                "owners": [{"owner": {"id": o["id"]}} for o in sp_owners
                           if o.get("id")]}})

    role_assignments = gc.get_all("roleManagement/directory/roleAssignments")
    if role_assignments:
        entries.append({"kind": "AZRoleAssignment", "data": {
            "roleAssignments": [{
                "principalId": r.get("principalId", ""),
                "roleDefinitionId": r.get("roleDefinitionId", ""),
                "directoryScopeId": r.get("directoryScopeId", "/"),
            } for r in role_assignments]}})

    # Conditional Access policies (needs Policy.Read.All) — optional: skip
    # gracefully if the app/user lacks the permission rather than failing the run.
    try:
        for pol in gc.get_all("identity/conditionalAccess/policies"):
            entries.append({"kind": "AZConditionalAccessPolicy", "data": pol})
    except AzureCollectError as exc:
        logger.warning("Conditional Access policies not collected (%s)", exc)

    # Verified domains — authenticationType exposes federation (Golden SAML).
    try:
        for dom in gc.get_all("domains"):
            entries.append({"kind": "AZDomain", "data": dom})
    except AzureCollectError as exc:
        logger.warning("Domains not collected (%s)", exc)

    # Cross-tenant access partners — inbound user sync is a provisioning backdoor.
    # identitySynchronization is a separate nav property; pull it inline via $expand.
    try:
        for partner in gc.get_all("policies/crossTenantAccessPolicy/partners",
                                  params={"$expand": "identitySynchronization"}):
            entries.append({"kind": "AZCrossTenantPartner", "data": partner})
    except AzureCollectError as exc:
        logger.warning("Cross-tenant partners not collected (%s)", exc)

    return entries

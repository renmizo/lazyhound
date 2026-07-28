"""Native Azure / Entra OAuth2 token acquisition — hand-rolled against the
Microsoft identity platform (no msal dependency, mirrors how AzureHound auths).

Tokens are bearer tokens scoped to either Microsoft Graph or Azure Resource
Manager. Each flow posts to the tenant's v2.0 token endpoint. A `session`
(anything with a requests-compatible ``.post``) can be injected for testing.

Implemented so far: client-credentials (service principal). Device-code,
refresh-token, and ROPC flows slot in alongside as later work.
"""
from __future__ import annotations

import time

import requests

_AUTHORITY = "https://login.microsoftonline.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"

# Azure CLI well-known public client — supports ROPC + device code, pre-consented
# for Microsoft Graph in virtually every tenant. Overridable by the caller.
PUBLIC_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

_MFA_CODES = ("AADSTS50076", "AADSTS50079", "AADSTS50158")

_TIMEOUT = 30


class AzureAuthError(Exception):
    """Raised when token acquisition fails."""


class AzureMfaRequired(AzureAuthError):
    """Token error indicating interaction / MFA is required (fall back to device code)."""


def token_endpoint(tenant_id: str) -> str:
    return f"{_AUTHORITY}/{tenant_id}/oauth2/v2.0/token"


def device_code_endpoint(tenant_id: str) -> str:
    return f"{_AUTHORITY}/{tenant_id}/oauth2/v2.0/devicecode"


def _extract_token(resp) -> str:
    try:
        body = resp.json()
    except Exception:  # pragma: no cover - defensive
        body = {}
    if resp.status_code == 200 and body.get("access_token"):
        return body["access_token"]
    err = body.get("error", f"HTTP {resp.status_code}")
    desc = body.get("error_description", "token response had no access_token")
    if err == "interaction_required" or any(c in desc for c in _MFA_CODES):
        raise AzureMfaRequired(f"{err}: {desc}")
    raise AzureAuthError(f"{err}: {desc}")


def acquire_token_client_credentials(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    scope: str = GRAPH_SCOPE,
    *,
    session=None,
) -> str:
    """Service-principal (app) auth via the client-credentials grant."""
    sess = session or requests
    resp = sess.post(
        token_endpoint(tenant_id),
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
        timeout=_TIMEOUT,
    )
    return _extract_token(resp)


def acquire_token_password(
    tenant_id: str,
    username: str,
    password: str,
    client_id: str = PUBLIC_CLIENT_ID,
    scope: str = GRAPH_SCOPE,
    *,
    session=None,
) -> str:
    """Supplied-credential (ROPC) auth. Raises AzureMfaRequired when the account
    needs interactive/MFA sign-in (caller should fall back to device code)."""
    sess = session or requests
    resp = sess.post(
        token_endpoint(tenant_id),
        data={
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": scope,
        },
        timeout=_TIMEOUT,
    )
    return _extract_token(resp)


_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def acquire_token_device_code(
    tenant_id: str,
    client_id: str = PUBLIC_CLIENT_ID,
    scope: str = GRAPH_SCOPE,
    *,
    session=None,
    on_prompt=None,
    sleep=time.sleep,
) -> str:
    """Device-code auth (MFA-friendly). Posts the device request, hands the
    user-facing message to on_prompt, then polls for the token."""
    sess = session or requests
    resp = sess.post(device_code_endpoint(tenant_id),
                     data={"client_id": client_id, "scope": scope},
                     timeout=_TIMEOUT)
    try:
        d = resp.json()
    except Exception:  # pragma: no cover - defensive
        d = {}
    if resp.status_code != 200 or not d.get("device_code"):
        err = d.get("error", f"HTTP {resp.status_code}")
        raise AzureAuthError(f"{err}: {d.get('error_description', 'no device_code')}")
    if on_prompt:
        on_prompt(d.get("message")
                  or f"To sign in, open {d.get('verification_uri')} and enter "
                     f"code {d.get('user_code')}")
    interval = int(d.get("interval", 5)) or 5
    waited, limit = 0, int(d.get("expires_in", 900))
    while waited < limit:
        sleep(interval)
        waited += interval
        poll = sess.post(token_endpoint(tenant_id),
                         data={"grant_type": _DEVICE_GRANT, "client_id": client_id,
                               "device_code": d["device_code"]},
                         timeout=_TIMEOUT)
        try:
            b = poll.json()
        except Exception:  # pragma: no cover - defensive
            b = {}
        if poll.status_code == 200 and b.get("access_token"):
            return b["access_token"]
        err = b.get("error", "")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        raise AzureAuthError(f"{err or 'device flow failed'}: "
                             f"{b.get('error_description', '')}".strip())
    raise AzureAuthError("device code expired before authentication completed")

"""CA-host ADCS enrichment for `collect crawl --adcs`.

`collect run` is DCOnly and captures ADCS *directory* objects (templates, CAs)
over LDAP, but NOT CA-host state. This module actively gathers the CA-host data
needed for the host-side ESCs and merges it into the loaded collection, so
`analyze`/`report` can surface them offline (the SharpHound CARegistry analog):

  - ESC8  — web enrollment reachable      (HTTP HEAD to /certsrv/)
  - ESC6  — EDITF_ATTRIBUTESUBJECTALTNAME2 (remote registry)
  - ESC11 — RPC encryption enforcement    (remote registry)
  - ESC7  — CA security DACL (Manage CA / Manage Certificates) (remote registry)

Only ESC8 is unauthenticated HTTP. The registry reads need SMB auth AND the
Remote Registry service running on the CA — often disabled — so they degrade
gracefully: on failure the three registry-backed fields are ``None`` ("could not
read", distinct from ``False`` = "read it, not vulnerable"), and the ESC8 data
still lands.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ..security import parse_security_descriptor
from ..finder_utils import resolve_ip
from .collection_meta import compose_collection_method

logger = logging.getLogger(__name__)

# EDITF_ATTRIBUTESUBJECTALTNAME2 (policy module EditFlags) — makes every
# template ESC1-able.
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
# IF_ENFORCEENCRYPTICERTREQUEST (CA InterfaceFlags) — encrypted RPC enrollment.
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200

_CERTSVC_CONFIG = "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration"


def ca_hosts_from_collection(data: dict) -> list[dict[str, str]]:
    """Return the CA hosts to enrich, from the collection's ``pki`` objects.

    Each entry: ``{"key", "ca_name", "host"}`` where *key* is the pki object's
    dn (or name) used to merge results back, *ca_name* is the CA common name
    (registry key), and *host* is the dNSHostName to reach over HTTP/SMB.
    """
    hosts: list[dict[str, str]] = []
    for o in data.get("objects", []):
        if o.get("object_class") != "pki":
            continue
        props = o.get("properties", {})
        name = o.get("name") or props.get("cn") or ""
        host = props.get("dNSHostName") or name
        if not host:
            continue
        hosts.append({
            "key": o.get("dn") or name,
            "ca_name": name,
            "host": host,
        })
    return hosts


def _probe_web_enrollment(host: str, timeout: int) -> tuple[bool, list[str]]:
    """ESC8: is the HTTP web-enrollment endpoint reachable?  (HEAD /certsrv/)"""
    import urllib.request
    import urllib.error

    url = f"http://{host}/certsrv/"
    resolved = resolve_ip(host, logger)
    logger.info("ADCS web-enrollment probe %s [%s]:80", host, resolved)
    try:
        req = urllib.request.Request(url, method="HEAD")
        urllib.request.urlopen(req, timeout=timeout)
        return True, [url]
    except urllib.error.HTTPError:
        # Any HTTP response (401/403/etc.) means the endpoint is up.
        return True, [url]
    except Exception as exc:
        logger.debug("web-enrollment probe failed on %s: %s", host, exc)
        return False, []


def _read_ca_registry(host: str, ca_name: str, username: str, password: str,
                      domain: str, nthash: str, ccache: str,
                      timeout: int) -> dict[str, Any]:
    """ESC6/ESC11/ESC7 via Remote Registry.

    Returns editf_san2 / enforce_encrypt_rpc / ca_security, each ``None`` when
    unreadable (Remote Registry off, access denied, key missing).
    """
    import os
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, rrp
    from ..connectors.smb import _split_nt_hash, SMB_PORT

    out: dict[str, Any] = {
        "editf_san2": None,
        "enforce_encrypt_rpc": None,
        "ca_security": None,
    }
    smb_conn = None
    dce = None
    try:
        smb_conn = SMBConnection(host, host, sess_port=SMB_PORT, timeout=timeout)
        if ccache:
            os.environ["KRB5CCNAME"] = ccache
            smb_conn.kerberosLogin(username, "", domain, "", "", "", useCache=True)
        elif nthash:
            lmhash, nt = _split_nt_hash(nthash)
            smb_conn.login(username, "", domain, lmhash, nt)
        else:
            smb_conn.login(username, password, domain)

        rpctransport = transport.SMBTransport(host, SMB_PORT, r"\winreg",
                                              smb_connection=smb_conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        hklm = rrp.hOpenLocalMachine(dce)["phKey"]
        base = f"{_CERTSVC_CONFIG}\\{ca_name}"

        def _qv(key_handle, value_name):
            _dtype, data = rrp.hBaseRegQueryValue(dce, key_handle, value_name)
            return data

        # <base>: InterfaceFlags (ESC11) + Security (ESC7)
        try:
            ck = rrp.hBaseRegOpenKey(dce, hklm, base)["phkResult"]
            try:
                iflags = int(_qv(ck, "InterfaceFlags"))
                out["enforce_encrypt_rpc"] = bool(iflags & IF_ENFORCEENCRYPTICERTREQUEST)
            except Exception as exc:
                logger.debug("InterfaceFlags read failed on %s: %s", host, exc)
            try:
                sec = _qv(ck, "Security")
                if isinstance(sec, (bytes, bytearray)):
                    sd = parse_security_descriptor(bytes(sec))
                    out["ca_security"] = (
                        [ace.to_dict() for ace in sd.dacl.aces] if sd.dacl else []
                    )
            except Exception as exc:
                logger.debug("CA Security read failed on %s: %s", host, exc)
        except Exception as exc:
            logger.debug("open CertSvc config key failed on %s: %s", host, exc)

        # <base>\PolicyModules\<Active>: EditFlags (ESC6)
        try:
            pmk = rrp.hBaseRegOpenKey(dce, hklm, base + "\\PolicyModules")["phkResult"]
            active = str(_qv(pmk, "Active")).rstrip("\x00")
            pk = rrp.hBaseRegOpenKey(dce, hklm,
                                     base + "\\PolicyModules\\" + active)["phkResult"]
            editflags = int(_qv(pk, "EditFlags"))
            out["editf_san2"] = bool(editflags & EDITF_ATTRIBUTESUBJECTALTNAME2)
        except Exception as exc:
            logger.debug("EditFlags read failed on %s: %s", host, exc)

    except Exception as exc:
        # Remote Registry off / access denied / unreachable -> everything None.
        logger.warning("CA registry read failed on %s (Remote Registry off?): %s",
                       host, exc)
    finally:
        try:
            if dce:
                dce.disconnect()
        except Exception:
            pass
        try:
            if smb_conn:
                smb_conn.close()
        except Exception:
            pass
    return out


def enrich_ca(ca: dict[str, str], username: str, password: str, domain: str,
              nthash: str = "", ccache: str = "", timeout: int = 5,
              endpoints_ldap: list[str] | None = None) -> dict[str, Any]:
    """Enrich a single CA host: HTTP web-enrollment probe + registry reads."""
    http_up, http_endpoints = _probe_web_enrollment(ca["host"], timeout)
    reg = _read_ca_registry(ca["host"], ca["ca_name"], username, password,
                            domain, nthash, ccache, timeout)
    endpoints = list(dict.fromkeys((endpoints_ldap or []) + http_endpoints))
    return {
        "web_enrollment_http": http_up,
        "web_enrollment_endpoints": endpoints,
        "editf_san2": reg["editf_san2"],
        "enforce_encrypt_rpc": reg["enforce_encrypt_rpc"],
        "ca_security": reg["ca_security"],
    }


def merge_adcs_into_collection(data: dict, results: dict[str, dict]) -> dict:
    """Write each CA's ``adcs`` block onto its ``pki`` object + update meta.

    *results* maps a CA key (pki dn/name) → the enrichment block.
    """
    enriched = 0
    registry_reachable = False
    for o in data.get("objects", []):
        if o.get("object_class") != "pki":
            continue
        key = o.get("dn") or o.get("name")
        block = results.get(key)
        if not block:
            continue
        o["adcs"] = block
        enriched += 1
        if any(block.get(f) is not None
               for f in ("editf_san2", "enforce_encrypt_rpc", "ca_security")):
            registry_reachable = True

    meta = data.setdefault("meta", {})
    meta.setdefault("base_method", "DCOnly")
    meta["adcs_enrichment"] = {
        "collected": True,
        "cas_total": len(results),
        "cas_enriched": enriched,
        "registry_reachable": registry_reachable,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    meta["collection_method"] = compose_collection_method(meta)
    data["meta"] = meta
    return data

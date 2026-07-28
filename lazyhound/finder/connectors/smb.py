"""SMB/DCERPC connector for session enumeration and local group membership.

Uses impacket (optional dependency) to connect to remote Windows hosts via
SMB and enumerate:
  - Active sessions (NetSessionEnum via SRVSVC named pipe)
  - Logged-on users (NetWkstaUserEnum via WKSSVC named pipe)
  - Local group memberships (SAM-R for Administrators, Remote Desktop Users,
    Distributed COM Users, Remote Management Users)

These operations mirror SharpHound's session and local-group collection
methods and produce HasSession / AdminTo / CanRDP / ExecuteDCOM / CanPSRemote
edges for attack path analysis.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..finder_utils import resolve_ip

logger = logging.getLogger(__name__)

_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def _split_nt_hash(nthash: str) -> tuple[str, str]:
    """Split a stored NT-hash value into (lmhash, nthash) for impacket login.

    Accepts a bare 32-char NT hash or a full ``LM:NT`` pair. impacket's
    ``SMBConnection.login`` takes lmhash and nthash as separate arguments, so
    an ``LM:NT`` string must be split rather than passed whole. A bare NT hash
    is paired with the empty-LM constant.
    """
    h = (nthash or "").strip()
    if not h:
        return "", ""
    if ":" in h:
        lm, _, nt = h.partition(":")
        return (lm or _EMPTY_LM), nt
    return _EMPTY_LM, h


# Lazy-check for impacket availability
_IMPACKET_AVAILABLE: bool | None = None


def _check_impacket() -> bool:
    global _IMPACKET_AVAILABLE
    if _IMPACKET_AVAILABLE is None:
        try:
            import impacket  # noqa: F401
            _IMPACKET_AVAILABLE = True
        except ImportError:
            _IMPACKET_AVAILABLE = False
    return _IMPACKET_AVAILABLE


def require_impacket() -> None:
    """Raise ImportError with a helpful message if impacket is not installed."""
    if not _check_impacket():
        raise ImportError(
            "Network collection requires the 'impacket' package. "
            "Install it with: pip install impacket"
        )


# Well-known local group RIDs
LOCAL_ADMINS_RID = 544
REMOTE_DESKTOP_USERS_RID = 555
DISTRIBUTED_COM_USERS_RID = 562
REMOTE_MANAGEMENT_USERS_RID = 580

LOCAL_GROUP_RIDS = {
    LOCAL_ADMINS_RID: "Administrators",
    REMOTE_DESKTOP_USERS_RID: "Remote Desktop Users",
    DISTRIBUTED_COM_USERS_RID: "Distributed COM Users",
    REMOTE_MANAGEMENT_USERS_RID: "Remote Management Users",
}

# Edge types produced by local group enumeration
RID_TO_EDGE = {
    LOCAL_ADMINS_RID: "AdminTo",
    REMOTE_DESKTOP_USERS_RID: "CanRDP",
    DISTRIBUTED_COM_USERS_RID: "ExecuteDCOM",
    REMOTE_MANAGEMENT_USERS_RID: "CanPSRemote",
}

CONNECT_TIMEOUT = 5
SMB_PORT = 445


@dataclass
class SessionInfo:
    """A single active session on a remote host."""
    username: str
    source_host: str  # where the session originates from
    target_host: str  # the computer the session is on
    source_method: str = ""  # how the session was discovered
    collected_at: str = ""   # ISO timestamp when discovered


@dataclass
class LocalGroupMember:
    """A member of a local group on a remote host."""
    member_sid: str
    member_name: str
    group_rid: int
    group_name: str
    target_host: str


@dataclass
class HostEnumResult:
    """Results from enumerating a single host."""
    hostname: str
    reachable: bool = False
    sessions: list[SessionInfo] = field(default_factory=list)
    local_group_members: list[LocalGroupMember] = field(default_factory=list)
    error: str | None = None


def is_port_open(host: str, port: int = SMB_PORT,
                 timeout: int = CONNECT_TIMEOUT) -> bool:
    """Quick TCP connect check."""
    resolved = resolve_ip(host, logger)
    try:
        with socket.create_connection((resolved, port), timeout=timeout):
            logger.info("Port %d open on %s [%s]", port, host, resolved)
            return True
    except (OSError, TimeoutError):
        logger.debug("Port %d closed/unreachable on %s [%s]", port, host, resolved)
        return False


def enumerate_sessions(
    host: str,
    username: str,
    password: str,
    domain: str,
    nthash: str = "",
    ccache: str = "",
    timeout: int = CONNECT_TIMEOUT,
) -> list[SessionInfo]:
    """Enumerate active SMB sessions on a remote host via NetSessionEnum.

    This uses the SRVSVC named pipe (\\PIPE\\srvsvc) and calls
    NetrSessionEnum at info level 10 (username + source host).

    Any authenticated domain user can typically call this.
    """
    require_impacket()
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, srvs
    from impacket.dcerpc.v5.dtypes import NULL

    sessions: list[SessionInfo] = []

    resolved = resolve_ip(host, logger)
    smb_conn = None
    dce = None
    try:
        # Connect via SMB
        logger.info("SMB session enum connecting to %s [%s]:%d", host, resolved, SMB_PORT)
        smb_conn = SMBConnection(host, host, sess_port=SMB_PORT,
                                 timeout=timeout)
        if ccache:
            # Kerberos: read the TGT from the ccache (impacket's own krb5, no
            # gssapi dependency). Host must be the DC FQDN for the SPN match.
            os.environ["KRB5CCNAME"] = ccache
            smb_conn.kerberosLogin(username, "", domain, "", "", "", useCache=True)
        elif nthash:
            lmhash, nt = _split_nt_hash(nthash)
            smb_conn.login(username, "", domain, lmhash, nt)
        else:
            smb_conn.login(username, password, domain)

        # Bind to SRVSVC
        rpctransport = transport.SMBTransport(
            host, SMB_PORT, r"\srvsvc",
            smb_connection=smb_conn,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        # Call NetrSessionEnum (info level 10: user + client).
        # clientName / userName are optional NDR pointers — pass impacket's NULL
        # sentinel (enumerate ALL sessions), NOT Python None. Python None makes
        # the NDR marshaller call .encode() on it and raise
        # "'NoneType' object has no attribute 'encode'" before any packet is sent.
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

        for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
            raw_user = session["sesi10_username"]
            raw_client = session["sesi10_cname"]
            if raw_user is None or raw_client is None:
                continue
            sess_user = str(raw_user).rstrip("\x00")
            sess_client = str(raw_client).rstrip("\x00")
            # Skip machine accounts and empty entries
            if not sess_user or sess_user.endswith("$"):
                continue
            # Clean up client name (remove leading \\)
            sess_client = sess_client.lstrip("\\")
            sessions.append(SessionInfo(
                username=sess_user,
                source_host=sess_client,
                target_host=host,
                source_method="NetSessionEnum",
                collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ))

    except Exception as exc:
        logger.warning("Session enum failed on %s: %s", host, exc)
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

    return sessions


def enumerate_logged_on(
    host: str,
    username: str,
    password: str,
    domain: str,
    nthash: str = "",
    ccache: str = "",
    timeout: int = CONNECT_TIMEOUT,
) -> list[SessionInfo]:
    """Enumerate interactively logged-on users via NetWkstaUserEnum.

    This uses the WKSSVC named pipe (\\PIPE\\wkssvc) and calls
    NetrWkstaUserEnum at info level 1.

    Requires local Administrator privileges on the target.
    """
    require_impacket()
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, wkst

    sessions: list[SessionInfo] = []

    resolved = resolve_ip(host, logger)
    smb_conn = None
    dce = None
    try:
        logger.info("SMB logged-on enum connecting to %s [%s]:%d", host, resolved, SMB_PORT)
        smb_conn = SMBConnection(host, host, sess_port=SMB_PORT,
                                 timeout=timeout)
        if ccache:
            # Kerberos: read the TGT from the ccache (impacket's own krb5, no
            # gssapi dependency). Host must be the DC FQDN for the SPN match.
            os.environ["KRB5CCNAME"] = ccache
            smb_conn.kerberosLogin(username, "", domain, "", "", "", useCache=True)
        elif nthash:
            lmhash, nt = _split_nt_hash(nthash)
            smb_conn.login(username, "", domain, lmhash, nt)
        else:
            smb_conn.login(username, password, domain)

        rpctransport = transport.SMBTransport(
            host, SMB_PORT, r"\wkssvc",
            smb_connection=smb_conn,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST)

        resp = wkst.hNetrWkstaUserEnum(dce, 1)

        for entry in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
            raw_user = entry["wkui1_username"]
            raw_domain = entry["wkui1_logon_domain"]
            if raw_user is None:
                continue
            logged_user = str(raw_user).rstrip("\x00")
            logged_domain = str(raw_domain).rstrip("\x00") if raw_domain else ""
            # Skip machine accounts and empty entries
            if not logged_user or logged_user.endswith("$"):
                continue
            sessions.append(SessionInfo(
                username=f"{logged_domain}\\{logged_user}" if logged_domain else logged_user,
                source_host="",  # interactive logon, no remote source
                target_host=host,
                source_method="NetWkstaUserEnum",
                collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ))

    except Exception as exc:
        logger.warning("LoggedOn enum failed on %s: %s", host, exc)
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

    return sessions


def enumerate_registry_sessions(
    host: str,
    username: str,
    password: str,
    domain: str,
    nthash: str = "",
    ccache: str = "",
    timeout: int = CONNECT_TIMEOUT,
) -> list[SessionInfo]:
    """Enumerate logged-on users via the Remote Registry service.

    Reads HKEY_USERS on the target host to find loaded user hives, which
    indicates an interactive (console or RDP) logon.  This mirrors
    SharpHound's registry-based session collection and works as a
    fallback when NetWkstaUserEnum is unavailable or fails.

    Requires the Remote Registry service to be running on the target and
    the caller to have admin privileges.
    """
    require_impacket()
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, rrp

    sessions: list[SessionInfo] = []

    resolved = resolve_ip(host, logger)
    smb_conn = None
    dce = None
    try:
        logger.info("SMB registry session enum connecting to %s [%s]:%d", host, resolved, SMB_PORT)
        smb_conn = SMBConnection(host, host, sess_port=SMB_PORT,
                                 timeout=timeout)
        if ccache:
            # Kerberos: read the TGT from the ccache (impacket's own krb5, no
            # gssapi dependency). Host must be the DC FQDN for the SPN match.
            os.environ["KRB5CCNAME"] = ccache
            smb_conn.kerberosLogin(username, "", domain, "", "", "", useCache=True)
        elif nthash:
            lmhash, nt = _split_nt_hash(nthash)
            smb_conn.login(username, "", domain, lmhash, nt)
        else:
            smb_conn.login(username, password, domain)

        rpctransport = transport.SMBTransport(
            host, SMB_PORT, r"\winreg",
            smb_connection=smb_conn,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # Open HKEY_USERS
        resp = rrp.hOpenUsers(dce)
        hku_handle = resp["phKey"]

        i = 0
        while True:
            try:
                subkey = rrp.hBaseRegEnumKey(dce, hku_handle, i)
                sid_str = subkey["lpNameOut"].rstrip("\x00")
                i += 1

                # Skip non-user SIDs: defaults, classes hives, well-known
                if "_Classes" in sid_str or sid_str in (
                    ".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20",
                ):
                    continue
                # Only keep full-length user SIDs (S-1-5-21-...)
                if not sid_str.startswith("S-1-5-21-"):
                    continue

                sessions.append(SessionInfo(
                    username=sid_str,  # SID; caller resolves to name
                    source_host="",
                    target_host=host,
                    source_method="RemoteRegistry",
                    collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ))
            except Exception:
                # rrp.hBaseRegEnumKey raises when index is out of range
                break

        rrp.hBaseRegCloseKey(dce, hku_handle)

    except Exception as exc:
        logger.warning("Registry session enum failed on %s: %s", host, exc)
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

    return sessions


def enumerate_local_groups(
    host: str,
    username: str,
    password: str,
    domain: str,
    nthash: str = "",
    ccache: str = "",
    timeout: int = CONNECT_TIMEOUT,
    group_rids: dict[int, str] | None = None,
) -> list[LocalGroupMember]:
    """Enumerate members of local security groups via SAM-R.

    Uses the SAMR named pipe (\\PIPE\\samr) to open each target local group
    by RID and enumerate its members.

    Any authenticated domain user can typically query local Administrators.
    Other groups may require local admin privileges.
    """
    require_impacket()
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr

    if group_rids is None:
        group_rids = LOCAL_GROUP_RIDS

    members: list[LocalGroupMember] = []

    resolved = resolve_ip(host, logger)
    smb_conn = None
    dce = None
    try:
        logger.info("SMB local group enum connecting to %s [%s]:%d", host, resolved, SMB_PORT)
        smb_conn = SMBConnection(host, host, sess_port=SMB_PORT,
                                 timeout=timeout)
        if ccache:
            # Kerberos: read the TGT from the ccache (impacket's own krb5, no
            # gssapi dependency). Host must be the DC FQDN for the SPN match.
            os.environ["KRB5CCNAME"] = ccache
            smb_conn.kerberosLogin(username, "", domain, "", "", "", useCache=True)
        elif nthash:
            lmhash, nt = _split_nt_hash(nthash)
            smb_conn.login(username, "", domain, lmhash, nt)
        else:
            smb_conn.login(username, password, domain)

        rpctransport = transport.SMBTransport(
            host, SMB_PORT, r"\samr",
            smb_connection=smb_conn,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Connect to SAM and open the built-in domain
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        # Enumerate domains to find the Builtin domain
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        builtin_domain_sid = None
        for domain_entry in resp["Buffer"]["Buffer"]:
            dname = domain_entry["Name"].rstrip("\x00")
            if dname.upper() == "BUILTIN":
                resp2 = samr.hSamrLookupDomainInSamServer(
                    dce, server_handle, dname
                )
                builtin_domain_sid = resp2["DomainId"]
                break

        if builtin_domain_sid is None:
            logger.debug("Could not find Builtin domain on %s", host)
            return members

        # Open the Builtin domain
        resp = samr.hSamrOpenDomain(
            dce, server_handle, samr.MAXIMUM_ALLOWED, builtin_domain_sid
        )
        domain_handle = resp["DomainHandle"]

        # Enumerate each target group
        for rid, group_name in group_rids.items():
            try:
                resp = samr.hSamrOpenAlias(
                    dce, domain_handle, samr.MAXIMUM_ALLOWED, rid
                )
                alias_handle = resp["AliasHandle"]

                resp = samr.hSamrGetMembersInAlias(dce, alias_handle)

                for member_sid in resp["Members"]["Sids"]:
                    sid_str = member_sid["SidPointer"].formatCanonical()
                    members.append(LocalGroupMember(
                        member_sid=sid_str,
                        member_name="",  # resolved later via SID map
                        group_rid=rid,
                        group_name=group_name,
                        target_host=host,
                    ))

                samr.hSamrCloseHandle(dce, alias_handle)

            except Exception as exc:
                logger.warning(
                    "Failed to enumerate %s (RID %d) on %s: %s",
                    group_name, rid, host, exc,
                )

        samr.hSamrCloseHandle(dce, domain_handle)
        samr.hSamrCloseHandle(dce, server_handle)

    except Exception as exc:
        logger.warning("Local group enum failed on %s: %s", host, exc)
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

    return members


def enumerate_host(
    host: str,
    username: str,
    password: str,
    domain: str,
    nthash: str = "",
    ccache: str = "",
    collect_sessions: bool = True,
    collect_local_groups: bool = True,
    timeout: int = CONNECT_TIMEOUT,
) -> HostEnumResult:
    """Run all enabled enumeration on a single host.

    Combines session enumeration and local group enumeration into a
    single result. Checks port reachability first to avoid timeouts.
    """
    result = HostEnumResult(hostname=host)

    addr = resolve_ip(host, logger)
    if not is_port_open(addr, SMB_PORT, timeout):
        result.error = "SMB port unreachable"
        return result

    result.reachable = True

    if collect_sessions:
        try:
            result.sessions.extend(
                enumerate_sessions(addr, username, password, domain,
                                   nthash, ccache, timeout)
            )
        except Exception as exc:
            logger.warning("Session collection failed on %s: %s", host, exc)

        try:
            logged_on = enumerate_logged_on(
                addr, username, password, domain, nthash, ccache, timeout
            )
            # Merge logged-on users, dedup by username+host
            existing = {(s.username, s.target_host) for s in result.sessions}
            for s in logged_on:
                if (s.username, s.target_host) not in existing:
                    result.sessions.append(s)
        except Exception as exc:
            logger.warning("LoggedOn collection failed on %s: %s", host, exc)
            logged_on = []

        # Fallback: if NetWkstaUserEnum returned nothing, try registry-based
        # enumeration which detects interactive logins via loaded user hives.
        if not logged_on:
            try:
                reg_sessions = enumerate_registry_sessions(
                    addr, username, password, domain, nthash, ccache, timeout
                )
                existing = {(s.username, s.target_host) for s in result.sessions}
                for s in reg_sessions:
                    if (s.username, s.target_host) not in existing:
                        result.sessions.append(s)
            except Exception as exc:
                logger.warning("Registry session enum failed on %s: %s",
                               host, exc)

    if collect_local_groups:
        try:
            result.local_group_members = enumerate_local_groups(
                addr, username, password, domain, nthash, ccache, timeout
            )
        except Exception as exc:
            logger.warning("Local group collection failed on %s: %s", host, exc)

    return result

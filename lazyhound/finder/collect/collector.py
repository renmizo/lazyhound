"""DC-only LDAP collector.

Mirrors SharpHound's DCOnly collection method: connects to a domain controller
via LDAP, queries users, groups, computers, OUs, and GPOs with their security
descriptors, then writes structured JSON files for offline analysis.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

import ldap3

from .analyzer import WELL_KNOWN_SIDS, PRIVILEGED_RIDS
from ..security import parse_security_descriptor
from ..stealth import StealthConfig

def _ntlm_bind_secret(password: str, nthash: str | None) -> str:
    """Build the ldap3 NTLM bind secret from a password or NT hash.

    Accepts an NT hash as either a bare 32-char hex string or a full
    ``LM:NT`` pair (already colon-separated); a bare NT hash gets the
    empty-LM prefix ldap3 expects. Falls back to the password when no hash
    is set.
    """
    h = (nthash or "").strip()
    if h:
        return h if ":" in h else f"aad3b435b51404eeaad3b435b51404ee:{h}"
    return password


# Maximum number of SIDs per batched OR-filter LDAP query.
# AD has a default MaxPageSize of 1000; keep batches well under that.
_SID_BATCH_SIZE = 500

# LDAP_SERVER_SD_FLAGS_OID — requests specific SD components
SD_FLAGS_OID = "1.2.840.113556.1.4.801"

# SD flags: OWNER (0x01) + GROUP (0x02) + DACL (0x04) = 0x07
SD_FLAGS_VALUE = 0x07

# Minimal attribute set when stealth.minimal_attrs is True
_MINIMAL_ATTRS = [
    "distinguishedName",
    "sAMAccountName",
    "objectSid",
    "objectClass",
    "nTSecurityDescriptor",
]


def _sd_flags_control(flags_value: int = SD_FLAGS_VALUE):
    """Build the SD_FLAGS LDAP control to request specific SD components.

    The control value is a BER-encoded SEQUENCE containing a single INTEGER
    with the requested SD components bitmask.

    Args:
        flags_value: Bitmask of SD components to request.  Default 0x07
            (owner + group + DACL).
    """
    # BER: SEQUENCE { INTEGER <flags> } → 30 03 02 01 <flags>
    ber_value = b"\x30\x03\x02\x01" + struct.pack("B", flags_value)
    return ldap3.protocol.controls.build_control(
        SD_FLAGS_OID, True, ber_value, encode_control_value=False
    )


# Object classes to collect and the extra attributes relevant to each
_OBJECT_QUERIES = {
    "user": {
        "filter": "(&(objectCategory=person)(objectClass=user))",
        "attrs": [
            "distinguishedName",
            "sAMAccountName",
            "objectSid",
            "nTSecurityDescriptor",
            "memberOf",
            "userAccountControl",
            "servicePrincipalName",
            "adminCount",
            "description",
            "displayName",
            "mail",
            "title",
            "department",
            "manager",
            "userPrincipalName",
            "logonCount",
            "accountExpires",
            "msDS-SupportedEncryptionTypes",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "primaryGroupID",
            "pwdLastSet",
            "lastLogonTimestamp",
            "sIDHistory",
            "whenCreated",
        ],
    },
    "group": {
        "filter": "(objectClass=group)",
        "attrs": [
            "distinguishedName",
            "sAMAccountName",
            "objectSid",
            "nTSecurityDescriptor",
            "member",
            "adminCount",
            "description",
            "groupType",
            "managedBy",
            "mail",
            "whenCreated",
        ],
    },
    "computer": {
        "filter": "(objectClass=computer)",
        "attrs": [
            "distinguishedName",
            "sAMAccountName",
            "objectSid",
            "nTSecurityDescriptor",
            "memberOf",
            "userAccountControl",
            "operatingSystem",
            "operatingSystemVersion",
            "operatingSystemServicePack",
            "servicePrincipalName",
            "adminCount",
            "description",
            "dNSHostName",
            "managedBy",
            "primaryGroupID",
            "pwdLastSet",
            "lastLogonTimestamp",
            "msDS-SupportedEncryptionTypes",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "sIDHistory",
            "whenCreated",
        ],
    },
    "ou": {
        "filter": "(objectClass=organizationalUnit)",
        "attrs": [
            "distinguishedName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "gPLink",
            "description",
            "whenCreated",
        ],
    },
    "gpo": {
        "filter": "(objectClass=groupPolicyContainer)",
        "attrs": [
            "distinguishedName",
            "displayName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "gPCFileSysPath",
            "whenCreated",
        ],
    },
    "container": {
        "filter": "(&(objectClass=container)(cn=AdminSDHolder))",
        "attrs": [
            "distinguishedName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "whenCreated",
        ],
    },
    "domain": {
        "filter": "(objectClass=domain)",
        "attrs": [
            "distinguishedName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "ms-DS-MachineAccountQuota",
            "whenCreated",
        ],
    },
    "trusteddomain": {
        "filter": "(objectClass=trustedDomain)",
        "attrs": [
            "distinguishedName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "trustDirection",
            "trustType",
            "trustAttributes",
            "securityIdentifier",
            "flatName",
            "whenCreated",
        ],
    },
    "certtemplate": {
        "filter": "(objectClass=pKICertificateTemplate)",
        "attrs": [
            "distinguishedName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "displayName",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "msPKI-RA-Signature",
            "pKIExtendedKeyUsage",
            "msPKI-Certificate-Application-Policy",
            "msPKI-Certificate-Policy",
            "msPKI-Template-Schema-Version",
            "whenCreated",
        ],
    },
    "pki": {
        "filter": "(objectClass=pKIEnrollmentService)",
        "attrs": [
            "distinguishedName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "displayName",
            "cACertificate",
            "certificateTemplates",
            "dNSHostName",
            "flags",
            "msPKI-Enrollment-Servers",
            "whenCreated",
        ],
    },
    "oidobject": {
        "filter": "(objectClass=msPKI-Enterprise-Oid)",
        "attrs": [
            "distinguishedName",
            "name",
            "objectSid",
            "nTSecurityDescriptor",
            "displayName",
            "msDS-OIDToGroupLink",
            "msPKI-Cert-Template-OID",
            "whenCreated",
        ],
    },
    "gmsa": {
        "filter": "(objectClass=msDS-GroupManagedServiceAccount)",
        "attrs": [
            "distinguishedName",
            "sAMAccountName",
            "objectSid",
            "nTSecurityDescriptor",
            "memberOf",
            "userAccountControl",
            "servicePrincipalName",
            "msDS-GroupMSAMembership",
            "msDS-ManagedPasswordId",
            "msDS-ManagedPasswordInterval",
            "description",
            "adminCount",
            "whenCreated",
        ],
    },
    "dmsa": {
        # Delegated Managed Service Accounts (Windows Server 2025) — BadSuccessor.
        "filter": "(objectClass=msDS-DelegatedManagedServiceAccount)",
        "attrs": [
            "distinguishedName",
            "sAMAccountName",
            "objectSid",
            "nTSecurityDescriptor",
            "memberOf",
            "userAccountControl",
            "servicePrincipalName",
            "msDS-ManagedAccountPrecededByLink",
            "msDS-DelegatedMSAState",
            "description",
            "whenCreated",
        ],
    },
}


def _bytes_to_sid_string(raw: bytes) -> str:
    """Convert raw objectSid bytes to S-x-x-... string.

    Raises ``ValueError`` on malformed input (too short or truncated).
    """
    if len(raw) < 8:
        raise ValueError(f"SID bytes too short ({len(raw)} bytes, need at least 8)")
    revision = raw[0]
    sub_count = raw[1]
    expected_len = 8 + 4 * sub_count
    if len(raw) < expected_len:
        raise ValueError(
            f"SID bytes truncated: expected {expected_len} bytes for "
            f"{sub_count} sub-authorities, got {len(raw)}"
        )
    authority = int.from_bytes(raw[2:8], "big")
    subs = []
    for i in range(sub_count):
        (sa,) = struct.unpack_from("<I", raw, 8 + 4 * i)
        subs.append(str(sa))
    if subs:
        return f"S-{revision}-{authority}-" + "-".join(subs)
    return f"S-{revision}-{authority}"


def _first(values: list) -> object | None:
    """Safely get the first element of a list, or None if empty."""
    return values[0] if values else None


def _serialize_entry(entry: ldap3.Entry, object_class: str) -> dict | None:
    """Convert an ldap3 Entry to a serialisable dict with parsed DACL."""
    attrs = entry.entry_attributes_as_dict

    dn = str(entry.entry_dn)
    name = (
        _first(attrs.get("sAMAccountName", []))
        or _first(attrs.get("displayName", []))
        or _first(attrs.get("name", []))
        or dn
    )

    # Parse objectSid — may be raw bytes or an already-decoded string
    # depending on ldap3 configuration / server behaviour.
    raw_sid = _first(attrs.get("objectSid", []))
    sid_str = None
    if raw_sid:
        if isinstance(raw_sid, bytes):
            sid_str = _bytes_to_sid_string(raw_sid)
        elif isinstance(raw_sid, str) and raw_sid.startswith("S-"):
            sid_str = raw_sid

    # Parse nTSecurityDescriptor → DACL ACEs + owner SID
    dacl_entries = []
    owner_sid = None
    raw_sd = _first(attrs.get("nTSecurityDescriptor", []))
    if raw_sd and isinstance(raw_sd, bytes):
        try:
            sd = parse_security_descriptor(raw_sd)
            if sd.owner:
                owner_sid = str(sd.owner)
            if sd.dacl:
                dacl_entries = [ace.to_dict() for ace in sd.dacl.aces]
        except Exception as exc:
            print(f"  [!] Failed to parse SD for {dn}: {exc}", file=sys.stderr)

    # Collect remaining properties as simple values
    props = {}
    skip = {"distinguishedName", "sAMAccountName", "objectSid", "nTSecurityDescriptor"}
    for key, values in attrs.items():
        if key in skip:
            continue
        cleaned = []
        for v in (values if values else []):
            if isinstance(v, bytes):
                cleaned.append(v.hex())
            else:
                cleaned.append(v)
        if cleaned:
            props[key] = cleaned[0] if len(cleaned) == 1 else cleaned

    return {
        "dn": dn,
        "name": name,
        "object_sid": sid_str,
        "object_class": object_class,
        "owner_sid": owner_sid,
        "properties": props,
        "dacl": dacl_entries,
    }


def collect(
    dc_host: str,
    domain: str,
    username: str,
    password: str,
    output_dir: str = ".",
    use_ssl: bool = False,
    port: int | None = None,
    auth_method: str = "simple",
    nthash: str | None = None,
    ccache: str = "",
    page_size: int = 1000,
    validate_cert: bool = True,
    timeout: int = 30,
    use_start_tls: bool = True,
    auto_negotiate: bool = False,
    stealth: StealthConfig | None = None,
) -> Path:
    """Run DC-only collection and write results to a JSON file.

    Args:
        dc_host: Hostname or IP of the domain controller.
        domain: FQDN of the AD domain (e.g. contoso.local).
        username: sAMAccountName for LDAP bind.
        password: Password for LDAP bind.
        output_dir: Directory to write the output JSON.
        use_ssl: Use LDAPS (port 636) instead of LDAP (port 389).
        port: Override the LDAP port.
        auth_method: Authentication method — ``"simple"`` (default),
            ``"ntlm"`` for NTLM/pass-the-hash, or ``"kerberos"``.
        nthash: NT hash for pass-the-hash authentication (requires
            ``auth_method="ntlm"``).
        page_size: LDAP paged search page size (default 1000).  Set to
            match the server's ``MaxPageSize`` policy.  Use 0 to disable
            paged search (not recommended for large domains).
        validate_cert: Validate the TLS certificate of the DC (default True).
            Set to False for self-signed or internal CA certificates.
        timeout: Connection timeout in seconds (default 30).
        use_start_tls: Use STARTTLS on port 389 (default True).  This
            upgrades the plaintext connection to TLS before binding,
            satisfying DC LDAP signing requirements without needing
            NTLM-level message signing.
        stealth: Optional stealth configuration controlling SD flags,
            pacing, collection scope, and other noise-reduction settings.

    Returns:
        Path to the written JSON file.
    """
    if stealth is None:
        stealth = StealthConfig()
    import ssl as _ssl

    # Apply stealth overrides
    if stealth.ldap_page_size is not None:
        page_size = stealth.ldap_page_size

    if port is None:
        port = 636 if use_ssl else 389

    base_dn = ",".join(f"DC={part}" for part in domain.split("."))

    # Resolve authentication credentials
    auth_method_lower = auth_method.lower()
    # A Kerberos ccache forces GSSAPI; an nthash forces NTLM (pass-the-hash
    # can't use a SIMPLE bind). Either overrides an empty/'simple' method.
    if ccache:
        auth_method_lower = "kerberos"
    elif nthash and auth_method_lower not in ("ntlm", "kerberos"):
        auth_method_lower = "ntlm"
    sasl_mech = None
    if auth_method_lower == "ntlm":
        bind_user = f"{domain}\\{username}"
        bind_password = _ntlm_bind_secret(password, nthash)
        auth_type = ldap3.NTLM
    elif auth_method_lower == "kerberos":
        # GSSAPI reads the TGT from KRB5CCNAME; 'gssapi' is optional/lazy.
        if ccache:
            os.environ["KRB5CCNAME"] = ccache
        try:
            import gssapi  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "Kerberos requires the 'gssapi' package: "
                "pip install gssapi (and system krb5 libraries)."
            ) from exc
        bind_user = None
        bind_password = None
        auth_type = ldap3.SASL
        sasl_mech = ldap3.GSSAPI
    else:
        # SIMPLE bind — UPN format avoids the MD4/NTLM issue on systems
        # with OpenSSL 3.0+ where legacy hashes are disabled.
        bind_user = f"{username}@{domain}"
        bind_password = password
        auth_type = ldap3.SIMPLE

    def _try_connect(
        _port: int, _use_ssl: bool, _use_start_tls: bool, _quiet: bool = False,
    ) -> ldap3.Connection:
        do_starttls = _use_start_tls and not _use_ssl
        needs_tls = _use_ssl or do_starttls

        if not validate_cert and needs_tls and not _quiet:
            logger.warning(
                "TLS certificate validation is DISABLED — connection is vulnerable to MITM attacks"
            )
        tls_config = ldap3.Tls(
            validate=_ssl.CERT_REQUIRED if validate_cert else _ssl.CERT_NONE,
        ) if needs_tls else None

        mode = "STARTTLS" if do_starttls else ("LDAPS" if _use_ssl else "LDAP")
        if not _quiet:
            print(f"[*] Connecting to {dc_host}:{_port} ({mode}, auth={auth_method_lower})")

        server = ldap3.Server(
            dc_host, port=_port, use_ssl=_use_ssl, get_info=ldap3.ALL,
            tls=tls_config, connect_timeout=timeout,
        )
        ab = ldap3.AUTO_BIND_TLS_BEFORE_BIND if do_starttls else True

        result: ldap3.Connection | None = None
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                result = ldap3.Connection(
                    server,
                    user=bind_user,
                    password=bind_password,
                    authentication=auth_type,
                    sasl_mechanism=sasl_mech,
                    auto_bind=ab,
                    receive_timeout=timeout,
                )
                return result
            except (ldap3.core.exceptions.LDAPException, OSError) as exc:
                is_conn_reset = isinstance(exc, ConnectionResetError) or (
                    isinstance(exc, OSError) and getattr(exc, "errno", None) == 104
                )
                if attempt == max_retries:
                    if is_conn_reset:
                        hint = (
                            "The DC enforces LDAP channel binding (CBT) for LDAPS. "
                            "Try --no-ssl (port 389 with STARTTLS)."
                        ) if _use_ssl else (
                            "The DC requires LDAP signing which ldap3 cannot negotiate. "
                            "Ensure STARTTLS is enabled (default), or try --auth simple."
                        )
                        raise ConnectionResetError(
                            f"Connection reset by {dc_host}:{_port}. {hint}"
                        ) from exc
                    raise
                wait = 2 ** attempt
                # Suppress per-retry noise — only the final error matters
                pass  # retry silently
                time.sleep(wait)
        raise RuntimeError("Failed to establish LDAP connection after retries")

    if auto_negotiate:
        # Try LDAPS (636) → LDAP+STARTTLS (389) → plain LDAP (389)
        try:
            conn = _try_connect(636, True, False, _quiet=True)
        except (ldap3.core.exceptions.LDAPException, OSError):
            try:
                conn = _try_connect(389, False, True, _quiet=True)
            except (ldap3.core.exceptions.LDAPException, OSError):
                conn = _try_connect(389, False, False)
    else:
        conn = _try_connect(port, use_ssl, use_start_tls)
    print(f"[+] Bound as {bind_user}")

    try:
        return _do_collect(conn, domain, dc_host, base_dn, page_size, output_dir, username, stealth)
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _schema_supports_dmsa(conn) -> bool | None:
    """Whether the AD schema defines delegated MSAs (Windows Server 2025+).

    dMSA collection requests the ``msDS-ManagedAccountPrecededByLink`` attribute,
    which only exists in a Server 2025 schema. The connection fetches the schema
    (get_info=ALL), so we can check directly. Returns True/False, or None when
    the schema isn't available (then we let the query run and rely on the
    invalid-attribute fallback message).
    """
    schema = getattr(getattr(conn, "server", None), "schema", None)
    if not schema:
        return None
    try:
        classes = schema.object_classes or {}
        attrs = schema.attribute_types or {}
        # ldap3 exposes these as case-insensitive dicts.
        return ("msDS-DelegatedManagedServiceAccount" in classes
                or "msDS-ManagedAccountPrecededByLink" in attrs)
    except Exception:
        return None


def _attr_error_hint(obj_class: str, exc: Exception) -> str:
    """A parenthetical hint for a search error, when the cause is likely a
    schema that predates the object type. dMSA uses a Server 2025 attribute, so
    an 'invalid attribute' failure there almost always means an older schema."""
    if obj_class == "dmsa" and "invalid attribute" in str(exc).lower():
        return " (Not Windows 2025?)"
    return ""


# Object classes that live in the Configuration NC (CN=Configuration,...), NOT
# the domain NC. ADCS/PKI objects are published under
# CN=Public Key Services,CN=Services,CN=Configuration — searching the domain
# partition for them always returns 0.
_CONFIG_NC_TYPES = frozenset({"certtemplate", "pki", "oidobject"})


def _config_naming_context(conn, base_dn: str) -> str:
    """Return the Configuration partition DN where ADCS/PKI objects live.

    Prefers rootDSE's ``configurationNamingContext`` (correct for child domains
    in a multi-domain forest, where it is NOT ``CN=Configuration,<domain>``);
    falls back to constructing it from *base_dn*. Mirrors how the scan context
    derives ``configuration_dn``.
    """
    try:
        info = getattr(getattr(conn, "server", None), "info", None)
        other = getattr(info, "other", None) or {}
        vals = other.get("configurationNamingContext")
        if vals:
            return vals[0] if isinstance(vals, (list, tuple)) else str(vals)
    except Exception:
        pass
    return f"CN=Configuration,{base_dn}"


def _do_collect(conn, domain, dc_host, base_dn, page_size, output_dir, username, stealth: StealthConfig):
    # Build SD control based on stealth settings
    effective_sd = stealth.effective_sd_flags()
    sd_control = _sd_flags_control(effective_sd) if effective_sd else None
    controls = [sd_control] if sd_control else []

    all_objects: list[dict] = []
    sid_map: dict[str, str] = {}

    # ADCS/PKI object classes live in the Configuration NC, not the domain NC.
    config_nc = _config_naming_context(conn, base_dn)

    for obj_class, query in _OBJECT_QUERIES.items():
        # Stealth: skip object types not in collect_types filter
        if not stealth.should_collect(obj_class):
            logger.info("Skipping %s (filtered by stealth.collect_types)", obj_class)
            continue

        # PKI classes are published under CN=Configuration; everything else
        # lives in the domain partition.
        search_base = config_nc if obj_class in _CONFIG_NC_TYPES else base_dn

        # Build attribute list (minimal or full)
        if stealth.minimal_attrs:
            attrs = list(_MINIMAL_ATTRS)
            if stealth.skip_sd and "nTSecurityDescriptor" in attrs:
                attrs.remove("nTSecurityDescriptor")
        else:
            attrs = list(query["attrs"])
            if stealth.skip_sd and "nTSecurityDescriptor" in attrs:
                attrs.remove("nTSecurityDescriptor")

        print(f"[*] Collecting {obj_class}s ...")
        # dMSA is a Windows Server 2025 object type; skip cleanly on older
        # schemas instead of erroring on the 2025-only attribute.
        if obj_class == "dmsa" and _schema_supports_dmsa(conn) is False:
            print("    (Not Server 2025 or newer, skipping)")
            print(f"    Found 0 {obj_class}(s)")
            continue
        count = 0
        if page_size > 0:
            # Paged search — iterate with cookie to retrieve all results
            cookie: bytes | None = None
            while True:
                # Stealth: pace between page fetches
                if cookie:  # don't delay the first page
                    stealth.ldap_pace()
                try:
                    conn.search(
                        search_base=search_base,
                        search_filter=query["filter"],
                        search_scope=ldap3.SUBTREE,
                        attributes=attrs,
                        controls=controls,
                        paged_size=page_size,
                        paged_cookie=cookie,
                    )
                except (ldap3.core.exceptions.LDAPException, OSError) as exc:
                    hint = _attr_error_hint(obj_class, exc)
                    print(
                        f"  [!] Search failed for {obj_class} (collected {count} so far): {exc}{hint}",
                        file=sys.stderr,
                    )
                    logger.warning("Paged search failed for %s: %s", obj_class, exc)
                    break
                for entry in conn.entries:
                    obj = _serialize_entry(entry, obj_class)
                    if obj:
                        all_objects.append(obj)
                        if obj["object_sid"] and obj["name"]:
                            sid_map[obj["object_sid"]] = obj["name"]
                        count += 1
                # Check for continuation cookie
                resp_controls = conn.result.get("controls", {})
                paged_ctrl = resp_controls.get("1.2.840.113556.1.4.319", {})
                cookie = paged_ctrl.get("value", {}).get("cookie")
                if not cookie:
                    break
        else:
            # Non-paged search (page_size=0)
            try:
                conn.search(
                    search_base=search_base,
                    search_filter=query["filter"],
                    search_scope=ldap3.SUBTREE,
                    attributes=attrs,
                    controls=controls,
                )
            except (ldap3.core.exceptions.LDAPException, OSError) as exc:
                hint = _attr_error_hint(obj_class, exc)
                print(
                    f"  [!] Search failed for {obj_class}: {exc}{hint}",
                    file=sys.stderr,
                )
                logger.warning("Search failed for %s: %s", obj_class, exc)
                print(f"    Found {count} {obj_class}(s)")
                continue
            for entry in conn.entries:
                obj = _serialize_entry(entry, obj_class)
                if obj:
                    all_objects.append(obj)
                    if obj["object_sid"] and obj["name"]:
                        sid_map[obj["object_sid"]] = obj["name"]
                    count += 1
        print(f"    Found {count} {obj_class}(s)")

        # Stealth: pace between different object type queries
        stealth.ldap_pace()

    # Second pass: resolve trustee SIDs from ACEs that aren't in sid_map yet.
    # First, pre-resolve anything we can without hitting LDAP (well-known SIDs
    # and privileged RIDs).  Then batch the remaining unknowns into OR-filter
    # queries so we don't issue one LDAP round-trip per SID.
    all_trustee_sids: set[str] = set()
    for obj in all_objects:
        for ace in obj.get("dacl", []):
            tsid = ace.get("trustee_sid", "")
            if tsid and tsid not in sid_map:
                all_trustee_sids.add(tsid)

    # Pre-resolve from static maps (no LDAP needed)
    for tsid in list(all_trustee_sids):
        if tsid in WELL_KNOWN_SIDS:
            sid_map[tsid] = WELL_KNOWN_SIDS[tsid]
            all_trustee_sids.discard(tsid)
            continue
        parts = tsid.rsplit("-", 1)
        if len(parts) == 2:
            try:
                rid = int(parts[1])
                if rid in PRIVILEGED_RIDS:
                    sid_map[tsid] = PRIVILEGED_RIDS[rid]
                    all_trustee_sids.discard(tsid)
            except ValueError:
                pass

    # Batch-resolve the rest via LDAP using OR-filters
    unresolved = sorted(all_trustee_sids)
    if unresolved:
        print(f"[*] Resolving {len(unresolved)} unknown trustee SID(s) via LDAP ...")
        resolved = 0
        for i in range(0, len(unresolved), _SID_BATCH_SIZE):
            batch = unresolved[i : i + _SID_BATCH_SIZE]
            or_clauses = "".join(f"(objectSid={s})" for s in batch)
            ldap_filter = f"(|{or_clauses})" if len(batch) > 1 else f"(objectSid={batch[0]})"
            try:
                conn.search(
                    search_base=base_dn,
                    search_filter=ldap_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=["objectSid", "sAMAccountName", "distinguishedName", "name"],
                )
                for entry in conn.entries:
                    a = entry.entry_attributes_as_dict
                    raw_sid = _first(a.get("objectSid", []))
                    if raw_sid and isinstance(raw_sid, bytes):
                        entry_sid = _bytes_to_sid_string(raw_sid)
                    elif raw_sid and isinstance(raw_sid, str) and raw_sid.startswith("S-"):
                        entry_sid = raw_sid
                    else:
                        continue
                    name = (
                        _first(a.get("sAMAccountName", []))
                        or _first(a.get("name", []))
                        or str(entry.entry_dn)
                    )
                    sid_map[entry_sid] = name
                    resolved += 1
            except Exception as exc:
                logger.warning("SID resolution batch error: %s", exc)
        print(f"    Resolved {resolved} of {len(unresolved)} SID(s)")

    # Build output
    output = {
        "meta": {
            "domain": domain,
            "run_as_user": username,
            "dc": dc_host,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "base_method": "DCOnly",
            "collection_method": "DCOnly",
            "object_count": len(all_objects),
            "stealth": stealth.to_dict(),
        },
        "sid_map": sid_map,
        "objects": all_objects,
    }

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_path / f"{domain}_{timestamp}_dconly.json"

    with open(filename, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"[+] Wrote {len(all_objects)} objects to {filename}")
    return filename

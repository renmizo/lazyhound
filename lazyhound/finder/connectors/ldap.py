"""LDAP(S) connector with paged results, retry logic, and multiple auth methods."""

from __future__ import annotations

import logging
import os
import ssl as _ssl
import time
from dataclasses import dataclass, field
from typing import Any

from ldap3 import (
    ALL,
    AUTO_BIND_TLS_BEFORE_BIND,
    GSSAPI,
    NTLM,
    SASL,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPAttributeError, LDAPException, LDAPSocketOpenError

from ..finder_utils import resolve_ip

logger = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 1000
MAX_RETRIES = 3
RETRY_BACKOFF = 2


def detect_domain(dc_host: str, timeout: int = 10) -> str | None:
    """Auto-detect the AD domain via an unauthenticated LDAP rootDSE query.

    Connects to the DC on port 389 without credentials and reads the
    ``defaultNamingContext`` attribute (e.g. ``DC=corp,DC=local``), then
    converts it to a DNS-style domain name (``corp.local``).

    Returns ``None`` if detection fails.
    """
    try:
        srv = Server(dc_host, port=389, use_ssl=False, get_info=ALL,
                     connect_timeout=timeout)
        conn = Connection(srv, auto_bind=True, read_only=True,
                          receive_timeout=timeout)
        info = srv.info
        conn.unbind()
        if info and info.other and "defaultNamingContext" in info.other:
            dn = info.other["defaultNamingContext"][0]
            # Convert "DC=corp,DC=local" → "corp.local"
            parts = []
            for component in dn.split(","):
                component = component.strip()
                if component.upper().startswith("DC="):
                    parts.append(component[3:])
            if parts:
                return ".".join(parts)
    except Exception as exc:
        logger.debug("Domain auto-detect failed on %s: %s", dc_host, exc)
    return None


def _ntlm_bind_secret(password: str, nthash: str) -> str:
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


@dataclass
class LDAPConfig:
    server: str = ""
    port: int = 389
    use_ssl: bool = False
    username: str = ""
    password: str = ""
    domain: str = ""
    auth_method: str = "ntlm"
    nthash: str = ""
    ccache: str = ""
    validate_cert: bool = True
    page_size: int = DEFAULT_PAGE_SIZE
    timeout: int = 30
    use_start_tls: bool = True
    auto_negotiate: bool = False


@dataclass
class LDAPConnector:
    config: LDAPConfig
    _conn: Connection | None = field(default=None, init=False, repr=False)
    _srv: Server | None = field(default=None, init=False, repr=False)
    _base_dn: str = field(default="", init=False)

    # -- base DN --

    @property
    def base_dn(self) -> str:
        if self._base_dn:
            return self._base_dn
        if self.config.domain:
            self._base_dn = ",".join(
                f"DC={p}" for p in self.config.domain.split(".")
            )
        return self._base_dn

    @base_dn.setter
    def base_dn(self, v: str) -> None:
        self._base_dn = v

    # -- connect / close --

    def _build_tls_config(self) -> Tls:
        """Build a TLS configuration object."""
        if not self.config.validate_cert:
            logger.warning(
                "TLS certificate validation is DISABLED — connection is vulnerable to MITM attacks"
            )
        return Tls(
            validate=_ssl.CERT_REQUIRED if self.config.validate_cert else _ssl.CERT_NONE,
        )

    def connect(self) -> None:
        if self.config.auto_negotiate:
            self._connect_auto_negotiate()
        else:
            self._connect_single()

    def _connect_auto_negotiate(self) -> None:
        """Try LDAPS (636), then LDAP+STARTTLS (389), then plain LDAP (389).

        Suppresses per-attempt retry noise — only logs the final method used.
        """
        old_level = logger.level
        # Suppress retry warnings during auto-negotiate — they're expected
        logger.setLevel(max(old_level, logging.ERROR))

        # First attempt: LDAPS on 636
        try:
            self.config.port = 636
            self.config.use_ssl = True
            self.config.use_start_tls = False
            self._connect_single()
            logger.setLevel(old_level)
            return
        except (LDAPException, OSError):
            pass

        # Second attempt: LDAP + STARTTLS on 389
        try:
            self.config.port = 389
            self.config.use_ssl = False
            self.config.use_start_tls = True
            self._connect_single()
            logger.setLevel(old_level)
            return
        except (LDAPException, OSError):
            pass

        # Third attempt: plain LDAP on 389 (no encryption)
        logger.setLevel(old_level)
        logger.info(
            "Using plain LDAP (389) with no encryption on %s",
            self.config.server,
        )
        self.config.port = 389
        self.config.use_ssl = False
        self.config.use_start_tls = False
        self._connect_single()

    def _connect_single(self) -> None:
        # Determine TLS config: needed for both LDAPS and STARTTLS
        needs_tls = self.config.use_ssl or self.config.use_start_tls
        tls_config = self._build_tls_config() if needs_tls else None

        resolved_ip = resolve_ip(self.config.server, logger)

        self._srv = Server(
            self.config.server,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            get_info=ALL,
            tls=tls_config,
            connect_timeout=self.config.timeout,
        )
        auth, user, pw = self._resolve_auth()

        # Kerberos: GSSAPI reads the TGT from KRB5CCNAME. The 'gssapi' package
        # (plus system krb5 libraries) is required but kept optional — imported
        # lazily here so non-Kerberos runs never need it.
        sasl_mech = None
        if auth is SASL:
            sasl_mech = GSSAPI
            if self.config.ccache:
                os.environ["KRB5CCNAME"] = self.config.ccache
            try:
                import gssapi  # noqa: F401
            except ImportError as exc:
                raise LDAPException(
                    "Kerberos requires the 'gssapi' package: "
                    "pip install gssapi (and system krb5 libraries)."
                ) from exc

        # Use STARTTLS (TLS_BEFORE_BIND) on port 389 to satisfy DC signing
        # requirements without needing NTLM-level message signing.
        use_starttls = (
            self.config.use_start_tls
            and not self.config.use_ssl  # already encrypted, no need
        )
        auto_bind = AUTO_BIND_TLS_BEFORE_BIND if use_starttls else True

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._conn = Connection(
                    self._srv,
                    user=user,
                    password=pw,
                    authentication=auth,
                    sasl_mechanism=sasl_mech,
                    auto_bind=auto_bind,
                    receive_timeout=self.config.timeout,
                )
                mode = "STARTTLS" if use_starttls else ("LDAPS" if self.config.use_ssl else "LDAP")
                ip_info = f" [{resolved_ip}]" if resolved_ip != self.config.server else ""
                logger.info("Connected to %s%s:%d (%s)", self.config.server, ip_info, self.config.port, mode)
                if not self._base_dn and self._srv.info:
                    nc = self._srv.info.naming_contexts
                    if nc:
                        self._base_dn = str(nc[0])
                return
            except (LDAPException, OSError) as exc:
                is_conn_reset = isinstance(exc, ConnectionResetError) or (
                    isinstance(exc, OSError) and getattr(exc, "errno", None) == 104
                )
                if attempt == MAX_RETRIES:
                    if is_conn_reset:
                        hint = (
                            "The DC enforces LDAP channel binding (CBT) for LDAPS. "
                            "Try --no-ssl (port 389 with STARTTLS)."
                        ) if self.config.use_ssl else (
                            "The DC requires LDAP signing which ldap3 cannot negotiate. "
                            "Ensure STARTTLS is enabled (default), or try --auth simple."
                        )
                        raise ConnectionResetError(
                            f"Connection reset by {self.config.server}:{self.config.port}. {hint}"
                        ) from exc
                    raise
                wait = RETRY_BACKOFF ** attempt
                logger.debug("Attempt %d failed: %s.  Retry in %ds", attempt, exc, wait)
                time.sleep(wait)

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.unbind()
            except LDAPException:
                pass
            self._conn = None

    def __enter__(self) -> LDAPConnector:
        self.connect()
        return self

    def __exit__(self, *a: Any) -> None:
        self.close()

    # -- reconnect --

    def _reconnect(self) -> bool:
        """Attempt to re-establish the LDAP connection after a socket failure.

        Returns True if reconnection succeeded.
        """
        try:
            self.close()
            self.connect()
            return self._conn is not None and self._conn.bound
        except (LDAPException, OSError) as exc:
            logger.warning("Reconnect attempt failed: %s", exc)
            return False

    # -- auth helpers --

    def _resolve_auth(self) -> tuple[Any, Any, Any]:
        m = self.config.auth_method.lower()
        # A Kerberos ccache forces GSSAPI; an nthash forces NTLM (pass-the-hash
        # can't use a SIMPLE bind). Either overrides an empty/'simple' method.
        if self.config.ccache:
            m = "kerberos"
        elif self.config.nthash and m not in ("ntlm", "kerberos"):
            m = "ntlm"
        if m == "kerberos":
            # GSSAPI reads the TGT from KRB5CCNAME; ldap3 derives ldap/<host>.
            return SASL, None, None
        if m == "ntlm":
            user = f"{self.config.domain}\\{self.config.username}"
            pw = _ntlm_bind_secret(self.config.password, self.config.nthash)
            return NTLM, user, pw
        # SIMPLE bind — UPN format avoids MD4/NTLM issues on OpenSSL 3.0+
        user = f"{self.config.username}@{self.config.domain}" if self.config.domain else self.config.username
        return SIMPLE, user, self.config.password

    # -- search --

    def search(
        self,
        search_filter: str,
        attributes: list[str] | str = "*",
        search_base: str | None = None,
        scope: Any = SUBTREE,
    ) -> list[dict[str, Any]]:
        """Paged LDAP search returning all results."""
        if not self._conn:
            raise RuntimeError("Not connected")
        base = search_base or self.base_dn
        all_entries: list[dict[str, Any]] = []
        cookie: bytes | None = None
        attrs = attributes if isinstance(attributes, list) else [attributes]
        partial = False

        while True:
            try:
                self._conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attrs,
                    paged_size=self.config.page_size,
                    paged_cookie=cookie,
                )
            except LDAPAttributeError as exc:
                # Schema doesn't have the requested attribute (e.g. LAPS not installed).
                # This is benign — return whatever we have so far (usually nothing).
                logger.debug(
                    "Attribute not in schema, skipping search: %s", exc,
                )
                partial = True
                break
            except (LDAPException, OSError) as exc:
                # If socket is dead, attempt one reconnect before giving up
                is_socket_dead = isinstance(exc, (LDAPSocketOpenError, TimeoutError)) or (
                    isinstance(exc, OSError) and "timed out" in str(exc)
                )
                if is_socket_dead and not cookie:
                    # Only retry on the first page — mid-paging reconnect
                    # would restart from scratch and duplicate entries.
                    logger.warning(
                        "Socket error on search, attempting reconnect: %s", exc
                    )
                    if self._reconnect():
                        try:
                            self._conn.search(
                                search_base=base,
                                search_filter=search_filter,
                                search_scope=scope,
                                attributes=attrs,
                                paged_size=self.config.page_size,
                                paged_cookie=cookie,
                            )
                        except (LDAPException, OSError):
                            logger.exception(
                                "Search failed after reconnect (partial=%d entries): %s",
                                len(all_entries), search_filter,
                            )
                            partial = True
                            break
                    else:
                        logger.error(
                            "Reconnect failed, search aborted (partial=%d entries): %s",
                            len(all_entries), search_filter,
                        )
                        partial = True
                        break
                else:
                    logger.exception(
                        "Search failed (partial=%d entries): %s",
                        len(all_entries), search_filter,
                    )
                    partial = True
                    break

            for entry in self._conn.entries:
                d: dict[str, Any] = {"dn": str(entry.entry_dn)}
                for attr in entry.entry_attributes:
                    val = entry[attr].value
                    if isinstance(val, list):
                        d[str(attr)] = [v if isinstance(v, bytes) else str(v) for v in val]
                    elif isinstance(val, bytes):
                        d[str(attr)] = val
                    else:
                        d[str(attr)] = str(val) if val is not None else None
                all_entries.append(d)

            controls = self._conn.result.get("controls", {})
            paged = controls.get("1.2.840.113556.1.4.319", {})
            cookie = (paged.get("value") or {}).get("cookie")
            if not cookie:
                break

        if partial and all_entries:
            logger.warning(
                "Search returned partial results (%d entries) for: %s",
                len(all_entries), search_filter,
            )
        logger.debug("Search returned %d entries", len(all_entries))
        return all_entries

    def get_domain_sid(self) -> str:
        results = self.search(
            "(objectClass=domain)", ["objectSid"], search_base=self.base_dn
        )
        if results and "objectSid" in results[0]:
            raw = results[0]["objectSid"]
            if isinstance(raw, bytes):
                from ..security import parse_sid
                sid, _ = parse_sid(raw)
                return str(sid)
            return str(raw)
        return ""

    def get_root_dse(self) -> dict[str, Any]:
        """Read rootDSE for domain functional level, forest, etc."""
        if not self._srv or not self._srv.info:
            return {}
        info = self._srv.info
        result: dict[str, Any] = {}
        if hasattr(info, "other") and info.other:
            for k, v in info.other.items():
                result[k] = v
        return result

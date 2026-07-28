"""Scan context — the runtime object passed to every check."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from lazyhound.finder.connectors.ldap import LDAPConnector
from lazyhound.finder.connectors.dns import DNSConnector
from lazyhound.finder.stealth import StealthConfig


@dataclass
class ScanContext:
    """Provides connectors, domain metadata, and a shared query cache."""

    ldap: LDAPConnector
    dns: DNSConnector | None = None
    domain_dn: str = ""
    domain_sid: str = ""
    dc_hostname: str = ""
    dc_ip: str = ""
    domain_functional_level: str = ""
    forest_name: str = ""
    config_naming_ctx: str = ""  # from rootDSE configurationNamingContext
    stealth: StealthConfig = field(default_factory=StealthConfig)
    _cache: dict[str, Any] = field(default_factory=dict, repr=False)
    _cache_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def configuration_dn(self) -> str:
        """Return the Configuration partition DN.

        Uses rootDSE configurationNamingContext when available (correct for
        child domains in a multi-domain forest).  Falls back to constructing
        it from domain_dn.
        """
        if self.config_naming_ctx:
            return self.config_naming_ctx
        return f"CN=Configuration,{self.domain_dn}"

    def cached_search(
        self, key: str, search_filter: str, attributes: list[str]
    ) -> list[dict[str, Any]]:
        with self._cache_lock:
            if key in self._cache:
                return self._cache[key]
        # Perform search outside lock to avoid holding it during I/O
        results = self.ldap.search(search_filter, attributes)
        with self._cache_lock:
            # Double-check: another thread may have populated while we searched
            if key not in self._cache:
                self._cache[key] = results
            return self._cache[key]

    # -- common queries used by many checks --

    def get_all_users(self) -> list[dict[str, Any]]:
        return self.cached_search(
            "all_users",
            "(&(objectClass=user)(!(objectClass=computer)))",
            [
                "sAMAccountName", "distinguishedName", "userAccountControl",
                "pwdLastSet", "lastLogonTimestamp", "memberOf",
                "servicePrincipalName", "adminCount", "description",
                "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        )

    def get_all_computers(self) -> list[dict[str, Any]]:
        return self.cached_search(
            "all_computers",
            "(objectClass=computer)",
            [
                "sAMAccountName", "distinguishedName", "userAccountControl",
                "operatingSystem", "operatingSystemVersion",
                "servicePrincipalName", "dNSHostName", "lastLogonTimestamp",
                "msDS-AllowedToDelegateTo",
            ],
        )

    def get_domain_controllers(self) -> list[dict[str, Any]]:
        return self.cached_search(
            "dcs",
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            [
                "sAMAccountName", "distinguishedName", "dNSHostName",
                "operatingSystem", "operatingSystemVersion",
            ],
        )

    def get_privileged_groups(self) -> list[str]:
        return [
            f"CN=Domain Admins,CN=Users,{self.domain_dn}",
            f"CN=Enterprise Admins,CN=Users,{self.domain_dn}",
            f"CN=Schema Admins,CN=Users,{self.domain_dn}",
            f"CN=Administrators,CN=Builtin,{self.domain_dn}",
            f"CN=Backup Operators,CN=Builtin,{self.domain_dn}",
            f"CN=Account Operators,CN=Builtin,{self.domain_dn}",
            f"CN=Server Operators,CN=Builtin,{self.domain_dn}",
        ]

    def get_domain_admins(self) -> list[dict[str, Any]]:
        da_dn = f"CN=Domain Admins,CN=Users,{self.domain_dn}"
        return self.cached_search(
            "domain_admins",
            f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={da_dn}))",
            ["sAMAccountName", "distinguishedName", "adminCount", "pwdLastSet"],
        )

    # -- ADCS queries (shared across ESC checks) --

    def get_certificate_templates(self) -> list[dict[str, Any]]:
        """All certificate templates from the Configuration partition."""
        key = "certificate_templates"
        with self._cache_lock:
            if key in self._cache:
                return self._cache[key]
        results = self.ldap.search(
            "(objectClass=pKICertificateTemplate)",
            [
                "cn", "displayName", "nTSecurityDescriptor",
                "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage",
                "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                "msPKI-Certificate-Policy", "msPKI-Template-Schema-Version",
            ],
            search_base=self.configuration_dn,
        )
        with self._cache_lock:
            if key not in self._cache:
                self._cache[key] = results
            return self._cache[key]

    def get_enrollment_services(self) -> list[dict[str, Any]]:
        """All CA enrollment service objects from the Configuration partition."""
        key = "enrollment_services"
        with self._cache_lock:
            if key in self._cache:
                return self._cache[key]
        results = self.ldap.search(
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "certificateTemplates", "nTSecurityDescriptor", "flags"],
            search_base=self.configuration_dn,
        )
        with self._cache_lock:
            if key not in self._cache:
                self._cache[key] = results
            return self._cache[key]

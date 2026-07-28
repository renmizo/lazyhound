"""DNS connector for AD-related DNS queries and zone transfer checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import dns.resolver
import dns.query
import dns.zone
import dns.exception

from ..stealth import StealthConfig
from ..finder_utils import resolve_ip

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10


@dataclass
class DNSConnector:
    """Queries AD-integrated DNS for SRV records, zone transfers, and dangling entries."""

    nameserver: str
    domain: str
    timeout: int = DEFAULT_TIMEOUT
    stealth: StealthConfig = field(default_factory=StealthConfig)

    def __post_init__(self) -> None:
        resolve_ip(self.nameserver, logger)

    def resolve(self, qname: str, rdtype: str = "A") -> list[str]:
        """Resolve a DNS record."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.nameserver]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(qname, rdtype)
            return [str(r) for r in answers]
        except dns.exception.DNSException as exc:
            logger.debug("DNS resolve %s %s failed: %s", qname, rdtype, exc)
            return []

    def get_dc_srv_records(self) -> list[str]:
        """Get domain controller SRV records."""
        self.stealth.dns_pace()
        return self.resolve(f"_ldap._tcp.dc._msdcs.{self.domain}", "SRV")

    def get_gc_srv_records(self) -> list[str]:
        """Get global catalog SRV records.

        Skipped when ``stealth.skip_gc_lookup`` is True.
        """
        if self.stealth.skip_gc_lookup:
            logger.info("Skipping GC SRV lookup (stealth.skip_gc_lookup)")
            return []
        self.stealth.dns_pace()
        return self.resolve(f"_gc._tcp.{self.domain}", "SRV")

    def get_kerberos_srv_records(self) -> list[str]:
        """Get Kerberos KDC SRV records.

        Skipped when ``stealth.skip_kerberos_lookup`` is True.
        """
        if self.stealth.skip_kerberos_lookup:
            logger.info("Skipping Kerberos SRV lookup (stealth.skip_kerberos_lookup)")
            return []
        self.stealth.dns_pace()
        return self.resolve(f"_kerberos._tcp.{self.domain}", "SRV")

    def attempt_zone_transfer(self) -> dict[str, Any] | None:
        """Attempt AXFR zone transfer — should fail in a secure environment."""
        try:
            resolved = resolve_ip(self.nameserver, logger)
            logger.info("Attempting zone transfer to %s [%s] for %s", self.nameserver, resolved, self.domain)
            z = dns.zone.from_xfr(
                dns.query.xfr(self.nameserver, self.domain, timeout=self.timeout)
            )
            records = {}
            for name, node in z.nodes.items():
                records[str(name)] = [str(r) for rdataset in node.rdatasets for r in rdataset]
            logger.warning("Zone transfer succeeded for %s — insecure!", self.domain)
            return records
        except dns.exception.DNSException:
            logger.debug("Zone transfer denied (expected)")
            return None

    def check_wildcard_record(self) -> bool:
        """Check if a wildcard DNS record exists."""
        import uuid

        random_host = f"adtool-probe-{uuid.uuid4().hex[:8]}.{self.domain}"
        results = self.resolve(random_host, "A")
        return len(results) > 0

    def get_spf_record(self) -> str | None:
        """Retrieve SPF record for the domain."""
        results = self.resolve(self.domain, "TXT")
        for r in results:
            if "v=spf1" in r.lower():
                return r
        return None

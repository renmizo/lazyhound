"""Patch-level CVE advisories.

These CVEs cannot be confirmed from LDAP/collected data alone — exploitability
depends on the DC's patch level, which is not exposed over LDAP. The checks
therefore emit **advisories** (INFO): they flag the *precondition* (an affected
OS is present, or a delegation surface exists) and tell the operator what to
verify. They deliberately do not claim the environment is vulnerable.
"""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import (
    CheckCategory, Finding, MitreAttack, Remediation, Severity,
)

# OS strings affected by ZeroLogon (Netlogon). Server 2022/2025 shipped after
# the fix and are not affected, so they are intentionally absent.
_ZEROLOGON_AFFECTED_OS = (
    "Server 2008 R2", "Server 2012", "Server 2016", "Server 2019",
)


@register_check(
    check_id="patch_001",
    name="ZeroLogon Advisory (CVE-2020-1472)",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Flags DCs on affected OS versions to verify the ZeroLogon patch/enforcement",
    tags=["advisory", "netlogon", "privilege_escalation"],
)
def check_zerologon_advisory(ctx) -> list[Finding]:
    dcs = ctx.get_domain_controllers()
    affected = []
    for dc in dcs:
        os_name = dc.get("operatingSystem", "") or ""
        if any(p in os_name for p in _ZEROLOGON_AFFECTED_OS):
            host = dc.get("dNSHostName") or dc.get("sAMAccountName", "?")
            affected.append(f"{host} ({os_name})")
    if not affected:
        return []
    return [Finding(
        title=f"ZeroLogon Advisory — {len(affected)} DC(s) on affected OS",
        description=(
            "Domain controllers run OS versions affected by ZeroLogon "
            "(CVE-2020-1472), a Netlogon flaw that lets an unauthenticated "
            "attacker with network access reset the DC machine account and "
            "escalate to Domain Admin. Scored CRITICAL by impact (unauthenticated "
            "domain takeover, CVSS 10.0), not by confirmability — patch level is "
            "not visible over LDAP, so verify the August 2020 update is installed "
            "AND Netlogon is in enforcement mode (FullSecureChannelProtection)."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="patch_001",
        affected_objects=affected,
        mitre=MitreAttack(
            "T1210", "Exploitation of Remote Services", "Lateral Movement",
            known_tools=("zerologon", "CVE-2020-1472 PoC", "Impacket secretsdump"),
        ),
        remediation=Remediation(
            "Apply the Aug-2020 (or later) cumulative update on all DCs and "
            "enable Netlogon enforcement mode",
        ),
    )]


@register_check(
    check_id="patch_002",
    name="Bronze Bit Advisory (CVE-2020-17049)",
    category=CheckCategory.DELEGATION,
    description="Flags a delegation surface to verify the Bronze Bit (Kerberos S4U) patch",
    tags=["advisory", "kerberos", "delegation"],
)
def check_bronze_bit_advisory(ctx) -> list[Finding]:
    if not getattr(ctx, "ldap", None):
        return []
    results = ctx.ldap.search(
        "(&(msDS-AllowedToDelegateTo=*))",
        ["sAMAccountName", "msDS-AllowedToDelegateTo"],
    ) or []
    accounts = [e.get("sAMAccountName", "?") for e in results]
    if not accounts:
        return []
    return [Finding(
        title=f"Bronze Bit Advisory — {len(accounts)} constrained-delegation account(s)",
        description=(
            "Constrained delegation is configured in this domain. Bronze Bit "
            "(CVE-2020-17049) lets an attacker who controls such an account "
            "forge the S4U2self service ticket to bypass the "
            "'sensitive / cannot be delegated' and Protected Users protections "
            "and impersonate those users. Patch level is not visible over LDAP "
            "— verify the November 2020 update (PerformTicketSignature "
            "enforcement) is installed on all DCs."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.DELEGATION,
        check_id="patch_002",
        affected_objects=accounts,
        mitre=MitreAttack(
            "T1558.003", "Kerberoasting / S4U abuse", "Credential Access",
            known_tools=("Rubeus s4u /bronzebit", "Impacket getST -force-forwardable"),
        ),
        remediation=Remediation(
            "Apply the Nov-2020 (or later) cumulative update on all DCs "
            "(enforces PerformTicketSignature)",
        ),
    )]

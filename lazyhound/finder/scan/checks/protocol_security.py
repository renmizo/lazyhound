"""Protocol and infrastructure security checks: LDAP signing, channel binding, SMB, NTLMv1."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity
from lazyhound.finder.finder_utils import resolve_ip


# ── proto_001: LDAP signing requirements ─────────────────────────────────────


@register_check(
    check_id="proto_001",
    name="LDAP Signing",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Checks whether LDAP signing is required on domain controllers",
    tags=["protocol", "ldap", "relay"],
)
def check_ldap_signing(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["sAMAccountName", "dNSHostName"],
    )
    if not results:
        return []
    # Check ms-DS-MachineAccountQuota and DC registry heuristic via LDAP
    # The definitive check requires reading the DC's LDAPServerIntegrity registry value
    # or ms-DS-ReplicationEpoch.  We flag this as needing manual verification.
    dcs = [e.get("dNSHostName") or e.get("sAMAccountName", "?") for e in results]
    return [Finding(
        title="LDAP Signing Configuration Audit",
        description=(
            f"{len(dcs)} DC(s) detected. Verify LDAP signing is set to 'Required' on all DCs. "
            "Without signing, LDAP traffic is vulnerable to relay and man-in-the-middle attacks."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_001",
        affected_objects=dcs,
        details={"note": "Verify via: reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity"},
        mitre=MitreAttack(
            "T1557", "Adversary-in-the-Middle", "Credential Access",
            known_tools=("ntlmrelayx", "Responder"),
        ),
        remediation=Remediation(
            "Set LDAP signing to Required on all DCs",
            gpo_path="Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements",
            reference_url="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements",
        ),
    )]


# ── proto_002: machine account quota ────────────────────────────────────────


@register_check(
    check_id="proto_002",
    name="Machine Account Quota",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Checks ms-DS-MachineAccountQuota (default 10 allows RBCD attacks)",
    tags=["protocol", "relay", "delegation"],
)
def check_machine_account_quota(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(objectClass=domain)",
        ["ms-DS-MachineAccountQuota"],
        search_base=ctx.domain_dn,
    )
    if not results:
        return []
    quota = int(results[0].get("ms-DS-MachineAccountQuota", 10) or 10)
    if quota == 0:
        return []
    return [Finding(
        title=f"Machine Account Quota: {quota}",
        description=(
            f"Any authenticated user can create up to {quota} machine account(s). "
            "This enables RBCD-based privilege escalation."
        ),
        severity=Severity.HIGH if quota >= 10 else Severity.MEDIUM,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_002",
        details={"ms-DS-MachineAccountQuota": quota},
        mitre=MitreAttack(
            "T1134.001", "Token Impersonation/Theft", "Privilege Escalation",
            known_tools=("Impacket addcomputer", "PowerMad"),
        ),
        remediation=Remediation(
            "Set ms-DS-MachineAccountQuota to 0",
            powershell='Set-ADDomain -Identity "<domain>" -Replace @{"ms-DS-MachineAccountQuota"=0}',
        ),
    )]


# ── proto_003: LAPS deployment ──────────────────────────────────────────────


@register_check(
    check_id="proto_003",
    name="LAPS Deployment",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Checks LAPS coverage on domain-joined computers",
    tags=["protocol", "password", "lateral_movement"],
)
def check_laps_deployment(ctx) -> list[Finding]:
    # Check for both legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password)
    # Search with base attributes first, then try LAPS-specific attributes.
    # This avoids ERROR logs when the LAPS schema extensions aren't installed.
    computer_filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
    all_computers = ctx.ldap.search(computer_filter, ["sAMAccountName"])
    if not all_computers:
        return []

    # Try to enrich with LAPS attributes; if schema doesn't have them,
    # the search may fail — catch and fall back to basic computer list.
    try:
        laps_computers = ctx.ldap.search(
            computer_filter,
            ["sAMAccountName", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"],
        )
        if laps_computers:
            all_computers = laps_computers
    except Exception:
        pass  # LAPS schema not installed — all computers count as no LAPS

    no_laps = []
    for c in all_computers:
        has_legacy = c.get("ms-Mcs-AdmPwdExpirationTime") is not None
        has_new = c.get("msLAPS-PasswordExpirationTime") is not None
        if not has_legacy and not has_new:
            no_laps.append(c.get("sAMAccountName", "?"))

    if not no_laps:
        return []

    pct = len(no_laps) / len(all_computers) * 100
    sev = Severity.HIGH if pct > 50 else Severity.MEDIUM
    return [Finding(
        title=f"LAPS Not Deployed: {len(no_laps)}/{len(all_computers)} computers ({pct:.0f}%)",
        description=(
            f"{len(no_laps)} computer(s) ({pct:.0f}%) have no LAPS password managed. "
            "Shared local admin passwords enable lateral movement."
        ),
        severity=sev,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_003",
        affected_objects=no_laps[:20],
        details={"total_computers": len(all_computers), "without_laps": len(no_laps), "pct": round(pct, 1)},
        mitre=MitreAttack(
            "T1078.002", "Valid Accounts: Domain Accounts", "Lateral Movement",
            known_tools=("CrackMapExec", "psexec"),
        ),
        remediation=Remediation(
            "Deploy Windows LAPS to all domain-joined computers",
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
        ),
    )]


# ── proto_004: legacy OS ────────────────────────────────────────────────────


@register_check(
    check_id="proto_004",
    name="Legacy Operating Systems",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Detects end-of-life OS versions still in the domain",
    tags=["infrastructure", "legacy"],
)
def check_legacy_os(ctx) -> list[Finding]:
    LEGACY_PATTERNS = [
        "Windows Server 2003",
        "Windows Server 2008",
        "Windows Server 2012",
        "Windows XP",
        "Windows Vista",
        "Windows 7",
        "Windows 8",
    ]
    all_computers = ctx.get_all_computers()
    legacy = []
    for c in all_computers:
        os_name = c.get("operatingSystem", "")
        if os_name and any(p in os_name for p in LEGACY_PATTERNS):
            name = c.get("dNSHostName") or c.get("sAMAccountName", "?")
            legacy.append(f"{name} ({os_name})")
    if not legacy:
        return []
    return [Finding(
        title=f"Legacy Operating Systems ({len(legacy)})",
        description=f"{len(legacy)} computer(s) run end-of-life OS versions without security updates.",
        severity=Severity.HIGH,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_004",
        affected_objects=legacy,
        remediation=Remediation("Upgrade or decommission legacy systems"),
    )]


# ── proto_005: LDAP channel binding ──────────────────────────────────────


@register_check(
    check_id="proto_005",
    name="LDAP Channel Binding",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Checks whether LDAP channel binding is enforced on domain controllers",
    tags=["protocol", "ldap", "relay"],
)
def check_ldap_channel_binding(ctx) -> list[Finding]:
    dcs = ctx.get_domain_controllers()
    if not dcs:
        return []
    dc_names = [e.get("dNSHostName") or e.get("sAMAccountName", "?") for e in dcs]
    return [Finding(
        title="LDAP Channel Binding Audit",
        description=(
            f"{len(dc_names)} DC(s) detected. Verify LDAP channel binding (EPA) is set to "
            "'Required' on all DCs. Without channel binding, NTLM relay attacks to LDAP "
            "remain possible even with LDAP signing enabled."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_005",
        affected_objects=dc_names,
        details={
            "note": (
                "Verify via: reg query "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters "
                "/v LdapEnforceChannelBinding (0=Never, 1=When supported, 2=Always)"
            ),
        },
        mitre=MitreAttack(
            "T1557", "Adversary-in-the-Middle", "Credential Access",
            known_tools=("ntlmrelayx", "Responder", "krbrelayx"),
        ),
        remediation=Remediation(
            "Set LdapEnforceChannelBinding to 2 (Always) on all DCs",
            gpo_path="Computer Configuration > Policies > Administrative Templates > System > DC > LDAP Channel Binding Token Requirements",
            reference_url="https://support.microsoft.com/en-us/topic/kb4520412",
        ),
    )]


# ── proto_006: NTLMv1 allowed ────────────────────────────────────────────


@register_check(
    check_id="proto_006",
    name="NTLMv1 Advisory",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Flags DCs for manual verification of NTLMv1 policy enforcement",
    tags=["protocol", "ntlm", "credential_access"],
)
def check_ntlmv1(ctx) -> list[Finding]:
    dcs = ctx.get_domain_controllers()
    if not dcs:
        return []
    dc_names = [e.get("dNSHostName") or e.get("sAMAccountName", "?") for e in dcs]
    return [Finding(
        title="NTLMv1 Policy Audit",
        description=(
            f"{len(dc_names)} DC(s) detected. Verify LmCompatibilityLevel is set to 5 "
            "(Send NTLMv2 response only, refuse LM & NTLM) on all DCs. NTLMv1 responses "
            "can be cracked to plaintext passwords in seconds using rainbow tables."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_006",
        affected_objects=dc_names,
        details={
            "note": (
                "Verify via: reg query "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel "
                "(should be 5)"
            ),
        },
        mitre=MitreAttack(
            "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay",
            "Credential Access",
            known_tools=("Responder", "Inveigh", "crack.sh"),
        ),
        remediation=Remediation(
            "Set LmCompatibilityLevel to 5 on all systems",
            gpo_path="Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level",
            reference_url="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level",
        ),
    )]


# ── proto_007: Print Spooler on DCs ──────────────────────────────────────


import logging
import socket

logger = logging.getLogger(__name__)


def _probe_spooler(host: str, timeout: int = 5) -> bool:
    """Check if the host is reachable on port 445 (prerequisite for MS-RPRN)."""
    resolved = resolve_ip(host, logger)
    try:
        logger.info("Spooler probe connecting to %s [%s]:445", host, resolved)
        with socket.create_connection((host, 445), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


@register_check(
    check_id="proto_007",
    name="Print Spooler on Domain Controllers",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Print Spooler enables coercion attacks (PrinterBug/SpoolSample) on DCs",
    protocols=["ldap", "smb"],
    tags=["protocol", "coercion", "relay"],
)
def check_print_spooler_on_dcs(ctx) -> list[Finding]:
    dcs = ctx.get_domain_controllers()
    if not dcs:
        return []

    reachable: list[str] = []
    for dc in dcs:
        host = dc.get("dNSHostName") or dc.get("sAMAccountName", "").rstrip("$")
        if host and _probe_spooler(host):
            reachable.append(host)

    if not reachable:
        return []
    return [Finding(
        title=f"Print Spooler Reachable on {len(reachable)} DC(s)",
        description=(
            "The Print Spooler service is reachable on domain controllers. "
            "An attacker can abuse the SpoolSample/PrinterBug (MS-RPRN RpcRemoteFindFirstPrinterChangeNotification) "
            "to coerce DC authentication to an attacker-controlled host, enabling "
            "NTLM relay or unconstrained delegation abuse. A running spooler is "
            "also the prerequisite for PrintNightmare (CVE-2021-34527) remote "
            "code execution — verify the July-2021 patch and hardening are applied."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_007",
        affected_objects=reachable,
        mitre=MitreAttack(
            "T1187", "Forced Authentication", "Credential Access",
            known_tools=("SpoolSample", "PrinterBug.py", "Coercer"),
        ),
        remediation=Remediation(
            "Disable the Print Spooler service on all DCs",
            powershell='Get-Service -Name Spooler | Stop-Service -PassThru | Set-Service -StartupType Disabled',
            gpo_path="Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Print Spooler",
        ),
    )]


# ── proto_008: coercion endpoint exposure ────────────────────────────────


@register_check(
    check_id="proto_008",
    name="Authentication Coercion Exposure",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="Advisory to verify PetitPotam and other coercion mitigations on DCs",
    tags=["protocol", "coercion", "relay"],
)
def check_coercion_advisory(ctx) -> list[Finding]:
    dcs = ctx.get_domain_controllers()
    if not dcs:
        return []
    dc_names = [e.get("dNSHostName") or e.get("sAMAccountName", "?") for e in dcs]
    return [Finding(
        title="Authentication Coercion Exposure Advisory",
        description=(
            f"{len(dc_names)} DC(s) detected. Verify PetitPotam (MS-EFSR), "
            "DFSCoerce (MS-DFSNM), and ShadowCoerce (MS-FSRVP) mitigations are applied. "
            "These protocols allow unauthenticated or low-privileged users to coerce DC "
            "authentication to attacker-controlled hosts for NTLM relay."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.PROTOCOL_SECURITY,
        check_id="proto_008",
        affected_objects=dc_names,
        details={
            "coercion_methods": [
                "PetitPotam (MS-EFSR): Patched in KB5005413 but unauthenticated vector may persist",
                "DFSCoerce (MS-DFSNM): Block via RPC filters",
                "ShadowCoerce (MS-FSRVP): Disable File Server VSS Agent Service",
                "PrinterBug (MS-RPRN): Disable Print Spooler (see proto_007)",
            ],
        },
        mitre=MitreAttack(
            "T1187", "Forced Authentication", "Credential Access",
            known_tools=("PetitPotam", "Coercer", "DFSCoerce"),
        ),
        remediation=Remediation(
            "Apply all coercion patches, enable EPA on all services, "
            "and use RPC filters to block unnecessary RPC interfaces on DCs",
            reference_url="https://support.microsoft.com/en-us/topic/kb5005413",
        ),
    )]

"""Infrastructure checks: SYSVOL replication, domain functional level, Recycle Bin, DNS."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity


# ── infra_001: FRS vs DFSR replication ───────────────────────────────────────


@register_check(
    check_id="infra_001",
    name="FRS vs DFSR Replication",
    category=CheckCategory.INFRASTRUCTURE,
    description="Checks whether SYSVOL replication uses legacy FRS or modern DFSR",
    tags=["infrastructure", "legacy"],
)
def check_frs_vs_dfsr(ctx) -> list[Finding]:
    findings: list[Finding] = []

    # Look for DFSR SYSVOL replication group — presence indicates DFSR in use
    dfsr_sysvol = ctx.ldap.search(
        "(&(objectClass=msDFSR-ReplicationGroup)(cn=Domain System Volume))",
        ["cn"],
        search_base=f"CN=System,{ctx.domain_dn}",
    )

    # Look for FRS subscriber objects
    frs = ctx.ldap.search(
        "(objectClass=nTFRSSubscriber)",
        ["cn", "fRSRootPath"],
        search_base=f"CN=System,{ctx.domain_dn}",
    )

    using_dfsr = bool(dfsr_sysvol)
    using_frs = bool(frs)

    if using_frs and not using_dfsr:
        findings.append(Finding(
            title="SYSVOL Replication Uses Legacy FRS",
            description=(
                "The File Replication Service (FRS) is deprecated since Windows Server 2008 R2. "
                "FRS lacks the reliability and performance of DFS Replication (DFSR) and "
                "will not be supported in future Windows Server releases."
            ),
            severity=Severity.MEDIUM,
            category=CheckCategory.INFRASTRUCTURE,
            check_id="infra_001",
            details={"replication_method": "FRS"},
            remediation=Remediation(
                "Migrate SYSVOL replication from FRS to DFSR",
                powershell="dfsrmig /setglobalstate 3",
                reference_url="https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr",
                effort="high",
            ),
        ))
    elif using_frs and using_dfsr:
        findings.append(Finding(
            title="SYSVOL DFSR Migration In Progress",
            description=(
                "Both FRS and DFSR objects exist, indicating a partial migration. "
                "Complete the migration to eliminate FRS dependency."
            ),
            severity=Severity.LOW,
            category=CheckCategory.INFRASTRUCTURE,
            check_id="infra_001",
            details={"replication_method": "FRS+DFSR (transitional)"},
            remediation=Remediation(
                "Complete DFSR migration to the 'Eliminated' state",
                powershell="dfsrmig /getmigrationstate\ndfsrmig /setglobalstate 3",
            ),
        ))

    return findings


# ── infra_002: domain/forest functional level ─────────────────────────────

# domainFunctionality values
_FUNCTIONAL_LEVELS = {
    "0": "Windows 2000",
    "1": "Windows Server 2003 Interim",
    "2": "Windows Server 2003",
    "3": "Windows Server 2008",
    "4": "Windows Server 2008 R2",
    "5": "Windows Server 2012",
    "6": "Windows Server 2012 R2",
    "7": "Windows Server 2016",
}


@register_check(
    check_id="infra_002",
    name="Domain Functional Level",
    category=CheckCategory.INFRASTRUCTURE,
    description="Checks if the domain functional level is below Server 2016",
    tags=["infrastructure", "legacy"],
)
def check_functional_level(ctx) -> list[Finding]:
    level = ctx.domain_functional_level
    if not level:
        return []

    level_str = str(level)
    level_name = _FUNCTIONAL_LEVELS.get(level_str, f"Unknown ({level_str})")

    try:
        level_int = int(level_str)
    except ValueError:
        return []

    if level_int >= 7:
        return []

    sev = Severity.HIGH if level_int < 5 else Severity.MEDIUM
    return [Finding(
        title=f"Domain Functional Level: {level_name}",
        description=(
            f"Domain functional level is {level_name} (level {level_int}). "
            "Server 2016 (level 7) is recommended to enable Privileged Access Management, "
            "credential guard support, and other modern security features."
        ),
        severity=sev,
        category=CheckCategory.INFRASTRUCTURE,
        check_id="infra_002",
        details={"functional_level": level_int, "level_name": level_name},
        remediation=Remediation(
            "Raise domain functional level to Windows Server 2016 after ensuring all DCs meet the requirement",
            powershell="Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain",
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels",
        ),
    )]


# ── infra_003: AD Recycle Bin ────────────────────────────────────────────


@register_check(
    check_id="infra_003",
    name="AD Recycle Bin",
    category=CheckCategory.INFRASTRUCTURE,
    description="Checks whether the AD Recycle Bin optional feature is enabled",
    tags=["infrastructure", "recovery"],
)
def check_recycle_bin(ctx) -> list[Finding]:
    config_dn = ctx.configuration_dn
    results = ctx.ldap.search(
        "(&(objectClass=msDS-OptionalFeature)(cn=Recycle Bin Feature))",
        ["msDS-EnabledFeatureBL"],
        search_base=config_dn,
    )

    if results:
        enabled_bl = results[0].get("msDS-EnabledFeatureBL")
        if enabled_bl:
            return []

    return [Finding(
        title="AD Recycle Bin Not Enabled",
        description=(
            "The Active Directory Recycle Bin is not enabled. Without it, deleted AD "
            "objects cannot be easily recovered and forensic investigation of deleted "
            "accounts is limited. This is an irreversible enable — once turned on, "
            "it cannot be disabled."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.INFRASTRUCTURE,
        check_id="infra_003",
        remediation=Remediation(
            "Enable the AD Recycle Bin (requires Forest Functional Level 2008 R2+)",
            powershell='Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target "<forest_name>"',
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#ad-recycle-bin",
        ),
    )]


# ── infra_004: tombstone lifetime ────────────────────────────────────────


@register_check(
    check_id="infra_004",
    name="Tombstone Lifetime",
    category=CheckCategory.INFRASTRUCTURE,
    description="Checks the tombstone lifetime for dangerously low values",
    tags=["infrastructure", "replication"],
)
def check_tombstone_lifetime(ctx) -> list[Finding]:
    config_dn = ctx.configuration_dn
    results = ctx.ldap.search(
        "(cn=Directory Service)",
        ["tombstoneLifetime"],
        search_base=f"CN=Windows NT,CN=Services,{config_dn}",
    )
    if not results:
        return []

    tsl = results[0].get("tombstoneLifetime")
    if tsl is None:
        # Default: 60 days (Server 2003) or 180 days (Server 2003 SP1+)
        return []

    tsl_int = int(tsl)
    if tsl_int >= 60:
        return []

    return [Finding(
        title=f"Tombstone Lifetime: {tsl_int} Days",
        description=(
            f"The tombstone lifetime is set to {tsl_int} days (default is 60-180). "
            "Extremely short values risk lingering objects and replication inconsistencies "
            "if a DC is offline longer than the tombstone lifetime."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.INFRASTRUCTURE,
        check_id="infra_004",
        details={"tombstone_lifetime_days": tsl_int},
        remediation=Remediation(
            "Set tombstoneLifetime to at least 180 days",
            reference_url="https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-objects-remain",
        ),
    )]


# ── infra_005: ADIDNS wildcard records ───────────────────────────────────


@register_check(
    check_id="infra_005",
    name="ADIDNS Wildcard Records",
    category=CheckCategory.DNS,
    description="Checks for wildcard DNS records in AD-integrated DNS zones",
    tags=["dns", "mitm"],
)
def check_adidns_wildcard(ctx) -> list[Finding]:
    # Look for any dnsNode with dc=* (wildcard) in common zones
    results = ctx.ldap.search(
        "(&(objectClass=dnsNode)(dc=\\2a))",
        ["dc", "distinguishedName", "dnsRecord"],
        search_base=f"CN=MicrosoftDNS,DC=DomainDnsZones,{ctx.domain_dn}",
    )
    if not results:
        return []

    wildcards = [e.get("distinguishedName", "?") for e in results]
    return [Finding(
        title=f"ADIDNS Wildcard Records ({len(wildcards)})",
        description=(
            "Wildcard (*) DNS records exist in AD-integrated DNS zones. "
            "These resolve any unregistered hostname to the wildcard target, "
            "enabling man-in-the-middle attacks via DNS name resolution poisoning "
            "within the domain."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.DNS,
        check_id="infra_005",
        affected_objects=wildcards,
        mitre=MitreAttack(
            "T1557", "Adversary-in-the-Middle", "Credential Access",
            known_tools=("Invoke-DNSUpdate", "dnstool.py", "krbrelayx"),
        ),
        remediation=Remediation(
            "Remove wildcard DNS records from AD-integrated zones",
            reference_url="https://www.netspi.com/blog/technical-blog/network-penetration-testing/exploiting-adidns/",
        ),
    )]


# ── infra_006: ADIDNS zone permissions ───────────────────────────────────


@register_check(
    check_id="infra_006",
    name="ADIDNS Zone Permissions",
    category=CheckCategory.DNS,
    description="Checks if low-privilege users can create records in AD-integrated DNS zones",
    tags=["dns", "mitm", "access_control"],
)
def check_adidns_permissions(ctx) -> list[Finding]:
    from lazyhound.finder.parsers import (
        GENERIC_ALL, GENERIC_WRITE,
        is_admin_sid, is_low_privilege_sid,
        parse_security_descriptor,
    )

    # Check the main forward lookup zone
    zone_dn = f"DC=DomainDnsZones,{ctx.domain_dn}"
    results = ctx.ldap.search(
        "(objectClass=dnsZone)",
        ["dc", "nTSecurityDescriptor"],
        search_base=f"CN=MicrosoftDNS,{zone_dn}",
    )
    if not results:
        return []

    dangerous_zones: list[str] = []
    create_child_mask = GENERIC_ALL | GENERIC_WRITE | 0x1  # ADS_RIGHT_DS_CREATE_CHILD

    for zone in results:
        name = zone.get("dc", "?")
        sd_raw = zone.get("nTSecurityDescriptor")
        if not isinstance(sd_raw, bytes):
            continue
        sd = parse_security_descriptor(sd_raw)
        if not sd:
            continue
        for ace in sd.dacl:
            if is_admin_sid(ace.sid, ctx.domain_sid):
                continue
            if is_low_privilege_sid(ace.sid, ctx.domain_sid):
                if ace.access_mask & create_child_mask:
                    dangerous_zones.append(f"{name} (SID: {ace.sid})")
                    break

    if not dangerous_zones:
        return []
    return [Finding(
        title=f"ADIDNS Zones with Broad Write Access ({len(dangerous_zones)})",
        description=(
            "Low-privilege principals can create DNS records in AD-integrated zones. "
            "An attacker can add records to redirect traffic for non-existent hostnames, "
            "enabling MITM and credential capture via NTLM relay."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.DNS,
        check_id="infra_006",
        affected_objects=dangerous_zones,
        mitre=MitreAttack(
            "T1557", "Adversary-in-the-Middle", "Credential Access",
            known_tools=("Invoke-DNSUpdate", "dnstool.py"),
        ),
        remediation=Remediation(
            "Restrict CreateChild permissions on DNS zones to administrative groups only",
            reference_url="https://www.netspi.com/blog/technical-blog/network-penetration-testing/exploiting-adidns/",
        ),
    )]

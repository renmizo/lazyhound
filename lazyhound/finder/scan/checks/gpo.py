"""GPO security checks."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity


# ── gpo_001: GPOs linked to Domain root ──────────────────────────────────────


@register_check(
    check_id="gpo_001",
    name="GPO Security Review",
    category=CheckCategory.GPO,
    description="Identifies GPOs and potential misconfigurations",
    tags=["gpo", "configuration"],
)
def check_gpo_overview(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(objectClass=groupPolicyContainer)",
        ["displayName", "gPCFileSysPath", "flags", "whenChanged"],
        search_base=ctx.domain_dn,
    )
    disabled_gpos = []
    for gpo in results:
        name = gpo.get("displayName", "?")
        flags = int(gpo.get("flags", 0) or 0)
        # flags: 0=enabled, 1=user disabled, 2=computer disabled, 3=both disabled
        if flags == 3:
            disabled_gpos.append(name)

    if disabled_gpos:
        findings.append(Finding(
            title=f"Fully Disabled GPOs ({len(disabled_gpos)})",
            description="GPOs with both user and computer settings disabled — candidates for cleanup.",
            severity=Severity.INFO,
            category=CheckCategory.GPO,
            check_id="gpo_001",
            affected_objects=disabled_gpos,
            remediation=Remediation("Review and remove unused GPOs to reduce attack surface"),
        ))
    return findings


# ── gpo_002: GPO permissions (broad write access) ───────────────────────────


@register_check(
    check_id="gpo_002",
    name="GPO with Broad Edit Permissions",
    category=CheckCategory.GPO,
    description="GPOs editable by non-admin users or large groups",
    tags=["gpo", "privilege_escalation"],
)
def check_gpo_permissions(ctx) -> list[Finding]:
    # This is a simplified heuristic — full ACL parsing requires DACL enumeration
    results = ctx.ldap.search(
        "(objectClass=groupPolicyContainer)",
        ["displayName", "nTSecurityDescriptor"],
        search_base=ctx.domain_dn,
    )
    # We report the total GPO count as INFO since full ACL parsing
    # is beyond pure LDAP attribute reads
    if not results:
        return []
    return [Finding(
        title=f"GPO Inventory: {len(results)} GPO(s) in Domain",
        description=(
            f"{len(results)} Group Policy Objects found. Manually audit GPO edit permissions "
            "using Get-GPPermission to identify over-privileged access."
        ),
        severity=Severity.INFO,
        category=CheckCategory.GPO,
        check_id="gpo_002",
        details={"total_gpos": len(results)},
        remediation=Remediation(
            "Audit GPO permissions with: Get-GPO -All | ForEach { Get-GPPermission -Guid $_.Id -All }",
            powershell="Get-GPO -All | ForEach-Object { Get-GPPermission -Guid $_.Id -All }",
        ),
    )]


# ── gpo_003: GPP cpassword (MS14-025) ───────────────────────────────────────

import base64
import logging

logger = logging.getLogger(__name__)

# Microsoft published AES key for GPP cpassword decryption (MS14-025)
_GPP_AES_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])

# GPP Client Side Extension GUIDs that may contain cpassword values
_GPP_CSE_GUIDS = {
    "{17D89FEC-5C44-4972-B12D-241CAEF74509}",  # Group Policy Preferences: Groups
    "{AADCED64-746C-4633-A97C-D61349046527}",  # Scheduled Tasks
    "{91FBB303-0CD5-4055-BF42-E512A681B325}",  # Services
    "{5794DAFD-BE60-433F-88A2-1A31939AC01F}",  # Drives
    "{B087BE9D-ED37-454F-AF9C-04291E351182}",  # Registry (Preferences)
    "{A3F3E39B-5D83-4940-B954-28315B82F0A8}",  # Data Sources
    "{6232C319-91F5-4B88-8141-3FA8B1B45A5E}",  # Environment Variables (Preferences)
}


def decrypt_gpp_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword value using the well-known AES-256-CBC key."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        logger.debug("pycryptodome not installed — cannot decrypt cpassword")
        return "<pycryptodome not installed>"
    try:
        # Pad the base64 string to a multiple of 4
        padded = cpassword + "=" * ((4 - len(cpassword) % 4) % 4)
        encrypted = base64.b64decode(padded)
        iv = b"\x00" * 16
        cipher = AES.new(_GPP_AES_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode("utf-16-le")
    except Exception:
        logger.debug("Failed to decrypt cpassword value")
        return "<decryption failed>"


@register_check(
    check_id="gpo_003",
    name="GPP cpassword (MS14-025)",
    category=CheckCategory.GPO,
    description="Detects GPOs with Group Policy Preferences that may contain cpassword values",
    tags=["credential_exposure", "gpo"],
)
def check_gpp_cpassword(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(objectClass=groupPolicyContainer)",
        [
            "displayName", "gPCFileSysPath",
            "gPCMachineExtensionNames", "gPCUserExtensionNames",
        ],
        search_base=ctx.domain_dn,
    )
    if not results:
        return findings

    gpp_gpos: list[str] = []
    for gpo in results:
        name = gpo.get("displayName", "?")
        machine_ext = gpo.get("gPCMachineExtensionNames", "") or ""
        user_ext = gpo.get("gPCUserExtensionNames", "") or ""
        extensions = machine_ext.upper() + user_ext.upper()

        for cse_guid in _GPP_CSE_GUIDS:
            if cse_guid.upper() in extensions:
                sysvol_path = gpo.get("gPCFileSysPath", "")
                gpp_gpos.append(f"{name} ({sysvol_path})" if sysvol_path else name)
                break

    if not gpp_gpos:
        return findings

    findings.append(Finding(
        title=f"GPOs with Group Policy Preferences ({len(gpp_gpos)})",
        description=(
            f"{len(gpp_gpos)} GPO(s) contain Group Policy Preferences extensions "
            "that historically stored credentials via cpassword.  While MS14-025 "
            "prevents new cpassword creation, existing values remain decryptable "
            "with the publicly known AES key."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.GPO,
        check_id="gpo_003",
        affected_objects=gpp_gpos,
        details={
            "note": "Check SYSVOL for cpassword values: "
                    'findstr /S /I "cpassword" \\\\<domain>\\SYSVOL\\*.xml',
        },
        mitre=MitreAttack(
            "T1552.006", "Group Policy Preferences", "Credential Access",
            known_tools=("Get-GPPPassword", "gpp-decrypt", "Metasploit"),
        ),
        remediation=Remediation(
            "Search SYSVOL for cpassword XML values and delete them; "
            "rotate any passwords that were stored in GPP",
            powershell=(
                "Get-ChildItem -Path \\\\<domain>\\SYSVOL -Recurse -Include *.xml | "
                'Select-String -Pattern "cpassword" | Select-Object Path'
            ),
            reference_url="https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025",
        ),
    ))
    return findings


# ── gpo_004: unlinked GPOs ───────────────────────────────────────────────


@register_check(
    check_id="gpo_004",
    name="Unlinked GPOs",
    category=CheckCategory.GPO,
    description="GPOs that exist but are unlinked from any OU, domain, or site",
    tags=["gpo", "hygiene"],
)
def check_unlinked_gpos(ctx) -> list[Finding]:
    # Get all GPOs
    gpos = ctx.ldap.search(
        "(objectClass=groupPolicyContainer)",
        ["displayName", "distinguishedName", "cn"],
        search_base=ctx.domain_dn,
    )
    if not gpos:
        return []

    # Build set of GPO DNs
    gpo_dns = {}
    for gpo in gpos:
        dn = gpo.get("distinguishedName", "")
        name = gpo.get("displayName") or gpo.get("cn", "?")
        if dn:
            gpo_dns[dn.lower()] = name

    # Search for all objects with gpLink attribute (OUs, domain, sites)
    linked = ctx.ldap.search(
        "(gpLink=*)",
        ["gpLink"],
        search_base=ctx.domain_dn,
    )

    linked_gpo_dns: set[str] = set()
    for obj in linked:
        gp_link = obj.get("gpLink", "")
        if isinstance(gp_link, list):
            gp_link = "".join(gp_link)
        # gpLink format: [LDAP://CN=...,CN=Policies,...;0][LDAP://...;1]
        for part in gp_link.split("["):
            if "LDAP://" in part.upper():
                dn_raw = part.split(";")[0]
                # Case-insensitive removal of LDAP:// prefix
                if dn_raw.upper().startswith("LDAP://"):
                    dn_part = dn_raw[7:]
                else:
                    dn_part = dn_raw
                linked_gpo_dns.add(dn_part.lower())

    unlinked = [
        gpo_dns[dn]
        for dn in gpo_dns
        if dn not in linked_gpo_dns
    ]

    if not unlinked:
        return []
    return [Finding(
        title=f"Unlinked GPOs ({len(unlinked)})",
        description=(
            f"{len(unlinked)} GPO(s) exist but are unlinked from any OU, domain, or site. "
            "Unlinked GPOs may contain stale configurations, hardcoded credentials in "
            "scripts, or residual security settings that should be audited and removed."
        ),
        severity=Severity.LOW,
        category=CheckCategory.GPO,
        check_id="gpo_004",
        affected_objects=unlinked,
        remediation=Remediation(
            "Review unlinked GPOs and delete those that are no longer needed",
            powershell="Get-GPO -All | Where-Object { ($_ | Get-GPOReport -ReportType XML | Select-String '<LinksTo>') -eq $null }",
        ),
    )]


# ── gpo_005: GPOs with login/startup scripts ────────────────────────────

# Script CSE GUIDs
_SCRIPT_CSE_GUIDS = {
    "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}",  # Scripts (Startup/Shutdown)
    "{40B6664F-4972-11D1-A7CA-0000F87571E3}",  # Scripts (Logon/Logoff)
}


@register_check(
    check_id="gpo_005",
    name="GPOs with Login/Startup Scripts",
    category=CheckCategory.GPO,
    description="GPOs containing scripts that should be audited for hardcoded credentials",
    tags=["gpo", "credential_exposure"],
)
def check_gpo_scripts(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(objectClass=groupPolicyContainer)",
        ["displayName", "gPCFileSysPath", "gPCMachineExtensionNames", "gPCUserExtensionNames"],
        search_base=ctx.domain_dn,
    )
    if not results:
        return []

    script_gpos: list[str] = []
    for gpo in results:
        name = gpo.get("displayName", "?")
        machine_ext = gpo.get("gPCMachineExtensionNames", "") or ""
        user_ext = gpo.get("gPCUserExtensionNames", "") or ""
        extensions = machine_ext.upper() + user_ext.upper()

        for cse_guid in _SCRIPT_CSE_GUIDS:
            if cse_guid.upper() in extensions:
                sysvol_path = gpo.get("gPCFileSysPath", "")
                script_gpos.append(f"{name} ({sysvol_path})" if sysvol_path else name)
                break

    if not script_gpos:
        return []
    return [Finding(
        title=f"GPOs with Login/Startup Scripts ({len(script_gpos)})",
        description=(
            f"{len(script_gpos)} GPO(s) contain login/startup script extensions. "
            "SYSVOL scripts are readable by all authenticated users and frequently "
            "contain hardcoded credentials, network paths, or sensitive configuration."
        ),
        severity=Severity.INFO,
        category=CheckCategory.GPO,
        check_id="gpo_005",
        affected_objects=script_gpos,
        details={
            "note": "Audit SYSVOL scripts for credentials: "
                    'findstr /S /I "password\\|credential\\|secret" \\\\<domain>\\SYSVOL\\*.bat *.cmd *.ps1 *.vbs',
        },
        mitre=MitreAttack(
            "T1552.001", "Credentials In Files", "Credential Access",
            known_tools=("PowerView", "Snaffler"),
        ),
        remediation=Remediation(
            "Audit all SYSVOL scripts for hardcoded credentials and replace with "
            "secure credential management (gMSA, credential vault, etc.)",
        ),
    )]

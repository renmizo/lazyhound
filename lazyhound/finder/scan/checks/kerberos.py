"""Kerberos security checks."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity
from lazyhound.finder.finder_utils import filetime_days_ago as _filetime_days_ago

UAC_DISABLED = 0x2
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_USE_DES_ONLY = 0x200000
UAC_DONT_EXPIRE_PASSWORD = 0x10000


def _uac(entry: dict) -> int:
    v = entry.get("userAccountControl")
    return int(v) if v else 0


# ── kerb_001: Kerberoasting ──────────────────────────────────────────────────


@register_check(
    check_id="kerb_001",
    name="Kerberoastable Accounts",
    category=CheckCategory.KERBEROS,
    description="User accounts with SPNs vulnerable to offline cracking",
    tags=["credential_access", "kerberos"],
)
def check_kerberoastable(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(&(objectClass=user)(servicePrincipalName=*)"
        "(!(objectClass=computer))"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "servicePrincipalName", "adminCount", "pwdLastSet"],
    )
    if not results:
        return findings

    admins, normals = [], []
    for e in results:
        name = e.get("sAMAccountName", "?")
        (admins if e.get("adminCount") == "1" else normals).append(name)

    mitre = MitreAttack(
        "T1558.003", "Kerberoasting", "Credential Access",
        known_tools=("Rubeus", "Impacket GetUserSPNs", "hashcat"),
    )
    if admins:
        findings.append(Finding(
            title="Privileged Kerberoastable Accounts",
            description=(
                f"{len(admins)} admin account(s) have SPNs.  Compromising a single "
                "service ticket yields domain-admin-level credentials."
            ),
            severity=Severity.CRITICAL,
            category=CheckCategory.KERBEROS,
            check_id="kerb_001",
            affected_objects=admins,
            mitre=mitre,
            remediation=Remediation(
                "Remove SPNs from admin accounts or migrate to gMSA",
                powershell='Set-ADUser "<acct>" -ServicePrincipalNames @{Remove="<spn>"}',
                reference_url="https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview",
            ),
        ))
    if normals:
        findings.append(Finding(
            title="Service Accounts Exposed to Kerberoasting",
            description=f"{len(normals)} non-admin account(s) with SPNs.",
            severity=Severity.HIGH,
            category=CheckCategory.KERBEROS,
            check_id="kerb_001",
            affected_objects=normals,
            mitre=mitre,
            remediation=Remediation(
                "Migrate to gMSA or enforce 25+ character passwords on SPN accounts",
            ),
        ))
    return findings


# ── kerb_002: AS-REP Roasting ────────────────────────────────────────────────


@register_check(
    check_id="kerb_002",
    name="AS-REP Roastable Accounts",
    category=CheckCategory.KERBEROS,
    description="Accounts with Kerberos pre-authentication disabled",
    tags=["credential_access", "kerberos"],
)
def check_asrep_roastable(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_DONT_REQ_PREAUTH})"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName"],
    )
    if not results:
        return []
    affected = [e.get("sAMAccountName", "?") for e in results]
    return [Finding(
        title="AS-REP Roastable Accounts",
        description=(
            f"{len(affected)} account(s) have pre-auth disabled.  "
            "An attacker can request AS-REP data and crack it offline "
            "without any prior authentication."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.KERBEROS,
        check_id="kerb_002",
        affected_objects=affected,
        mitre=MitreAttack(
            "T1558.004", "AS-REP Roasting", "Credential Access",
            known_tools=("Rubeus", "Impacket GetNPUsers", "hashcat"),
        ),
        remediation=Remediation(
            "Enable Kerberos pre-authentication for all accounts",
            powershell='Set-ADAccountControl "<acct>" -DoesNotRequirePreAuth $false',
        ),
    )]


# ── kerb_003: DES encryption ────────────────────────────────────────────────


@register_check(
    check_id="kerb_003",
    name="DES-Only Kerberos Encryption",
    category=CheckCategory.KERBEROS,
    description="Accounts restricted to broken DES encryption",
    tags=["credential_access", "kerberos", "legacy"],
)
def check_des_encryption(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        f"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={UAC_USE_DES_ONLY}))",
        ["sAMAccountName"],
    )
    if not results:
        return []
    affected = [e.get("sAMAccountName", "?") for e in results]
    return [Finding(
        title="DES-Only Kerberos Encryption",
        description=f"{len(affected)} account(s) restricted to cryptographically broken DES.",
        severity=Severity.HIGH,
        category=CheckCategory.KERBEROS,
        check_id="kerb_003",
        affected_objects=affected,
        remediation=Remediation(
            "Disable DES and enable AES encryption",
            powershell='Set-ADAccountControl "<acct>" -UseDESKeyOnly $false',
        ),
    )]


# ── kerb_004: KRBTGT password age ───────────────────────────────────────────


@register_check(
    check_id="kerb_004",
    name="KRBTGT Password Age",
    category=CheckCategory.KERBEROS,
    description="Checks if the krbtgt password has been rotated recently",
    tags=["credential_access", "kerberos", "persistence"],
)
def check_krbtgt_age(ctx) -> list[Finding]:
    results = ctx.ldap.search("(sAMAccountName=krbtgt)", ["pwdLastSet"])
    if not results:
        return []
    days = _filetime_days_ago(results[0].get("pwdLastSet"))
    if days is None:
        return []
    if days > 365:
        sev = Severity.CRITICAL
    elif days > 180:
        sev = Severity.HIGH
    else:
        return []
    return [Finding(
        title=f"KRBTGT Password Age: {days} Days",
        description=(
            f"The krbtgt password has not been changed in {days} days.  "
            "An attacker with the hash can forge Golden Tickets until rotated twice."
        ),
        severity=sev,
        category=CheckCategory.KERBEROS,
        check_id="kerb_004",
        details={"password_age_days": days},
        mitre=MitreAttack(
            "T1558.001", "Golden Ticket", "Credential Access",
            known_tools=("Mimikatz", "Impacket ticketer"),
        ),
        remediation=Remediation(
            "Rotate krbtgt password twice with replication delay between rotations",
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-resetting-the-krbtgt-password",
        ),
    )]


# ── kerb_005: non-expiring passwords on privileged accounts ──────────────────


@register_check(
    check_id="kerb_005",
    name="Non-Expiring Passwords on Privileged Accounts",
    category=CheckCategory.KERBEROS,
    description="Admin accounts with passwords that never expire",
    tags=["credential_access", "persistence"],
)
def check_non_expiring_admin_passwords(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_DONT_EXPIRE_PASSWORD})"
        "(adminCount=1)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName"],
    )
    if not results:
        return []
    affected = [e.get("sAMAccountName", "?") for e in results]
    return [Finding(
        title="Privileged Accounts with Non-Expiring Passwords",
        description=(
            f"{len(affected)} admin account(s) have passwords set to never expire, "
            "reducing the window for compromised credential rotation."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.KERBEROS,
        check_id="kerb_005",
        affected_objects=affected,
        remediation=Remediation(
            "Enable password expiration on privileged accounts or use gMSA",
            powershell='Set-ADUser "<acct>" -PasswordNeverExpires $false',
        ),
    )]


# ── kerb_006: RC4 / legacy Kerberos encryption types ────────────────────────

# msDS-SupportedEncryptionTypes bit flags
ETYPE_DES_CBC_CRC = 0x1
ETYPE_DES_CBC_MD5 = 0x2
ETYPE_RC4_HMAC = 0x4
ETYPE_AES128 = 0x8
ETYPE_AES256 = 0x10

AES_MASK = ETYPE_AES128 | ETYPE_AES256


@register_check(
    check_id="kerb_006",
    name="RC4/Legacy Kerberos Encryption",
    category=CheckCategory.KERBEROS,
    description="Accounts using RC4 or DES Kerberos encryption without AES",
    tags=["credential_access", "kerberos", "legacy"],
)
def check_rc4_encryption(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        "(msDS-SupportedEncryptionTypes=*)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "msDS-SupportedEncryptionTypes", "adminCount"],
    )
    rc4_only_admins: list[str] = []
    rc4_only_users: list[str] = []

    for e in results:
        etypes = int(e.get("msDS-SupportedEncryptionTypes", 0) or 0)
        has_rc4 = bool(etypes & ETYPE_RC4_HMAC)
        has_aes = bool(etypes & AES_MASK)
        if has_rc4 and not has_aes:
            name = e.get("sAMAccountName", "?")
            if e.get("adminCount") == "1":
                rc4_only_admins.append(name)
            else:
                rc4_only_users.append(name)

    mitre = MitreAttack(
        "T1558.003", "Kerberoasting", "Credential Access",
        known_tools=("Rubeus", "hashcat", "Impacket"),
    )
    if rc4_only_admins:
        findings.append(Finding(
            title=f"Privileged Accounts Restricted to RC4 ({len(rc4_only_admins)})",
            description=(
                f"{len(rc4_only_admins)} admin account(s) only support RC4_HMAC_MD5 "
                "without AES.  RC4 tickets are significantly faster to crack offline."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.KERBEROS,
            check_id="kerb_006",
            affected_objects=rc4_only_admins,
            mitre=mitre,
            remediation=Remediation(
                "Enable AES256 on all accounts and disable RC4 where possible",
                powershell='Set-ADUser "<acct>" -KerberosEncryptionType AES128,AES256',
                reference_url="https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-aes-encryption",
            ),
        ))
    if rc4_only_users:
        findings.append(Finding(
            title=f"Accounts Restricted to RC4 Encryption ({len(rc4_only_users)})",
            description=f"{len(rc4_only_users)} account(s) only support RC4 without AES.",
            severity=Severity.MEDIUM,
            category=CheckCategory.KERBEROS,
            check_id="kerb_006",
            affected_objects=rc4_only_users,
            mitre=mitre,
            remediation=Remediation(
                "Enable AES encryption types on these accounts",
                powershell='Set-ADUser "<acct>" -KerberosEncryptionType AES128,AES256',
            ),
        ))
    return findings


# ── kerb_007: duplicate SPNs ──────────────────────────────────────────────


@register_check(
    check_id="kerb_007",
    name="Duplicate SPNs",
    category=CheckCategory.KERBEROS,
    description="Multiple accounts sharing the same SPN break Kerberos authentication",
    tags=["kerberos", "misconfiguration"],
)
def check_duplicate_spns(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectCategory=*)(servicePrincipalName=*))",
        ["sAMAccountName", "servicePrincipalName"],
    )
    if not results:
        return []

    spn_map: dict[str, list[str]] = {}
    for e in results:
        name = e.get("sAMAccountName", "?")
        spns = e.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        for spn in spns:
            spn_lower = spn.lower()
            spn_map.setdefault(spn_lower, []).append(name)

    duplicates = [
        f"{spn} -> [{', '.join(accounts)}]"
        for spn, accounts in spn_map.items()
        if len(accounts) > 1
    ]
    if not duplicates:
        return []
    return [Finding(
        title=f"Duplicate SPNs ({len(duplicates)})",
        description=(
            f"{len(duplicates)} SPN(s) are registered on multiple accounts. "
            "Duplicate SPNs cause Kerberos authentication failures and can be "
            "exploited for credential interception."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.KERBEROS,
        check_id="kerb_007",
        affected_objects=duplicates[:20],
        details={"total_duplicates": len(duplicates)},
        remediation=Remediation(
            "Remove duplicate SPNs; use setspn -X to detect and resolve conflicts",
            powershell="setspn -X",
        ),
    )]


# ── kerb_008: constrained delegation to sensitive services ────────────────

SENSITIVE_SPN_PREFIXES = ("ldap/", "cifs/", "host/", "http/", "wsman/", "krbtgt/", "rpcss/")


@register_check(
    check_id="kerb_008",
    name="Constrained Delegation to Sensitive Services",
    category=CheckCategory.KERBEROS,
    description="Constrained delegation targeting LDAP/CIFS/HOST on DCs is effectively unconstrained",
    tags=["privilege_escalation", "delegation", "kerberos"],
)
def check_delegation_sensitive_targets(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))",
        ["sAMAccountName", "msDS-AllowedToDelegateTo"],
    )
    if not results:
        return []

    dc_names: set[str] = set()
    for dc in ctx.get_domain_controllers():
        for attr in ("dNSHostName", "sAMAccountName"):
            v = dc.get(attr)
            if v:
                dc_names.add(v.rstrip("$").lower())

    dangerous: list[str] = []
    for e in results:
        name = e.get("sAMAccountName", "?")
        targets = e.get("msDS-AllowedToDelegateTo") or []
        if isinstance(targets, str):
            targets = [targets]
        for target in targets:
            t_lower = target.lower()
            # Check if targeting a sensitive service on a DC
            prefix_match = any(t_lower.startswith(p) for p in SENSITIVE_SPN_PREFIXES)
            if not prefix_match:
                continue
            host_part = t_lower.split("/", 1)[-1].split(":")[0].split(".")[0]
            if any(dc in t_lower for dc in dc_names) or host_part in dc_names:
                dangerous.append(f"{name} -> {target}")
                break

    if not dangerous:
        return []
    return [Finding(
        title=f"Constrained Delegation to Sensitive DC Services ({len(dangerous)})",
        description=(
            "Accounts have constrained delegation configured to LDAP, CIFS, HOST, or "
            "other sensitive services on domain controllers. Delegation to ldap/DC or "
            "cifs/DC is effectively equivalent to unconstrained delegation — the "
            "delegated ticket can be used for DCSync or full DC access."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.KERBEROS,
        check_id="kerb_008",
        affected_objects=dangerous,
        mitre=MitreAttack(
            "T1134.001", "Token Impersonation/Theft", "Privilege Escalation",
            known_tools=("Rubeus s4u", "Impacket getST"),
        ),
        remediation=Remediation(
            "Change delegation targets away from sensitive DC services; "
            "use RBCD with specific service accounts instead",
            effort="high",
        ),
    )]


# ── kerb_009: delegation on privileged accounts ──────────────────────────


@register_check(
    check_id="kerb_009",
    name="Delegation on Privileged Accounts",
    category=CheckCategory.KERBEROS,
    description="Privileged accounts with delegation configured should use Protected Users instead",
    tags=["privilege_escalation", "delegation", "kerberos"],
)
def check_delegation_on_admins(ctx) -> list[Finding]:
    UAC_TRUSTED_FOR_DELEGATION = 0x80000
    UAC_TRUSTED_TO_AUTH = 0x1000000

    results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))(adminCount=1)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED}))"
        "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
        "(msDS-AllowedToDelegateTo=*)))",
        ["sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo"],
    )
    if not results:
        return []

    affected: list[str] = []
    for e in results:
        name = e.get("sAMAccountName", "?")
        uac = int(e.get("userAccountControl", 0) or 0)
        flags = []
        if uac & UAC_TRUSTED_FOR_DELEGATION:
            flags.append("unconstrained")
        if uac & UAC_TRUSTED_TO_AUTH:
            flags.append("protocol_transition")
        targets = e.get("msDS-AllowedToDelegateTo") or []
        if isinstance(targets, str):
            targets = [targets]
        if targets:
            flags.append(f"constrained({len(targets)} targets)")
        affected.append(f"{name} ({', '.join(flags)})")

    return [Finding(
        title=f"Privileged Accounts with Delegation ({len(affected)})",
        description=(
            f"{len(affected)} admin account(s) have delegation configured. "
            "Privileged accounts should never be configured for delegation — "
            "they should be in the Protected Users group which blocks delegation."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.KERBEROS,
        check_id="kerb_009",
        affected_objects=affected,
        mitre=MitreAttack(
            "T1550.003", "Pass the Ticket", "Lateral Movement",
            known_tools=("Rubeus", "Mimikatz"),
        ),
        remediation=Remediation(
            "Remove delegation from admin accounts and add them to Protected Users",
            powershell='Set-ADUser "<acct>" -TrustedForDelegation $false; '
                       'Add-ADGroupMember "Protected Users" -Members "<acct>"',
        ),
    )]

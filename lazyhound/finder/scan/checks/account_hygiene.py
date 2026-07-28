"""Account hygiene checks: credentials in descriptions, stale accounts, flags."""

from __future__ import annotations

import re

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity
from lazyhound.finder.finder_utils import filetime_days_ago as _filetime_days_ago

UAC_DISABLED = 0x2
UAC_PASSWD_NOTREQD = 0x20
UAC_REVERSIBLE_ENCRYPTION = 0x80

PASSWORD_PATTERNS = [
    re.compile(r"(?:pass(?:word)?|pwd|cred)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"p[/@]ss\s*[:=]", re.IGNORECASE),
]


# ── hygiene_001: passwords in description ────────────────────────────────────


@register_check(
    check_id="hygiene_001",
    name="Passwords in Description Fields",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Accounts with credential-like values in the description attribute",
    tags=["credential_exposure", "hygiene"],
)
def check_passwords_in_descriptions(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(&(objectClass=user)(description=*))",
        ["sAMAccountName", "description", "adminCount"],
    )
    admin_hits, user_hits = [], []
    for e in results:
        desc = e.get("description", "")
        if isinstance(desc, list):
            desc = " ".join(desc)
        if not desc:
            continue
        for pat in PASSWORD_PATTERNS:
            if pat.search(desc):
                name = e.get("sAMAccountName", "?")
                (admin_hits if e.get("adminCount") == "1" else user_hits).append(name)
                break

    if admin_hits:
        findings.append(Finding(
            title="Privileged Accounts with Passwords in Description",
            description="Admin account descriptions contain credential-like values readable by all authenticated users.",
            severity=Severity.CRITICAL,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_001",
            affected_objects=admin_hits,
            mitre=MitreAttack(
                "T1552.001", "Credentials In Files", "Credential Access",
                known_tools=("PowerView", "ldapsearch"),
            ),
            remediation=Remediation("Remove passwords from descriptions and rotate credentials"),
        ))
    if user_hits:
        findings.append(Finding(
            title="Accounts with Passwords in Description",
            description=f"{len(user_hits)} account(s) with credential-like description values.",
            severity=Severity.HIGH,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_001",
            affected_objects=user_hits,
            remediation=Remediation("Remove passwords from descriptions and rotate credentials"),
        ))
    return findings


# ── hygiene_002: reversible encryption ───────────────────────────────────────


@register_check(
    check_id="hygiene_002",
    name="Reversible Encryption",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Accounts storing passwords with reversible encryption (plaintext equivalent)",
    tags=["credential_exposure", "hygiene"],
)
def check_reversible_encryption(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_REVERSIBLE_ENCRYPTION}))",
        ["sAMAccountName"],
    )
    if not results:
        return []
    affected = [e.get("sAMAccountName", "?") for e in results]
    return [Finding(
        title="Accounts with Reversible Encryption",
        description=f"{len(affected)} account(s) store passwords in reversible form — equivalent to plaintext.",
        severity=Severity.CRITICAL,
        category=CheckCategory.ACCOUNT_HYGIENE,
        check_id="hygiene_002",
        affected_objects=affected,
        mitre=MitreAttack("T1003.006", "DCSync", "Credential Access", known_tools=("Mimikatz", "secretsdump")),
        remediation=Remediation(
            "Disable reversible encryption and force password reset",
            powershell='Set-ADUser "<acct>" -AllowReversiblePasswordEncryption $false',
        ),
    )]


# ── hygiene_003: PASSWD_NOTREQD ─────────────────────────────────────────────


@register_check(
    check_id="hygiene_003",
    name="Password Not Required Flag",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Active accounts with the PASSWD_NOTREQD flag or passwords never set",
    tags=["hygiene", "policy_bypass"],
)
def check_password_not_required(ctx) -> list[Finding]:
    findings: list[Finding] = []

    # --- PASSWD_NOTREQD flag ---
    notreqd_results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_PASSWD_NOTREQD})"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName"],
    )
    if notreqd_results:
        affected = [e.get("sAMAccountName", "?") for e in notreqd_results]
        findings.append(Finding(
            title="Accounts with Password Not Required",
            description=f"{len(affected)} active account(s) may have blank passwords.",
            severity=Severity.HIGH,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_003",
            affected_objects=affected,
            remediation=Remediation(
                "Clear PASSWD_NOTREQD and set a password",
                powershell='Set-ADUser "<acct>" -PasswordNotRequired $false',
            ),
        ))

    # --- Password never set (pwdLastSet = 0) ---
    # pwdLastSet=0 means the password was never set or account was configured
    # with "must change password at next logon" and nobody ever logged in.
    never_set_results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        "(pwdLastSet=0)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "adminCount"],
    )
    if never_set_results:
        # Separate privileged from normal
        admin_hits = []
        user_hits = []
        for e in never_set_results:
            name = e.get("sAMAccountName", "?")
            if e.get("adminCount") == "1":
                admin_hits.append(name)
            else:
                user_hits.append(name)

        if admin_hits:
            findings.append(Finding(
                title=f"Privileged Accounts with Password Never Set ({len(admin_hits)})",
                description=(
                    f"{len(admin_hits)} privileged account(s) have pwdLastSet=0 — the password "
                    "was never set or the account requires a password change that never happened. "
                    "These accounts may have blank or default passwords."
                ),
                severity=Severity.CRITICAL,
                category=CheckCategory.ACCOUNT_HYGIENE,
                check_id="hygiene_003",
                affected_objects=admin_hits,
                mitre=MitreAttack(
                    "T1078.002", "Valid Accounts: Domain Accounts", "Initial Access",
                ),
                remediation=Remediation(
                    "Set a strong password on these accounts immediately",
                    powershell='Set-ADAccountPassword "<acct>" -Reset -NewPassword (Read-Host -AsSecureString)',
                ),
            ))
        if user_hits:
            findings.append(Finding(
                title=f"Accounts with Password Never Set ({len(user_hits)})",
                description=(
                    f"{len(user_hits)} active account(s) have pwdLastSet=0 — the password was "
                    "never set or requires a change that never happened. "
                    "These accounts may be accessible with blank or default credentials."
                ),
                severity=Severity.HIGH,
                category=CheckCategory.ACCOUNT_HYGIENE,
                check_id="hygiene_003",
                affected_objects=user_hits,
                mitre=MitreAttack(
                    "T1078.002", "Valid Accounts: Domain Accounts", "Initial Access",
                ),
                remediation=Remediation(
                    "Set a password or disable these accounts",
                    powershell='Set-ADAccountPassword "<acct>" -Reset -NewPassword (Read-Host -AsSecureString)',
                ),
            ))

    return findings


# ── hygiene_004: stale accounts ──────────────────────────────────────────────


@register_check(
    check_id="hygiene_004",
    name="Stale Privileged Accounts",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Admin accounts that have not logged in for 180+ days",
    tags=["hygiene", "stale"],
)
def check_stale_admin_accounts(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))(adminCount=1)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "lastLogonTimestamp"],
    )
    stale = []
    for e in results:
        days = _filetime_days_ago(e.get("lastLogonTimestamp"))
        if days is not None and days > 180:
            stale.append(f"{e.get('sAMAccountName', '?')} ({days}d)")
    if not stale:
        return []
    return [Finding(
        title="Stale Privileged Accounts",
        description=f"{len(stale)} admin account(s) have not logged in for 180+ days.",
        severity=Severity.MEDIUM,
        category=CheckCategory.ACCOUNT_HYGIENE,
        check_id="hygiene_004",
        affected_objects=stale,
        remediation=Remediation("Disable or remove stale privileged accounts"),
    )]


# ── hygiene_005: blank adminCount on DA members ─────────────────────────────


@register_check(
    check_id="hygiene_005",
    name="AdminSDHolder Orphans",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Accounts with adminCount=1 that are no longer in protected groups",
    tags=["hygiene", "privilege_escalation"],
)
def check_adminsdholder_orphans(ctx) -> list[Finding]:
    # Accounts with adminCount=1 but NOT in any protected group (recursive)
    protected_groups = [
        f"CN=Domain Admins,CN=Users,{ctx.domain_dn}",
        f"CN=Enterprise Admins,CN=Users,{ctx.domain_dn}",
        f"CN=Schema Admins,CN=Users,{ctx.domain_dn}",
        f"CN=Administrators,CN=Builtin,{ctx.domain_dn}",
        f"CN=Account Operators,CN=Builtin,{ctx.domain_dn}",
        f"CN=Server Operators,CN=Builtin,{ctx.domain_dn}",
        f"CN=Backup Operators,CN=Builtin,{ctx.domain_dn}",
        f"CN=Print Operators,CN=Builtin,{ctx.domain_dn}",
        f"CN=Domain Controllers,CN=Users,{ctx.domain_dn}",
    ]
    all_admin_flagged = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))(adminCount=1))",
        ["sAMAccountName", "distinguishedName"],
    )
    # Collect DNs of all members across all protected groups
    protected_dns: set[str] = set()
    for group_dn in protected_groups:
        members = ctx.ldap.search(
            f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))",
            ["distinguishedName"],
        )
        protected_dns.update(
            e["distinguishedName"] for e in members if "distinguishedName" in e
        )
    orphans = [
        e.get("sAMAccountName", "?")
        for e in all_admin_flagged
        if e.get("distinguishedName") not in protected_dns
    ]
    if not orphans:
        return []
    return [Finding(
        title="AdminSDHolder Orphan Accounts",
        description=(
            f"{len(orphans)} account(s) have adminCount=1 but aren't in protected groups. "
            "These retain elevated ACLs from prior group membership."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.ACCOUNT_HYGIENE,
        check_id="hygiene_005",
        affected_objects=orphans,
        remediation=Remediation(
            "Clear adminCount and reset inherited ACLs on orphaned accounts",
            powershell='Set-ADUser "<acct>" -Clear adminCount',
        ),
    )]


# ── hygiene_006: shadow credentials (msDS-KeyCredentialLink) ────────────────


@register_check(
    check_id="hygiene_006",
    name="Shadow Credentials",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Accounts with msDS-KeyCredentialLink (potential persistence via shadow credentials)",
    tags=["credential_access", "persistence"],
)
def check_shadow_credentials(ctx) -> list[Finding]:
    findings: list[Finding] = []

    # User accounts with KeyCredentialLink — suspicious unless WHfB is deployed
    users = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))(msDS-KeyCredentialLink=*)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "adminCount"],
    )
    admin_hits: list[str] = []
    user_hits: list[str] = []
    for e in users:
        name = e.get("sAMAccountName", "?")
        if e.get("adminCount") == "1":
            admin_hits.append(name)
        else:
            user_hits.append(name)

    mitre = MitreAttack(
        "T1556.006", "Multi-Factor Authentication Interception",
        "Credential Access",
        known_tools=("Whisker", "pyWhisker", "Certipy"),
    )

    if admin_hits:
        findings.append(Finding(
            title=f"Shadow Credentials on Privileged Accounts ({len(admin_hits)})",
            description=(
                f"{len(admin_hits)} admin account(s) have msDS-KeyCredentialLink set. "
                "An attacker can use these to obtain TGTs without knowing the password. "
                "Verify these are legitimate Windows Hello for Business enrollments."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_006",
            affected_objects=admin_hits,
            mitre=mitre,
            remediation=Remediation(
                "Audit KeyCredentialLink values; remove unauthorized entries",
                powershell='Get-ADUser "<acct>" -Properties msDS-KeyCredentialLink',
            ),
        ))
    if user_hits:
        findings.append(Finding(
            title=f"Shadow Credentials on User Accounts ({len(user_hits)})",
            description=(
                f"{len(user_hits)} user account(s) have msDS-KeyCredentialLink set. "
                "Review for unauthorized shadow credential persistence."
            ),
            severity=Severity.MEDIUM,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_006",
            affected_objects=user_hits,
            mitre=mitre,
            remediation=Remediation(
                "Audit KeyCredentialLink values on these accounts",
            ),
        ))

    return findings


# ── hygiene_007: SID History injection ──────────────────────────────────────


@register_check(
    check_id="hygiene_007",
    name="SID History Injection",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Accounts with sIDHistory populated (potential privilege escalation persistence)",
    tags=["persistence", "privilege_escalation"],
)
def check_sid_history(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(&(objectCategory=person)(objectClass=user)(sIDHistory=*))",
        ["sAMAccountName", "sIDHistory", "adminCount"],
    )
    if not results:
        return findings

    # Separate admin-level SID history from normal
    priv_hits: list[str] = []
    normal_hits: list[str] = []
    # Well-known privileged RIDs
    PRIV_RIDS = {"500", "502", "512", "516", "518", "519", "520"}

    for e in results:
        name = e.get("sAMAccountName", "?")
        sid_hist = e.get("sIDHistory") or []
        if isinstance(sid_hist, str):
            sid_hist = [sid_hist]

        has_priv_sid = False
        for sid in sid_hist:
            sid_str = str(sid)
            # Check if the injected SID ends with a privileged RID
            parts = sid_str.rsplit("-", 1)
            if len(parts) == 2 and parts[1] in PRIV_RIDS:
                has_priv_sid = True
                break

        if has_priv_sid or e.get("adminCount") == "1":
            priv_hits.append(f"{name} (SIDs: {len(sid_hist)})")
        else:
            normal_hits.append(f"{name} (SIDs: {len(sid_hist)})")

    mitre = MitreAttack(
        "T1134.005", "SID-History Injection", "Privilege Escalation",
        known_tools=("Mimikatz", "Impacket", "DSInternals"),
    )

    if priv_hits:
        findings.append(Finding(
            title=f"Privileged SID History Entries ({len(priv_hits)})",
            description=(
                f"{len(priv_hits)} account(s) have SID History containing privileged SIDs. "
                "This grants them rights in the domain the SID belongs to and may indicate "
                "a SID-History injection attack."
            ),
            severity=Severity.CRITICAL,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_007",
            affected_objects=priv_hits,
            mitre=mitre,
            remediation=Remediation(
                "Remove SID History entries unless required for migration",
                powershell='Get-ADUser "<acct>" -Properties sIDHistory | '
                           'ForEach-Object { Set-ADUser $_ -Remove @{sIDHistory=$_.sIDHistory} }',
                reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-cleanup",
            ),
        ))

    if normal_hits:
        findings.append(Finding(
            title=f"Accounts with SID History ({len(normal_hits)})",
            description=(
                f"{len(normal_hits)} account(s) have SID History entries. "
                "This is expected during domain migrations but should be cleaned up afterward."
            ),
            severity=Severity.MEDIUM,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_007",
            affected_objects=normal_hits,
            mitre=mitre,
            remediation=Remediation(
                "Remove SID History entries after migration is complete",
            ),
        ))

    return findings


# ── hygiene_008: Guest account enabled ────────────────────────────────────


@register_check(
    check_id="hygiene_008",
    name="Guest Account Enabled",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Checks whether the built-in Guest account is enabled",
    tags=["hygiene", "initial_access"],
)
def check_guest_account(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectClass=user)(sAMAccountName=Guest))",
        ["sAMAccountName", "userAccountControl"],
    )
    if not results:
        return []
    uac = int(results[0].get("userAccountControl", 0) or 0)
    if uac & UAC_DISABLED:
        return []
    return [Finding(
        title="Guest Account Is Enabled",
        description=(
            "Built-in Guest account is currently active. This allows unauthenticated "
            "or anonymous access to domain resources. The Guest account should "
            "always be disabled."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.ACCOUNT_HYGIENE,
        check_id="hygiene_008",
        affected_objects=["Guest"],
        mitre=MitreAttack(
            "T1078.001", "Valid Accounts: Default Accounts", "Initial Access",
        ),
        remediation=Remediation(
            "Disable the Guest account",
            powershell='Disable-ADAccount -Identity "Guest"',
        ),
    )]


# ── hygiene_009: default Administrator hygiene ────────────────────────────


@register_check(
    check_id="hygiene_009",
    name="Default Administrator Hygiene",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Checks the RID-500 Administrator account for rename and password age",
    tags=["hygiene", "credential_access"],
)
def check_default_administrator(ctx) -> list[Finding]:
    findings: list[Finding] = []
    # RID 500 is the built-in Administrator — query by well-known RID
    admin_sid = f"{ctx.domain_sid}-500"
    results = ctx.ldap.search(
        f"(objectSid={admin_sid})",
        ["sAMAccountName", "pwdLastSet", "userAccountControl"],
    )
    if not results:
        # Fallback: try by name
        results = ctx.ldap.search(
            "(&(objectClass=user)(adminCount=1)(objectSid=*))",
            ["sAMAccountName", "pwdLastSet", "objectSid"],
        )
        # Filter for RID 500
        def _sid_ends_500(raw_sid) -> bool:
            if isinstance(raw_sid, bytes):
                from lazyhound.finder.parsers import parse_sid
                sid_str, _ = parse_sid(raw_sid)
                return sid_str.endswith("-500")
            return str(raw_sid).endswith("-500")

        results = [
            r for r in results
            if _sid_ends_500(r.get("objectSid", ""))
        ]
    if not results:
        return findings
    entry = results[0]
    name = entry.get("sAMAccountName", "Administrator")

    # Check if renamed
    if name.lower() == "administrator":
        findings.append(Finding(
            title="Default Administrator Account Not Renamed",
            description=(
                "The RID-500 account still uses the default name 'Administrator'. "
                "Renaming it adds a minor layer of defense against targeted brute-force."
            ),
            severity=Severity.LOW,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_009",
            affected_objects=[name],
            remediation=Remediation(
                "Rename the Administrator account",
                powershell='Rename-ADObject -Identity (Get-ADUser -Identity Administrator).DistinguishedName -NewName "NewAdminName"',
            ),
        ))

    # Check password age
    days = _filetime_days_ago(entry.get("pwdLastSet"))
    if days is not None and days > 365:
        findings.append(Finding(
            title=f"Default Administrator Password Age: {days} Days",
            description=(
                f"The RID-500 Administrator password has not been changed in {days} days. "
                "This account cannot be locked out and is a prime target for password attacks."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.ACCOUNT_HYGIENE,
            check_id="hygiene_009",
            affected_objects=[name],
            mitre=MitreAttack(
                "T1078.002", "Valid Accounts: Domain Accounts", "Persistence",
            ),
            remediation=Remediation(
                "Rotate the RID-500 Administrator password regularly (at least annually)",
            ),
        ))
    return findings


# ── hygiene_010: stale computer accounts ──────────────────────────────────


@register_check(
    check_id="hygiene_010",
    name="Stale Computer Accounts",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Enabled computer accounts that have not authenticated in 180+ days",
    tags=["hygiene", "stale"],
)
def check_stale_computers(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        f"(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "lastLogonTimestamp", "operatingSystem"],
    )
    stale = []
    for e in results:
        days = _filetime_days_ago(e.get("lastLogonTimestamp"))
        if days is not None and days > 180:
            name = e.get("sAMAccountName", "?")
            os_name = e.get("operatingSystem", "")
            label = f"{name} ({days}d, {os_name})" if os_name else f"{name} ({days}d)"
            stale.append(label)
    if not stale:
        return []
    sev = Severity.HIGH if len(stale) > 50 else Severity.MEDIUM
    return [Finding(
        title=f"Stale Computer Accounts ({len(stale)})",
        description=(
            f"{len(stale)} enabled computer account(s) have not authenticated in 180+ days. "
            "Orphaned machine accounts can be taken over via machine account password "
            "spraying or re-registration attacks."
        ),
        severity=sev,
        category=CheckCategory.ACCOUNT_HYGIENE,
        check_id="hygiene_010",
        affected_objects=stale[:30],
        details={"total_stale": len(stale)},
        remediation=Remediation(
            "Disable or delete stale computer accounts",
            powershell='Search-ADAccount -AccountInactive -TimeSpan 180 -ComputersOnly | Disable-ADAccount',
        ),
    )]


# ── hygiene_011: service accounts in Domain Admins ─────────────────────────


@register_check(
    check_id="hygiene_011",
    name="Service Accounts in Domain Admins",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Kerberoastable accounts that are also Domain Admins",
    tags=["credential_access", "privilege_escalation"],
)
def check_service_accounts_in_da(ctx) -> list[Finding]:
    da_dn = f"CN=Domain Admins,CN=Users,{ctx.domain_dn}"
    results = ctx.ldap.search(
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(servicePrincipalName=*)"
        f"(memberOf:1.2.840.113556.1.4.1941:={da_dn})"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "servicePrincipalName"],
    )
    if not results:
        return []
    affected = [e.get("sAMAccountName", "?") for e in results]
    return [Finding(
        title=f"Kerberoastable Domain Admins ({len(affected)})",
        description=(
            f"{len(affected)} account(s) have SPNs AND are members of Domain Admins. "
            "A Kerberoasting attack can request service tickets for these accounts "
            "and crack them offline to obtain Domain Admin credentials."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.ACCOUNT_HYGIENE,
        check_id="hygiene_011",
        affected_objects=affected,
        mitre=MitreAttack(
            "T1558.003", "Kerberoasting", "Credential Access",
            known_tools=("Rubeus", "Impacket GetUserSPNs", "hashcat"),
        ),
        remediation=Remediation(
            "Remove SPNs from Domain Admin accounts or remove them from Domain Admins; "
            "migrate to gMSA for service functionality",
            powershell='Set-ADUser "<acct>" -ServicePrincipalNames @{Remove="<spn>"}',
        ),
    )]


# ── hygiene_012: smartcard required but hash reusable ─────────────────────

UAC_SMARTCARD_REQUIRED = 0x40000


@register_check(
    check_id="hygiene_012",
    name="Smartcard Required but Hash Reusable",
    category=CheckCategory.ACCOUNT_HYGIENE,
    description="Accounts with SMARTCARD_REQUIRED but old password hashes that may still work",
    tags=["credential_access", "persistence"],
)
def check_smartcard_hash_reuse(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_SMARTCARD_REQUIRED})"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_DISABLED})))",
        ["sAMAccountName", "pwdLastSet", "adminCount"],
    )
    if not results:
        return []

    stale_hash: list[str] = []
    admin_affected = False
    for e in results:
        days = _filetime_days_ago(e.get("pwdLastSet"))
        # If password was set long ago (before smartcard was likely enabled),
        # the NT hash may still be valid for pass-the-hash
        if days is not None and days > 365:
            name = e.get("sAMAccountName", "?")
            stale_hash.append(f"{name} (pwd age: {days}d)")
            if e.get("adminCount") == "1":
                admin_affected = True

    if not stale_hash:
        return []

    sev = Severity.HIGH if admin_affected else Severity.MEDIUM
    return [Finding(
        title=f"Smartcard-Required Accounts with Stale Password Hash ({len(stale_hash)})",
        description=(
            f"{len(stale_hash)} account(s) require smartcard logon but have password "
            "hashes older than 1 year. When SMARTCARD_REQUIRED is set, the AD password "
            "is randomized — but if it was never rotated after the flag was enabled, "
            "the old NT hash may still work for pass-the-hash or NTLM authentication."
        ),
        severity=sev,
        category=CheckCategory.ACCOUNT_HYGIENE,
        check_id="hygiene_012",
        affected_objects=stale_hash,
        mitre=MitreAttack(
            "T1550.002", "Pass the Hash", "Lateral Movement",
            known_tools=("Mimikatz", "Impacket", "CrackMapExec"),
        ),
        remediation=Remediation(
            "Reset the password on these accounts after enabling SMARTCARD_REQUIRED "
            "to ensure the NT hash is properly randomized",
            powershell='Set-ADAccountPassword "<acct>" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force)',
        ),
    )]

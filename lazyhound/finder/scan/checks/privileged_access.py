"""Privileged access checks: group membership, AdminCount, nested groups, DCSync."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity

UAC_DISABLED = 0x2


# ── priv_001: excessive Domain Admin membership ──────────────────────────────


@register_check(
    check_id="priv_001",
    name="Domain Admin Membership",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Checks for excessive membership in Domain Admins",
    tags=["privilege_escalation", "access_control"],
)
def check_domain_admin_count(ctx) -> list[Finding]:
    da_dn = f"CN=Domain Admins,CN=Users,{ctx.domain_dn}"
    results = ctx.ldap.search(
        f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={da_dn}))",
        ["sAMAccountName"],
    )
    if not results:
        return []
    members = [e.get("sAMAccountName", "?") for e in results]
    if len(members) <= 5:
        return []
    return [Finding(
        title=f"Excessive Domain Admin Members ({len(members)})",
        description=(
            f"{len(members)} accounts are Domain Admins (directly or nested). "
            "Best practice is fewer than 5."
        ),
        severity=Severity.HIGH if len(members) > 10 else Severity.MEDIUM,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_001",
        affected_objects=members,
        remediation=Remediation(
            "Reduce Domain Admin membership; use tiered administration model",
            reference_url="https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model",
        ),
    )]


# ── priv_002: users with DCSync rights ──────────────────────────────────────


@register_check(
    check_id="priv_002",
    name="DCSync Permissions",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Non-default accounts with Replicating Directory Changes rights",
    tags=["credential_access", "privilege_escalation"],
)
def check_dcsync_rights(ctx) -> list[Finding]:
    from lazyhound.finder.parsers import (
        ACCESS_ALLOWED_OBJECT_ACE,
        ADS_RIGHT_DS_CONTROL_ACCESS,
        DS_REPL_GET_CHANGES, DS_REPL_GET_CHANGES_ALL,
        is_admin_sid,
        parse_security_descriptor,
    )

    findings: list[Finding] = []

    # Parse domain object's DACL for DS-Replication-Get-Changes GUIDs
    domain_obj = ctx.ldap.search(
        "(objectClass=domain)",
        ["nTSecurityDescriptor"],
        search_base=ctx.domain_dn,
    )
    if not domain_obj:
        return findings

    sd_raw = domain_obj[0].get("nTSecurityDescriptor")
    if not isinstance(sd_raw, bytes):
        return findings

    sd = parse_security_descriptor(sd_raw)
    if not sd:
        return findings

    # Build per-SID set of replication GUIDs granted
    repl_guids: dict[str, set[str]] = {}  # sid -> set of repl GUIDs
    for ace in sd.dacl:
        if ace.ace_type != ACCESS_ALLOWED_OBJECT_ACE:
            continue
        if not (ace.access_mask & ADS_RIGHT_DS_CONTROL_ACCESS):
            continue
        obj_guid = ace.object_type.lower() if ace.object_type else ""
        if obj_guid in (DS_REPL_GET_CHANGES, DS_REPL_GET_CHANGES_ALL):
            repl_guids.setdefault(ace.sid, set()).add(obj_guid)

    # Flag SIDs that have BOTH replication rights and are not expected admin SIDs
    dcsync_sids: list[str] = []
    for sid, guids in repl_guids.items():
        if DS_REPL_GET_CHANGES in guids and DS_REPL_GET_CHANGES_ALL in guids:
            if not is_admin_sid(sid, ctx.domain_sid):
                dcsync_sids.append(sid)

    if dcsync_sids:
        findings.append(Finding(
            title=f"DCSync Rights: {len(dcsync_sids)} Non-Default Principal(s)",
            description=(
                f"{len(dcsync_sids)} non-default principal(s) have both "
                "DS-Replication-Get-Changes and DS-Replication-Get-Changes-All "
                "on the domain object, granting DCSync capability."
            ),
            severity=Severity.CRITICAL,
            category=CheckCategory.PRIVILEGED_ACCESS,
            check_id="priv_002",
            affected_objects=dcsync_sids,
            mitre=MitreAttack(
                "T1003.006", "DCSync", "Credential Access",
                known_tools=("Mimikatz lsadump::dcsync", "Impacket secretsdump"),
            ),
            remediation=Remediation(
                "Remove Replicating Directory Changes rights from non-DC principals",
                powershell='dsacls "<domain_dn>" /R "<principal>"',
            ),
        ))

    # Keep the heuristic check as a fallback for accounts that may have
    # inherited rights not visible on the domain object directly
    results = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))(adminCount=1)"
        "(!(|(sAMAccountName=krbtgt)(sAMAccountName=Administrator)))"
        f"(!(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,{ctx.domain_dn}))"
        f"(!(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Controllers,CN=Users,{ctx.domain_dn})))",
        ["sAMAccountName", "distinguishedName"],
    )
    if results:
        suspects = [e.get("sAMAccountName", "?") for e in results]
        findings.append(Finding(
            title="Potential DCSync-Capable Accounts (Heuristic)",
            description=(
                f"{len(suspects)} non-DA account(s) have adminCount=1 and are outside standard "
                "protected groups. Audit their ACLs for Replicating Directory Changes rights."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.PRIVILEGED_ACCESS,
            check_id="priv_002",
            affected_objects=suspects,
            mitre=MitreAttack(
                "T1003.006", "DCSync", "Credential Access",
                known_tools=("Mimikatz lsadump::dcsync", "Impacket secretsdump"),
            ),
            remediation=Remediation("Audit and remove unnecessary replication rights"),
        ))

    return findings


# ── priv_003: protected users group usage ────────────────────────────────────


@register_check(
    check_id="priv_003",
    name="Protected Users Group",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Checks whether privileged accounts are in the Protected Users group",
    tags=["access_control", "kerberos"],
)
def check_protected_users(ctx) -> list[Finding]:
    pu_dn = f"CN=Protected Users,CN=Users,{ctx.domain_dn}"
    protected = ctx.ldap.search(
        f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={pu_dn}))",
        ["sAMAccountName"],
    )
    protected_names = {e.get("sAMAccountName") for e in protected}

    da_dn = f"CN=Domain Admins,CN=Users,{ctx.domain_dn}"
    das = ctx.ldap.search(
        f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={da_dn}))",
        ["sAMAccountName"],
    )
    unprotected = [
        e.get("sAMAccountName", "?")
        for e in das
        if e.get("sAMAccountName") not in protected_names
    ]
    if not unprotected:
        return []
    return [Finding(
        title="Domain Admins Not in Protected Users Group",
        description=(
            f"{len(unprotected)} Domain Admin(s) are not in the Protected Users group, "
            "missing credential theft protections (no NTLM, no delegation, short TGT lifetime)."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_003",
        affected_objects=unprotected,
        remediation=Remediation(
            "Add privileged accounts to the Protected Users group",
            powershell='Add-ADGroupMember -Identity "Protected Users" -Members "<acct>"',
            reference_url="https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group",
        ),
    )]


# ── priv_004: AdminSDHolder ACL audit ────────────────────────────────────────


@register_check(
    check_id="priv_004",
    name="AdminSDHolder ACL Audit",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Parses the AdminSDHolder DACL for non-default dangerous permissions",
    tags=["privilege_escalation", "access_control"],
)
def check_adminsdholder_acl(ctx) -> list[Finding]:
    from lazyhound.finder.parsers import (
        has_dangerous_access, is_admin_sid,
        parse_security_descriptor,
    )

    results = ctx.ldap.search(
        "(cn=AdminSDHolder)",
        ["nTSecurityDescriptor"],
        search_base=f"CN=System,{ctx.domain_dn}",
    )
    if not results:
        return []

    sd_raw = results[0].get("nTSecurityDescriptor")
    if not isinstance(sd_raw, bytes):
        return []

    sd = parse_security_descriptor(sd_raw)
    if not sd:
        return []

    suspicious: list[str] = []
    for ace in sd.dacl:
        if not has_dangerous_access(ace):
            continue
        if is_admin_sid(ace.sid, ctx.domain_sid):
            continue
        suspicious.append(f"{ace.sid} (mask=0x{ace.access_mask:08x})")

    if not suspicious:
        return []

    return [Finding(
        title=f"AdminSDHolder: {len(suspicious)} Non-Default Dangerous ACE(s)",
        description=(
            "The AdminSDHolder object's DACL is propagated to all protected accounts "
            "(Domain Admins, etc.) every 60 minutes.  Non-default write permissions "
            "here grant persistent backdoor access to all privileged accounts."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_004",
        affected_objects=suspicious,
        mitre=MitreAttack(
            "T1222.001", "File and Directory Permissions Modification: Windows",
            "Defense Evasion",
            known_tools=("PowerView", "BloodHound", "ADExplorer"),
        ),
        remediation=Remediation(
            "Remove non-default ACEs from AdminSDHolder",
            powershell=(
                'dsacls "CN=AdminSDHolder,CN=System,<domain_dn>" /R "<principal>"'
            ),
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory",
            effort="high",
        ),
    )]


# ── priv_005: Exchange PrivExchange ──────────────────────────────────────────


@register_check(
    check_id="priv_005",
    name="Exchange PrivExchange",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Detects Exchange groups with excessive domain-level permissions",
    tags=["privilege_escalation", "exchange"],
)
def check_exchange_privexchange(ctx) -> list[Finding]:
    from lazyhound.finder.parsers import (
        WRITE_DAC, WRITE_OWNER, GENERIC_ALL,
        parse_security_descriptor,
    )

    findings: list[Finding] = []

    # Step 1: Check if Exchange Windows Permissions group exists
    ewp = ctx.ldap.search(
        "(&(objectClass=group)(cn=Exchange Windows Permissions))",
        ["distinguishedName", "objectSid"],
    )
    if not ewp:
        return findings

    ewp_sid = ""
    ewp_raw_sid = ewp[0].get("objectSid")
    if isinstance(ewp_raw_sid, bytes):
        from lazyhound.finder.parsers import parse_sid
        ewp_sid, _ = parse_sid(ewp_raw_sid)
    elif isinstance(ewp_raw_sid, str):
        ewp_sid = ewp_raw_sid

    if not ewp_sid:
        return findings

    # Step 2: Read domain object's security descriptor
    domain_obj = ctx.ldap.search(
        "(objectClass=domain)",
        ["nTSecurityDescriptor"],
        search_base=ctx.domain_dn,
    )
    if not domain_obj:
        return findings

    sd_raw = domain_obj[0].get("nTSecurityDescriptor")
    if not isinstance(sd_raw, bytes):
        return findings

    sd = parse_security_descriptor(sd_raw)
    if not sd:
        return findings

    # Step 3: Check if Exchange Windows Permissions has WriteDACL on domain
    dangerous_mask = WRITE_DAC | WRITE_OWNER | GENERIC_ALL
    for ace in sd.dacl:
        if ace.sid == ewp_sid and (ace.access_mask & dangerous_mask):
            findings.append(Finding(
                title="Exchange PrivExchange: WriteDACL on Domain",
                description=(
                    "The 'Exchange Windows Permissions' group has WriteDACL rights on "
                    "the domain root.  Any Exchange server or member of this group can "
                    "grant themselves DCSync rights and dump all password hashes."
                ),
                severity=Severity.CRITICAL,
                category=CheckCategory.PRIVILEGED_ACCESS,
                check_id="priv_005",
                affected_objects=[ewp[0].get("distinguishedName", ewp_sid)],
                mitre=MitreAttack(
                    "T1003.006", "DCSync", "Credential Access",
                    known_tools=("PrivExchange", "ntlmrelayx", "Impacket"),
                ),
                remediation=Remediation(
                    "Remove WriteDACL from Exchange Windows Permissions on the domain object",
                    powershell=(
                        'dsacls "<domain_dn>" /R "Exchange Windows Permissions"'
                    ),
                    reference_url="https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/",
                    effort="medium",
                ),
            ))
            break

    return findings


# ── priv_006: Pre-Windows 2000 Compatible Access group ──────────────────────


@register_check(
    check_id="priv_006",
    name="Pre-Windows 2000 Compatible Access",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Checks if the Pre-Windows 2000 Compatible Access group contains broadly-scoped principals",
    tags=["access_control", "legacy", "reconnaissance"],
)
def check_pre_w2k_access(ctx) -> list[Finding]:
    pw2k_dn = f"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{ctx.domain_dn}"
    members = ctx.ldap.search(
        f"(&(objectClass=*)(memberOf:1.2.840.113556.1.4.1941:={pw2k_dn}))",
        ["sAMAccountName", "objectSid", "objectClass"],
    )

    # Also check direct group membership
    group_result = ctx.ldap.search(
        f"(distinguishedName={pw2k_dn})",
        ["member"],
    )
    direct_members: list[str] = []
    if group_result:
        dm = group_result[0].get("member") or []
        if isinstance(dm, str):
            dm = [dm]
        direct_members = dm

    # Check for dangerous well-known members
    dangerous_members: list[str] = []

    for dn in direct_members:
        # Check by DN patterns for well-known groups
        cn = dn.split(",")[0].replace("CN=", "") if "CN=" in dn else dn
        if cn.lower() in ("authenticated users", "everyone", "anonymous logon"):
            dangerous_members.append(cn)

    # Also check via recursive member search results
    for m in members:
        name = m.get("sAMAccountName") or ""
        if name and name.lower() in ("authenticated users", "everyone", "anonymous logon"):
            if name not in dangerous_members:
                dangerous_members.append(name)

    if not dangerous_members:
        return []

    return [Finding(
        title="Pre-Windows 2000 Compatible Access: Dangerous Members",
        description=(
            f"The Pre-Windows 2000 Compatible Access group contains {', '.join(dangerous_members)}. "
            "This grants broad read access to all AD objects, enabling reconnaissance by "
            "any authenticated user (or anonymous users if 'Anonymous Logon' is included)."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_006",
        affected_objects=dangerous_members,
        mitre=MitreAttack(
            "T1087.002", "Account Discovery: Domain Account", "Discovery",
            known_tools=("BloodHound", "PowerView", "ldapsearch"),
        ),
        remediation=Remediation(
            "Remove 'Authenticated Users' and 'Everyone' from this group; "
            "only add specific service accounts that require legacy compatibility",
            powershell='Remove-ADGroupMember "Pre-Windows 2000 Compatible Access" -Members "Authenticated Users" -Confirm:$false',
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
        ),
    )]


# ── priv_007: privileged group sprawl ──────────────────────────────────────


@register_check(
    check_id="priv_007",
    name="Privileged Group Sprawl",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Checks membership in high-privilege groups beyond Domain Admins",
    tags=["privilege_escalation", "access_control"],
)
def check_privileged_group_sprawl(ctx) -> list[Finding]:
    findings: list[Finding] = []
    groups = {
        "Enterprise Admins": f"CN=Enterprise Admins,CN=Users,{ctx.domain_dn}",
        "Schema Admins": f"CN=Schema Admins,CN=Users,{ctx.domain_dn}",
        "Backup Operators": f"CN=Backup Operators,CN=Builtin,{ctx.domain_dn}",
        "Account Operators": f"CN=Account Operators,CN=Builtin,{ctx.domain_dn}",
        "Server Operators": f"CN=Server Operators,CN=Builtin,{ctx.domain_dn}",
        "Print Operators": f"CN=Print Operators,CN=Builtin,{ctx.domain_dn}",
    }
    # Groups that should ideally be empty
    should_be_empty = {"Enterprise Admins", "Schema Admins"}

    for group_name, group_dn in groups.items():
        members = ctx.ldap.search(
            f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))",
            ["sAMAccountName"],
        )
        if not members:
            continue
        affected = [e.get("sAMAccountName", "?") for e in members]

        if group_name in should_be_empty:
            findings.append(Finding(
                title=f"{group_name}: {len(affected)} Member(s) (Should Be Empty)",
                description=(
                    f"{group_name} has {len(affected)} member(s). This group should "
                    "be empty except during active schema or forest changes."
                ),
                severity=Severity.HIGH,
                category=CheckCategory.PRIVILEGED_ACCESS,
                check_id="priv_007",
                affected_objects=affected,
                remediation=Remediation(
                    f"Remove all permanent members from {group_name}; add temporarily only when needed",
                    powershell=f'Remove-ADGroupMember -Identity "{group_name}" -Members "<acct>" -Confirm:$false',
                ),
            ))
        elif len(affected) > 3:
            findings.append(Finding(
                title=f"{group_name}: {len(affected)} Member(s)",
                description=(
                    f"{group_name} has {len(affected)} member(s). "
                    "Operator groups grant significant privileges and should be minimized."
                ),
                severity=Severity.MEDIUM,
                category=CheckCategory.PRIVILEGED_ACCESS,
                check_id="priv_007",
                affected_objects=affected,
                remediation=Remediation(
                    f"Review and reduce membership in {group_name}",
                    reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
                ),
            ))
    return findings


# ── priv_008: DNSAdmins abuse ─────────────────────────────────────────────


@register_check(
    check_id="priv_008",
    name="DNSAdmins Abuse",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Members of DNSAdmins can load arbitrary DLLs on domain controllers",
    tags=["privilege_escalation", "dns"],
)
def check_dnsadmins(ctx) -> list[Finding]:
    dns_admins_dn = f"CN=DnsAdmins,CN=Users,{ctx.domain_dn}"
    members = ctx.ldap.search(
        f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={dns_admins_dn}))",
        ["sAMAccountName"],
    )
    if not members:
        return []
    affected = [e.get("sAMAccountName", "?") for e in members]
    return [Finding(
        title=f"DNSAdmins Group: {len(affected)} Member(s)",
        description=(
            f"{len(affected)} user(s) in DNSAdmins. Members can configure the DNS "
            "service on DCs to load an arbitrary DLL via dnscmd /config "
            "/serverlevelplugindll, achieving SYSTEM-level code execution on DCs."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_008",
        affected_objects=affected,
        mitre=MitreAttack(
            "T1574", "Hijack Execution Flow", "Privilege Escalation",
            known_tools=("dnscmd", "PowerView"),
        ),
        remediation=Remediation(
            "Minimize DNSAdmins membership; treat it as a Tier 0 group",
            reference_url="https://adsecurity.org/?p=4064",
        ),
    )]


# ── priv_009: computers in privileged groups ──────────────────────────────


@register_check(
    check_id="priv_009",
    name="Computers in Privileged Groups",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Machine accounts that are members of Tier 0 privileged groups",
    tags=["privilege_escalation", "access_control"],
)
def check_computers_in_priv_groups(ctx) -> list[Finding]:
    findings: list[Finding] = []
    priv_groups = {
        "Domain Admins": f"CN=Domain Admins,CN=Users,{ctx.domain_dn}",
        "Enterprise Admins": f"CN=Enterprise Admins,CN=Users,{ctx.domain_dn}",
        "Administrators": f"CN=Administrators,CN=Builtin,{ctx.domain_dn}",
    }
    all_hits: list[str] = []
    for group_name, group_dn in priv_groups.items():
        members = ctx.ldap.search(
            f"(&(objectClass=computer)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))",
            ["sAMAccountName"],
        )
        for m in members:
            name = m.get("sAMAccountName", "?")
            all_hits.append(f"{name} ({group_name})")

    if not all_hits:
        return findings
    return [Finding(
        title=f"Computer Accounts in Privileged Groups ({len(all_hits)})",
        description=(
            "Machine accounts are members of Tier 0 groups. Compromising any of "
            "these computers grants the attacker domain-admin-equivalent privileges. "
            "This often results from SCCM or orchestration misconfigurations."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_009",
        affected_objects=all_hits,
        mitre=MitreAttack(
            "T1078.002", "Valid Accounts: Domain Accounts", "Privilege Escalation",
        ),
        remediation=Remediation(
            "Remove computer accounts from privileged groups; use dedicated service accounts instead",
        ),
    )]


# ── priv_010: GMSA password readers ──────────────────────────────────────


@register_check(
    check_id="priv_010",
    name="GMSA Password Readers",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Identifies gMSAs with broadly-scoped password retrieval principals",
    tags=["credential_access", "service_accounts"],
)
def check_gmsa_password_readers(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(&(objectClass=msDS-GroupManagedServiceAccount))",
        ["sAMAccountName", "msDS-GroupMSAMembership"],
    )
    if not results:
        return []

    from lazyhound.finder.parsers import (
        is_low_privilege_sid, parse_security_descriptor,
    )

    broad_access: list[str] = []
    for gmsa in results:
        name = gmsa.get("sAMAccountName", "?")
        sd_raw = gmsa.get("msDS-GroupMSAMembership")
        if not isinstance(sd_raw, bytes):
            continue
        sd = parse_security_descriptor(sd_raw)
        if not sd:
            continue
        for ace in sd.dacl:
            if is_low_privilege_sid(ace.sid, ctx.domain_sid):
                broad_access.append(f"{name} (SID: {ace.sid})")
                break

    if not broad_access:
        return []
    return [Finding(
        title=f"gMSAs with Broad Password Retrieval ({len(broad_access)})",
        description=(
            "Group Managed Service Accounts allow low-privilege principals "
            "(e.g., Domain Users, Authenticated Users) to retrieve their passwords. "
            "An attacker can read the gMSA password and impersonate the service account."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_010",
        affected_objects=broad_access,
        mitre=MitreAttack(
            "T1555", "Credentials from Password Stores", "Credential Access",
            known_tools=("gMSADumper", "GMSAPasswordReader", "Impacket"),
        ),
        remediation=Remediation(
            "Restrict msDS-GroupMSAMembership to only the specific computer/service accounts that need the password",
            powershell='Set-ADServiceAccount "<gMSA>" -PrincipalsAllowedToRetrieveManagedPassword "<specific_account>"',
        ),
    )]


# ── priv_011: LAPS password ACL audit ────────────────────────────────────


@register_check(
    check_id="priv_011",
    name="LAPS Password ACL Audit",
    category=CheckCategory.PRIVILEGED_ACCESS,
    description="Identifies computers where low-privilege principals can read LAPS passwords",
    tags=["credential_access", "lateral_movement", "laps"],
)
def check_laps_acl(ctx) -> list[Finding]:
    from lazyhound.finder.parsers import (
        ADS_RIGHT_DS_CONTROL_ACCESS,
        is_admin_sid, is_low_privilege_sid,
        parse_security_descriptor,
    )

    # Only check computers that have LAPS deployed
    computer_filter = (
        "(&(objectClass=computer)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        "(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)))"
    )
    try:
        computers = ctx.ldap.search(
            computer_filter,
            ["sAMAccountName", "nTSecurityDescriptor"],
        )
    except Exception:
        computers = []  # LAPS schema not installed
    if not computers:
        return []

    # LAPS extended-rights GUIDs
    LAPS_GUIDS = {
        "69b4a0d4-783c-4846-a54b-7e8c01b0e7c7",  # ms-Mcs-AdmPwd (legacy LAPS read)
    }

    broad_readable: list[str] = []
    for comp in computers:
        name = comp.get("sAMAccountName", "?")
        sd_raw = comp.get("nTSecurityDescriptor")
        if not isinstance(sd_raw, bytes):
            continue
        sd = parse_security_descriptor(sd_raw)
        if not sd:
            continue
        for ace in sd.dacl:
            if not is_low_privilege_sid(ace.sid, ctx.domain_sid):
                continue
            if is_admin_sid(ace.sid, ctx.domain_sid):
                continue
            # Check for control access on LAPS attribute or generic read all
            if ace.access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
                if not ace.object_type or ace.object_type.lower() in LAPS_GUIDS:
                    broad_readable.append(f"{name} (SID: {ace.sid})")
                    break

    if not broad_readable:
        return []
    return [Finding(
        title=f"LAPS Passwords Readable by Low-Privilege Principals ({len(broad_readable)})",
        description=(
            "Low-privilege principals (Domain Users, Authenticated Users, etc.) can "
            "read LAPS-managed local administrator passwords on these computers. "
            "This gives any domain user local admin access to the affected machines."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.PRIVILEGED_ACCESS,
        check_id="priv_011",
        affected_objects=broad_readable[:20],
        details={"total_affected": len(broad_readable)},
        mitre=MitreAttack(
            "T1078.002", "Valid Accounts: Domain Accounts", "Lateral Movement",
            known_tools=("CrackMapExec", "LAPSToolkit", "PowerView"),
        ),
        remediation=Remediation(
            "Restrict LAPS password read access to specific admin groups per OU",
            powershell='Set-AdmPwdReadPasswordPermission -OrgUnit "<OU>" -AllowedPrincipals "<admin_group>"',
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
        ),
    )]

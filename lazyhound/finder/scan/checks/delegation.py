"""Delegation security checks: unconstrained, constrained, RBCD."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity

UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_TRUSTED_TO_AUTH = 0x1000000
UAC_IS_DC = 0x2000

DANGEROUS_SPN_PREFIXES = ("ldap/", "host/", "cifs/", "http/", "wsman/", "rpcss/")


# ── deleg_001: unconstrained delegation ──────────────────────────────────────


@register_check(
    check_id="deleg_001",
    name="Unconstrained Delegation",
    category=CheckCategory.DELEGATION,
    description="Non-DC systems with unconstrained delegation",
    tags=["lateral_movement", "delegation"],
)
def check_unconstrained(ctx) -> list[Finding]:
    findings: list[Finding] = []
    mitre = MitreAttack(
        "T1550.003", "Pass the Ticket", "Lateral Movement",
        known_tools=("Rubeus", "Mimikatz", "Impacket"),
    )
    # computers (excluding DCs)
    comps = ctx.ldap.search(
        "(&(objectClass=computer)"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_TRUSTED_FOR_DELEGATION})"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_IS_DC})))",
        ["sAMAccountName", "dNSHostName"],
    )
    if comps:
        affected = [e.get("dNSHostName") or e.get("sAMAccountName", "?") for e in comps]
        findings.append(Finding(
            title="Unconstrained Delegation on Non-DC Computers",
            description=(
                f"{len(affected)} non-DC computer(s) cache every authenticating user's TGT, "
                "enabling attacker impersonation of any user including Domain Admins."
            ),
            severity=Severity.CRITICAL,
            category=CheckCategory.DELEGATION,
            check_id="deleg_001",
            affected_objects=affected,
            mitre=mitre,
            remediation=Remediation(
                "Replace unconstrained delegation with constrained delegation or RBCD",
                powershell='Set-ADComputer "<host>" -TrustedForDelegation $false',
                reference_url="https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview",
                effort="high",
            ),
        ))
    # user accounts (should almost never exist)
    users = ctx.ldap.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_TRUSTED_FOR_DELEGATION}))",
        ["sAMAccountName"],
    )
    if users:
        affected = [e.get("sAMAccountName", "?") for e in users]
        findings.append(Finding(
            title="Unconstrained Delegation on User Accounts",
            description=f"{len(affected)} user account(s) — almost never required.",
            severity=Severity.CRITICAL,
            category=CheckCategory.DELEGATION,
            check_id="deleg_001",
            affected_objects=affected,
            mitre=mitre,
            remediation=Remediation("Remove unconstrained delegation from user accounts"),
        ))
    return findings


# ── deleg_002: constrained delegation w/ protocol transition ─────────────────


@register_check(
    check_id="deleg_002",
    name="Constrained Delegation with Protocol Transition",
    category=CheckCategory.DELEGATION,
    description="Protocol transition to sensitive targets (S4U2Self abuse)",
    tags=["lateral_movement", "delegation", "privilege_escalation"],
)
def check_constrained(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(&(objectCategory=*)"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_TRUSTED_TO_AUTH})"
        "(msDS-AllowedToDelegateTo=*))",
        ["sAMAccountName", "msDS-AllowedToDelegateTo", "objectClass"],
    )
    if not results:
        return findings

    dc_names: set[str] = set()
    for dc in ctx.get_domain_controllers():
        for attr in ("dNSHostName", "sAMAccountName"):
            v = dc.get(attr)
            if v:
                dc_names.add(v.rstrip("$").lower())

    critical, high = [], []
    for e in results:
        name = e.get("sAMAccountName", "?")
        targets = e.get("msDS-AllowedToDelegateTo") or []
        if isinstance(targets, str):
            targets = [targets]
        hits_dc = any(
            any(dc in t.lower().split("/", 1)[-1].split(":")[0] for dc in dc_names)
            for t in targets
            if any(t.lower().startswith(p) for p in DANGEROUS_SPN_PREFIXES)
        )
        label = f"{name} -> {', '.join(targets)}"
        (critical if hits_dc else high).append(label)

    mitre = MitreAttack(
        "T1134.001", "Token Impersonation/Theft", "Privilege Escalation",
        known_tools=("Rubeus s4u", "Impacket getST"),
    )
    if critical:
        findings.append(Finding(
            title="Protocol Transition Delegation to Domain Controllers",
            description="Enables impersonation of any user (including Domain Admins) to DC services.",
            severity=Severity.CRITICAL,
            category=CheckCategory.DELEGATION,
            check_id="deleg_002",
            affected_objects=critical,
            mitre=mitre,
            remediation=Remediation("Remove protocol transition or restrict targets away from DCs", effort="high"),
        ))
    if high:
        findings.append(Finding(
            title="Constrained Delegation with Protocol Transition",
            description=f"{len(high)} account(s) can impersonate any user to their targets.",
            severity=Severity.HIGH,
            category=CheckCategory.DELEGATION,
            check_id="deleg_002",
            affected_objects=high,
            mitre=mitre,
            remediation=Remediation("Remove protocol transition or switch to RBCD with tighter controls"),
        ))
    return findings


# ── deleg_003: resource-based constrained delegation (RBCD) ──────────────────


@register_check(
    check_id="deleg_003",
    name="Resource-Based Constrained Delegation",
    category=CheckCategory.DELEGATION,
    description="RBCD configured on computers (msDS-AllowedToActOnBehalfOfOtherIdentity)",
    tags=["lateral_movement", "delegation"],
)
def check_rbcd(ctx) -> list[Finding]:
    from lazyhound.finder.parsers import parse_security_descriptor

    results = ctx.ldap.search(
        "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
        ["sAMAccountName", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
    )
    if not results:
        return []

    affected: list[str] = []
    for e in results:
        host = e.get("dNSHostName") or e.get("sAMAccountName", "?")
        sd_raw = e.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        delegators: list[str] = []
        if isinstance(sd_raw, bytes):
            sd = parse_security_descriptor(sd_raw)
            if sd:
                delegators = [ace.sid for ace in sd.dacl if ace.sid]
        if delegators:
            affected.append(f"{host} <- [{', '.join(delegators)}]")
        else:
            affected.append(host)

    return [Finding(
        title="RBCD Delegation Set on Computer Accounts",
        description=(
            f"{len(affected)} computer(s) have msDS-AllowedToActOnBehalfOfOtherIdentity set.  "
            "Review to ensure these are intentional and not attacker-planted."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.DELEGATION,
        check_id="deleg_003",
        affected_objects=affected,
        mitre=MitreAttack(
            "T1134.001", "Token Impersonation/Theft", "Privilege Escalation",
            known_tools=("Rubeus s4u", "Impacket rbcd"),
        ),
        remediation=Remediation(
            "Audit RBCD configurations and remove unauthorized entries",
            powershell='Get-ADComputer "<host>" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity',
        ),
    )]

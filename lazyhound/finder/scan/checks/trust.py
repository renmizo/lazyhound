"""Domain trust security checks: SID filtering, trust attributes."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity

# trustDirection values
TRUST_DIRECTION_INBOUND = 1
TRUST_DIRECTION_OUTBOUND = 2
TRUST_DIRECTION_BIDIRECTIONAL = 3

# trustType values
TRUST_TYPE_DOWNLEVEL = 1   # Windows NT
TRUST_TYPE_UPLEVEL = 2     # Active Directory
TRUST_TYPE_MIT = 3         # Non-Windows Kerberos

# trustAttributes bit flags
TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1
TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x2
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x4   # SID filtering enabled
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x8
TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20
TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x40

_DIRECTION_LABELS = {
    TRUST_DIRECTION_INBOUND: "Inbound",
    TRUST_DIRECTION_OUTBOUND: "Outbound",
    TRUST_DIRECTION_BIDIRECTIONAL: "Bidirectional",
}


# ── trust_001: SID filtering on domain trusts ────────────────────────────────


@register_check(
    check_id="trust_001",
    name="Domain Trust SID Filtering",
    category=CheckCategory.TRUST,
    description="Checks whether SID filtering is enforced on domain/forest trusts",
    tags=["lateral_movement", "trust", "persistence"],
)
def check_trust_sid_filtering(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(objectClass=trustedDomain)",
        [
            "cn", "trustPartner", "trustDirection", "trustType",
            "trustAttributes", "flatName",
        ],
    )
    if not results:
        return findings

    no_filter_external: list[str] = []
    no_filter_forest: list[str] = []

    for trust in results:
        partner = trust.get("trustPartner") or trust.get("cn", "?")
        attrs = int(trust.get("trustAttributes", 0) or 0)
        direction = int(trust.get("trustDirection", 0) or 0)
        direction_label = _DIRECTION_LABELS.get(direction, "Unknown")

        # Intra-forest trusts are inherently non-filtered — skip
        if attrs & TRUST_ATTRIBUTE_WITHIN_FOREST:
            continue

        sid_filtered = bool(attrs & TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)
        if sid_filtered:
            continue

        label = f"{partner} ({direction_label})"
        if attrs & TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            no_filter_forest.append(label)
        else:
            no_filter_external.append(label)

    mitre = MitreAttack(
        "T1134.005", "SID-History Injection", "Privilege Escalation",
        known_tools=("Mimikatz", "Impacket"),
    )

    if no_filter_external:
        findings.append(Finding(
            title=f"External Trusts Without SID Filtering ({len(no_filter_external)})",
            description=(
                "External domain trusts without SID filtering (quarantine) allow "
                "a compromised trusted domain to inject SID-History claims and "
                "escalate privileges in this forest."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.TRUST,
            check_id="trust_001",
            affected_objects=no_filter_external,
            mitre=mitre,
            remediation=Remediation(
                "Enable SID filtering (quarantine) on all external trusts",
                powershell='netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes',
                reference_url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10)",
            ),
        ))

    if no_filter_forest:
        findings.append(Finding(
            title=f"Forest Trusts Without SID Filtering ({len(no_filter_forest)})",
            description=(
                "Cross-forest trusts without SID filtering allow SID-History "
                "injection from the trusted forest."
            ),
            severity=Severity.CRITICAL,
            category=CheckCategory.TRUST,
            check_id="trust_001",
            affected_objects=no_filter_forest,
            mitre=mitre,
            remediation=Remediation(
                "Enable SID filtering on forest trusts",
                powershell='netdom trust <TrustingDomain> /domain:<TrustedDomain> /enablesidhistory:no',
                effort="high",
            ),
        ))

    return findings


# ── trust_002: orphaned foreign security principals ───────────────────────


@register_check(
    check_id="trust_002",
    name="Orphaned Foreign Security Principals",
    category=CheckCategory.TRUST,
    description="Foreign security principals that no longer resolve to a valid account",
    tags=["trust", "hygiene"],
)
def check_orphaned_fsps(ctx) -> list[Finding]:
    fsp_dn = f"CN=ForeignSecurityPrincipals,{ctx.domain_dn}"
    results = ctx.ldap.search(
        "(objectClass=foreignSecurityPrincipal)",
        ["cn", "name", "objectSid"],
        search_base=fsp_dn,
    )
    if not results:
        return []

    # FSPs with CN starting with "S-1-5-21-" are domain SIDs that should resolve
    # to an actual account. If the name == the SID string, it likely didn't resolve.
    orphans: list[str] = []
    for fsp in results:
        cn = fsp.get("cn", "")
        name = fsp.get("name", "")
        # Well-known SIDs like S-1-5-11 are expected; focus on domain SIDs
        if cn.startswith("S-1-5-21-") and cn == name:
            orphans.append(cn)

    if not orphans:
        return []
    return [Finding(
        title=f"Orphaned Foreign Security Principals ({len(orphans)})",
        description=(
            f"{len(orphans)} foreign security principal(s) reference SIDs from trusted "
            "domains that no longer resolve. These may indicate stale cross-domain "
            "access that cannot be audited or may be abused if the trusted domain "
            "is re-created with the same SID."
        ),
        severity=Severity.LOW,
        category=CheckCategory.TRUST,
        check_id="trust_002",
        affected_objects=orphans[:20],
        details={"total_orphans": len(orphans)},
        remediation=Remediation(
            "Remove orphaned FSPs that reference deleted or inaccessible trusted domains",
        ),
    )]


# ── trust_003: inbound trust with TGT delegation ────────────────────────


@register_check(
    check_id="trust_003",
    name="Inbound Trust with TGT Delegation",
    category=CheckCategory.TRUST,
    description="Trusts without cross-organization flag allow TGT delegation across the boundary",
    tags=["trust", "lateral_movement", "delegation"],
)
def check_trust_tgt_delegation(ctx) -> list[Finding]:
    results = ctx.ldap.search(
        "(objectClass=trustedDomain)",
        ["cn", "trustPartner", "trustDirection", "trustAttributes"],
    )
    if not results:
        return []

    vulnerable: list[str] = []
    for trust in results:
        partner = trust.get("trustPartner") or trust.get("cn", "?")
        attrs = int(trust.get("trustAttributes", 0) or 0)
        direction = int(trust.get("trustDirection", 0) or 0)

        # Only check inbound or bidirectional trusts
        if direction not in (TRUST_DIRECTION_INBOUND, TRUST_DIRECTION_BIDIRECTIONAL):
            continue

        # Skip intra-forest trusts
        if attrs & TRUST_ATTRIBUTE_WITHIN_FOREST:
            continue

        # CROSS_ORGANIZATION (0x10) restricts TGT delegation
        if not (attrs & TRUST_ATTRIBUTE_CROSS_ORGANIZATION):
            direction_label = _DIRECTION_LABELS.get(direction, "Unknown")
            vulnerable.append(f"{partner} ({direction_label})")

    if not vulnerable:
        return []
    return [Finding(
        title=f"Trusts Allowing TGT Delegation ({len(vulnerable)})",
        description=(
            "Inbound or bidirectional trusts without the CROSS_ORGANIZATION flag "
            "allow TGT delegation across the trust boundary. Users from the trusted "
            "domain can have their TGTs forwarded to services in this domain, "
            "potentially enabling impersonation through unconstrained delegation hosts."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.TRUST,
        check_id="trust_003",
        affected_objects=vulnerable,
        mitre=MitreAttack(
            "T1550.003", "Pass the Ticket", "Lateral Movement",
            known_tools=("Rubeus", "Mimikatz"),
        ),
        remediation=Remediation(
            "Enable Selective Authentication and CROSS_ORGANIZATION on external trusts",
            powershell='netdom trust <domain> /domain:<trusted_domain> /SelectiveAuth:yes',
        ),
    )]

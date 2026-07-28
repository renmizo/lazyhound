"""Password policy checks: default policy, fine-grained policies, lockout."""

from __future__ import annotations

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity


# ── pwd_001: default domain password policy ──────────────────────────────────


@register_check(
    check_id="pwd_001",
    name="Domain Password Policy",
    category=CheckCategory.PASSWORD_POLICY,
    description="Evaluates the default domain password policy",
    tags=["password", "policy"],
)
def check_password_policy(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(objectClass=domain)",
        ["minPwdLength", "pwdHistoryLength", "lockoutThreshold",
         "lockoutDuration", "maxPwdAge", "minPwdAge", "pwdProperties"],
        search_base=ctx.domain_dn,
    )
    if not results:
        return findings
    pol = results[0]

    # min length
    ml = int(pol.get("minPwdLength") or 0)
    if ml < 8:
        findings.append(Finding(
            title=f"Weak Minimum Password Length ({ml} chars)",
            description=f"Minimum is {ml}; 14+ recommended.",
            severity=Severity.HIGH,
            category=CheckCategory.PASSWORD_POLICY,
            check_id="pwd_001",
            details={"minPwdLength": ml},
            remediation=Remediation(
                "Increase to at least 14 characters",
                gpo_path="Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
            ),
        ))
    elif ml < 14:
        findings.append(Finding(
            title=f"Moderate Password Length ({ml} chars)",
            description=f"Minimum is {ml}; consider 14+.",
            severity=Severity.MEDIUM,
            category=CheckCategory.PASSWORD_POLICY,
            check_id="pwd_001",
            details={"minPwdLength": ml},
            remediation=Remediation("Increase to 14+ characters"),
        ))

    # history
    hist = int(pol.get("pwdHistoryLength") or 0)
    if hist < 10:
        findings.append(Finding(
            title=f"Weak Password History ({hist} remembered)",
            description="Low history allows password cycling.",
            severity=Severity.MEDIUM,
            category=CheckCategory.PASSWORD_POLICY,
            check_id="pwd_001",
            details={"pwdHistoryLength": hist},
            remediation=Remediation("Set history to 24+"),
        ))

    # lockout
    lockout = int(pol.get("lockoutThreshold") or 0)
    if lockout == 0:
        findings.append(Finding(
            title="No Account Lockout Policy",
            description="Unlimited password guessing with no lockout.",
            severity=Severity.CRITICAL,
            category=CheckCategory.PASSWORD_POLICY,
            check_id="pwd_001",
            mitre=MitreAttack(
                "T1110.001", "Password Guessing", "Credential Access",
                known_tools=("Spray", "Hydra", "CrackMapExec"),
            ),
            remediation=Remediation(
                "Set lockout threshold to 5-10 attempts",
                gpo_path="Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy",
            ),
        ))

    # complexity
    props = int(pol.get("pwdProperties") or 0)
    if not (props & 1):  # DOMAIN_PASSWORD_COMPLEX
        findings.append(Finding(
            title="Password Complexity Disabled",
            description="Complexity requirements are not enforced.",
            severity=Severity.HIGH,
            category=CheckCategory.PASSWORD_POLICY,
            check_id="pwd_001",
            remediation=Remediation("Enable password complexity requirements"),
        ))

    return findings


# ── pwd_002: fine-grained password policies ──────────────────────────────────


@register_check(
    check_id="pwd_002",
    name="Fine-Grained Password Policies",
    category=CheckCategory.PASSWORD_POLICY,
    description="Detects weak fine-grained password policies (PSOs)",
    tags=["password", "policy"],
)
def check_fine_grained_policies(ctx) -> list[Finding]:
    findings: list[Finding] = []
    results = ctx.ldap.search(
        "(objectClass=msDS-PasswordSettings)",
        ["cn", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
         "msDS-PSOAppliesTo", "msDS-PasswordHistoryLength"],
        search_base=ctx.domain_dn,
    )
    for pso in results:
        name = pso.get("cn", "Unknown PSO")
        min_len = int(pso.get("msDS-MinimumPasswordLength") or 0)
        lockout = int(pso.get("msDS-LockoutThreshold") or 0)
        applies_to = pso.get("msDS-PSOAppliesTo") or []
        if isinstance(applies_to, str):
            applies_to = [applies_to]

        if min_len < 8:
            findings.append(Finding(
                title=f"Weak PSO: {name} (min length {min_len})",
                description=f"Fine-grained policy '{name}' allows {min_len}-char passwords applied to {len(applies_to)} object(s).",
                severity=Severity.HIGH,
                category=CheckCategory.PASSWORD_POLICY,
                check_id="pwd_002",
                affected_objects=applies_to[:10],
                details={"pso_name": name, "min_length": min_len},
                remediation=Remediation(f"Increase min length on PSO '{name}' to 14+"),
            ))
        if lockout == 0:
            findings.append(Finding(
                title=f"PSO Without Lockout: {name}",
                description=f"Fine-grained policy '{name}' has no lockout threshold.",
                severity=Severity.HIGH,
                category=CheckCategory.PASSWORD_POLICY,
                check_id="pwd_002",
                affected_objects=applies_to[:10],
                remediation=Remediation(f"Set lockout threshold on PSO '{name}'"),
            ))
    return findings

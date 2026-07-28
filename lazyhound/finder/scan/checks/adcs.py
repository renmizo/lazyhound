"""AD Certificate Services (ADCS) checks: vulnerable templates, enrollment."""

from __future__ import annotations

import logging

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity
from lazyhound.finder.finder_utils import resolve_ip

_adcs_logger = logging.getLogger(__name__)

# Key PKIENROLLMENT flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
CT_FLAG_NO_SECURITY_EXTENSION = 0x80000
# EKU OIDs
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
ANY_PURPOSE = "2.5.29.37.0"
SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

DANGEROUS_EKUS = {CLIENT_AUTH, ANY_PURPOSE, SMART_CARD_LOGON, ""}

# CA interface flags
IF_ENFORCEENCRYPTICERTREQUEST = 0x200


def _attr_list(obj: dict, key: str) -> list[str]:
    """Return a possibly-multivalued LDAP attribute as a list, always.

    Guards the three ways the raw attribute arrives: absent, present-but-None
    (LDAP can hand back a null value — and ``dict.get(key, [])`` returns that
    None rather than the default, which then breaks ``x in v`` / ``for x in v``
    with "argument of type 'NoneType' is not iterable"), or a single bare
    string. Used for EKUs, certificate policies, altSecurityIdentities, etc.
    """
    v = obj.get(key) or []
    if isinstance(v, str):
        v = [v]
    return v


# ── adcs_001: vulnerable certificate templates (ESC1-like) ──────────────────


@register_check(
    check_id="adcs_001",
    name="Vulnerable Certificate Templates (ESC1)",
    category=CheckCategory.ADCS,
    description="Templates allowing enrollee-supplied SANs with client auth EKU",
    tags=["privilege_escalation", "adcs"],
)
def check_esc1_templates(ctx) -> list[Finding]:
    findings: list[Finding] = []
    templates = ctx.get_certificate_templates()

    vulnerable = []
    for tpl in templates:
        # ESC1 requires CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        name_flag = int(tpl.get("msPKI-Certificate-Name-Flag", 0) or 0)
        if not (name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT):
            continue
        name = tpl.get("displayName") or tpl.get("cn", "?")
        ekus = _attr_list(tpl, "pKIExtendedKeyUsage")
        ra_sig = int(tpl.get("msPKI-RA-Signature", 0) or 0)

        # ESC1: enrollee supplies SAN + client auth EKU + no manager approval
        has_dangerous_eku = not ekus or any(e in DANGEROUS_EKUS for e in ekus)
        if has_dangerous_eku and ra_sig == 0:
            vulnerable.append(name)

    if not vulnerable:
        return findings

    findings.append(Finding(
        title=f"ESC1: {len(vulnerable)} Vulnerable Certificate Template(s)",
        description=(
            "Templates allow enrollees to specify a Subject Alternative Name (SAN) "
            "with a client authentication EKU and no manager approval.  An attacker "
            "can request a certificate as any user, including Domain Admin."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.ADCS,
        check_id="adcs_001",
        affected_objects=vulnerable,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certify", "Certipy", "ForgeCert"),
        ),
        remediation=Remediation(
            "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or require manager approval",
            reference_url="https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            effort="medium",
        ),
    ))
    return findings


# ── adcs_002: enrollment agent templates (ESC3-like) ─────────────────────────


@register_check(
    check_id="adcs_002",
    name="Enrollment Agent Templates (ESC3)",
    category=CheckCategory.ADCS,
    description="Templates that grant enrollment agent rights to low-privilege users",
    tags=["privilege_escalation", "adcs"],
)
def check_esc3_templates(ctx) -> list[Finding]:
    templates = ctx.get_certificate_templates()

    names = []
    for tpl in templates:
        ekus = _attr_list(tpl, "pKIExtendedKeyUsage")
        if CERTIFICATE_REQUEST_AGENT in ekus:
            names.append(tpl.get("displayName") or tpl.get("cn", "?"))
    if not names:
        return []
    return [Finding(
        title=f"ESC3: {len(names)} Enrollment Agent Template(s)",
        description=(
            "Templates with the Certificate Request Agent EKU allow enrolling "
            "certificates on behalf of other users."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.ADCS,
        check_id="adcs_002",
        affected_objects=names,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certify", "Certipy"),
        ),
        remediation=Remediation(
            "Restrict enrollment agent templates to specific authorized users",
            effort="medium",
        ),
    )]


# ── adcs_003: ADCS web enrollment (ESC8) ────────────────────────────────────


@register_check(
    check_id="adcs_003",
    name="ADCS Web Enrollment (ESC8)",
    category=CheckCategory.ADCS,
    description="Checks for HTTP-based certificate enrollment endpoints (NTLM relay target)",
    tags=["privilege_escalation", "adcs", "ntlm_relay"],
)
def check_web_enrollment(ctx) -> list[Finding]:
    import urllib.request
    import urllib.error

    # Stealth: skip HTTP probing when adcs_http_probe is disabled
    if hasattr(ctx, "stealth") and not ctx.stealth.adcs_http_probe:
        _adcs_logger.info("Skipping ADCS HTTP enrollment probe (stealth.adcs_http_probe=False)")
        return []

    enrollment_services = ctx.get_enrollment_services()
    if not enrollment_services:
        return []

    http_reachable: list[str] = []
    http_unreachable: list[str] = []
    for es in enrollment_services:
        host = es.get("dNSHostName") or es.get("cn", "?")
        # Probe HTTP certsrv endpoint
        resolved = resolve_ip(host, _adcs_logger)
        url = f"http://{host}/certsrv/"
        _adcs_logger.info("ADCS web enrollment probe connecting to %s [%s]:80", host, resolved)
        try:
            req = urllib.request.Request(url, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=5)
            http_reachable.append(host)
        except urllib.error.HTTPError:
            # Any HTTP response (401, 403, etc.) means the endpoint is up
            http_reachable.append(host)
        except Exception:
            http_unreachable.append(host)

    findings: list[Finding] = []
    if http_reachable:
        findings.append(Finding(
            title=f"ESC8: HTTP Web Enrollment Active on {len(http_reachable)} CA(s)",
            description=(
                "Enterprise CA web enrollment (certsrv) is accessible over HTTP, "
                "making it vulnerable to NTLM relay attacks (ESC8/PetitPotam). "
                "An attacker can coerce a DC to authenticate and relay to the "
                "HTTP endpoint to obtain a certificate as the DC."
            ),
            severity=Severity.CRITICAL,
            category=CheckCategory.ADCS,
            check_id="adcs_003",
            affected_objects=http_reachable,
            mitre=MitreAttack(
                "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay",
                "Credential Access",
                known_tools=("ntlmrelayx", "PetitPotam", "Certipy"),
            ),
            remediation=Remediation(
                "Disable HTTP enrollment or enforce EPA (Extended Protection for Authentication)",
                reference_url="https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429",
            ),
        ))
    if http_unreachable:
        findings.append(Finding(
            title=f"ADCS Enrollment Service(s) Detected ({len(http_unreachable)})",
            description=(
                "Enterprise CA enrollment services detected. HTTP web enrollment "
                "probe could not connect — verify manually whether certsrv is "
                "enabled over HTTP."
            ),
            severity=Severity.MEDIUM,
            category=CheckCategory.ADCS,
            check_id="adcs_003",
            affected_objects=http_unreachable,
            details={"note": "HTTP probe failed — manual verification needed"},
            mitre=MitreAttack(
                "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay",
                "Credential Access",
                known_tools=("ntlmrelayx", "PetitPotam", "Certipy"),
            ),
            remediation=Remediation(
                "Disable HTTP enrollment or enforce EPA (Extended Protection for Authentication)",
                reference_url="https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429",
            ),
        ))
    return findings


# ── adcs_004: ESC4/ESC5/ESC7 — DACL-based certificate abuse ────────────────

# Well-known Certificate Services rights
MANAGE_CA = 0x1
MANAGE_CERTIFICATES = 0x2

# Enrollment OIDs
CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# ManageCA and ManageCertificates extended-right GUIDs
GUID_MANAGE_CA = "7726b9d5-a4b4-4288-a6b2-100714a0ed0a"
GUID_MANAGE_CERTIFICATES = "0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
# Note: ManageCA/ManageCertificates are CA-specific permissions checked via
# the CA's DACL, not standard AD extended-right GUIDs. For ESC7 we check
# for DS_CONTROL_ACCESS with no object_type (all extended rights) or with
# enrollment/auto-enrollment GUIDs on CA objects.


@register_check(
    check_id="adcs_004",
    name="Certificate Template and CA ACL Audit (ESC4/5/7)",
    category=CheckCategory.ADCS,
    description="Parses DACLs on certificate templates and CA objects for dangerous permissions",
    tags=["privilege_escalation", "adcs"],
)
def check_esc4_esc5_esc7(ctx) -> list[Finding]:
    from lazyhound.finder.parsers import (
        has_dangerous_access, is_admin_sid, is_low_privilege_sid,
        parse_security_descriptor,
    )

    findings: list[Finding] = []

    mitre = MitreAttack(
        "T1649", "Steal or Forge Authentication Certificates",
        "Credential Access",
        known_tools=("Certify", "Certipy", "ForgeCert"),
    )

    # ── ESC4: low-priv write access to certificate templates ──
    templates = ctx.get_certificate_templates()
    esc4_templates: list[str] = []
    for tpl in templates:
        name = tpl.get("displayName") or tpl.get("cn", "?")
        sd_raw = tpl.get("nTSecurityDescriptor")
        if not isinstance(sd_raw, bytes):
            continue
        sd = parse_security_descriptor(sd_raw)
        if not sd:
            continue
        for ace in sd.dacl:
            if has_dangerous_access(ace) and is_low_privilege_sid(ace.sid, ctx.domain_sid):
                esc4_templates.append(f"{name} (SID: {ace.sid})")
                break

    if esc4_templates:
        findings.append(Finding(
            title=f"ESC4: {len(esc4_templates)} Template(s) with Low-Priv Write Access",
            description=(
                "Low-privilege principals have write access to certificate templates. "
                "An attacker can modify the template to enable ESC1 conditions "
                "(enrollee supplies SAN + client auth EKU) and then enroll as any user."
            ),
            severity=Severity.CRITICAL,
            category=CheckCategory.ADCS,
            check_id="adcs_004",
            affected_objects=esc4_templates,
            mitre=mitre,
            remediation=Remediation(
                "Remove write permissions for low-privilege groups on certificate templates",
                reference_url="https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                effort="medium",
            ),
        ))

    # ── ESC5: write access to CA configuration objects ──
    ca_objects = ctx.get_enrollment_services()
    esc5_cas: list[str] = []
    for ca in ca_objects:
        name = ca.get("dNSHostName") or ca.get("cn", "?")
        sd_raw = ca.get("nTSecurityDescriptor")
        if not isinstance(sd_raw, bytes):
            continue
        sd = parse_security_descriptor(sd_raw)
        if not sd:
            continue
        for ace in sd.dacl:
            if has_dangerous_access(ace) and is_low_privilege_sid(ace.sid, ctx.domain_sid):
                esc5_cas.append(f"{name} (SID: {ace.sid})")
                break

    if esc5_cas:
        findings.append(Finding(
            title=f"ESC5: {len(esc5_cas)} CA(s) with Low-Priv Write Access",
            description=(
                "Low-privilege principals have write access to CA enrollment service objects. "
                "This may allow modification of CA configuration to enable certificate abuse."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.ADCS,
            check_id="adcs_004",
            affected_objects=esc5_cas,
            mitre=mitre,
            remediation=Remediation(
                "Remove write permissions for low-privilege groups on CA objects",
                effort="medium",
            ),
        ))

    # ── ESC7: ManageCA / ManageCertificates rights ──
    # CA DACLs use DS_CONTROL_ACCESS for ManageCA/ManageCertificates.
    # We flag ACEs that grant all extended rights (no object_type) or
    # specifically the enrollment GUIDs, to non-admin principals.
    _esc7_safe_guids = {
        CERTIFICATE_ENROLLMENT.lower(),
        CERTIFICATE_AUTOENROLLMENT.lower(),
    }
    esc7_cas: list[str] = []
    for ca in ca_objects:
        name = ca.get("dNSHostName") or ca.get("cn", "?")
        sd_raw = ca.get("nTSecurityDescriptor")
        if not isinstance(sd_raw, bytes):
            continue
        sd = parse_security_descriptor(sd_raw)
        if not sd:
            continue
        for ace in sd.dacl:
            if ace.sid and not is_admin_sid(ace.sid, ctx.domain_sid):
                # Check for DS_CONTROL_ACCESS extended rights
                if ace.access_mask & 0x00000100:
                    obj_type = ace.object_type.lower() if ace.object_type else ""
                    # Skip safe enrollment GUIDs — only flag broad/management rights
                    if obj_type and obj_type in _esc7_safe_guids:
                        continue
                    if is_low_privilege_sid(ace.sid, ctx.domain_sid):
                        esc7_cas.append(f"{name} (SID: {ace.sid})")
                        break

    if esc7_cas:
        findings.append(Finding(
            title=f"ESC7: {len(esc7_cas)} CA(s) with Low-Priv Management Rights",
            description=(
                "Low-privilege principals have ManageCA or ManageCertificates extended "
                "rights on CA objects.  ManageCA allows adding new officers; "
                "ManageCertificates allows approving pending requests."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.ADCS,
            check_id="adcs_004",
            affected_objects=esc7_cas,
            mitre=mitre,
            remediation=Remediation(
                "Restrict ManageCA and ManageCertificates to authorized CA administrators only",
                reference_url="https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            ),
        ))

    return findings


# ── adcs_005: ESC2 — Any Purpose / SubCA templates ─────────────────────────


@register_check(
    check_id="adcs_005",
    name="Any Purpose / SubCA Certificate Templates (ESC2)",
    category=CheckCategory.ADCS,
    description="Templates with Any Purpose EKU or no EKU (subordinate CA capable)",
    tags=["privilege_escalation", "adcs"],
)
def check_esc2_templates(ctx) -> list[Finding]:
    """Detect templates with overly broad EKU: Any Purpose or no EKU at all.

    ESC2 differs from ESC1 in that it does NOT require enrollee-supplied SANs.
    The risk is that certificates can be used for client auth (Any Purpose) or
    as a subordinate CA (no EKU) regardless of original template intent.
    """
    templates = ctx.get_certificate_templates()

    vulnerable: list[str] = []
    for tpl in templates:
        name = tpl.get("displayName") or tpl.get("cn", "?")
        ekus = _attr_list(tpl, "pKIExtendedKeyUsage")
        ra_sig = int(tpl.get("msPKI-RA-Signature", 0) or 0)
        if ra_sig > 0:
            continue

        # Skip templates already caught by ESC1 (enrollee supplies subject)
        name_flag = int(tpl.get("msPKI-Certificate-Name-Flag", 0) or 0)
        if name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT:
            continue

        # Skip enrollment agent templates (caught by ESC3)
        if CERTIFICATE_REQUEST_AGENT in ekus:
            continue

        if ANY_PURPOSE in ekus or not ekus:
            vulnerable.append(name)

    if not vulnerable:
        return []

    return [Finding(
        title=f"ESC2: {len(vulnerable)} Any Purpose/SubCA Template(s)",
        description=(
            "Templates with the Any Purpose EKU or no EKU restrictions allow issued "
            "certificates to be used for client authentication, code signing, or as "
            "a subordinate CA. An attacker who can enroll can abuse these for "
            "privilege escalation."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.ADCS,
        check_id="adcs_005",
        affected_objects=vulnerable,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certify", "Certipy"),
        ),
        remediation=Remediation(
            "Restrict templates to specific EKUs (e.g., only Server Authentication) "
            "and require manager approval for sensitive templates",
            reference_url="https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            effort="medium",
        ),
    )]


# ── adcs_006: ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 advisory ──────────────


@register_check(
    check_id="adcs_006",
    name="EDITF_ATTRIBUTESUBJECTALTNAME2 Advisory (ESC6)",
    category=CheckCategory.ADCS,
    description="Flags CAs for manual EDITF_ATTRIBUTESUBJECTALTNAME2 verification",
    tags=["privilege_escalation", "adcs"],
)
def check_esc6_editf_flag(ctx) -> list[Finding]:
    """Flag CAs that may have EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.

    This CA policy flag allows ANY certificate request to include an arbitrary
    SAN, bypassing template restrictions entirely.  The flag is stored in the
    CA registry and cannot be read via LDAP, so this check identifies CAs and
    recommends manual verification.
    """
    cas = ctx.get_enrollment_services()
    if not cas:
        return []

    ca_names = [ca.get("dNSHostName") or ca.get("cn", "?") for ca in cas]
    return [Finding(
        title=f"ESC6 Advisory: {len(ca_names)} CA(s) Require EDITF_ATTRIBUTESUBJECTALTNAME2 Review",
        description=(
            "When EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled on a CA policy module, "
            "any certificate request can include an arbitrary Subject Alternative Name "
            "regardless of template configuration. This effectively makes every template "
            "vulnerable to ESC1-style impersonation. This flag is stored in the CA "
            "registry and must be verified manually."
        ),
        severity=Severity.INFO,
        category=CheckCategory.ADCS,
        check_id="adcs_006",
        affected_objects=ca_names,
        details={"note": "Run 'certutil -getreg policy\\EditFlags' on each CA to verify"},
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certify", "Certipy"),
        ),
        remediation=Remediation(
            "Disable EDITF_ATTRIBUTESUBJECTALTNAME2: "
            "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
            powershell="certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
            reference_url="https://support.microsoft.com/en-us/topic/kb5014754",
            effort="low",
        ),
    )]


# ── adcs_007: ESC9 — No Security Extension on templates ───────────────────


@register_check(
    check_id="adcs_007",
    name="No Security Extension in Certificate Templates (ESC9)",
    category=CheckCategory.ADCS,
    description="Templates with CT_FLAG_NO_SECURITY_EXTENSION bypass strong certificate mapping",
    tags=["privilege_escalation", "adcs"],
)
def check_esc9_no_security_extension(ctx) -> list[Finding]:
    """Detect templates with CT_FLAG_NO_SECURITY_EXTENSION (0x80000).

    When set in msPKI-Enrollment-Flag, the szOID_NTDS_CA_SECURITY_EXT extension
    is omitted from issued certificates.  This extension embeds the requester's
    SID for strong certificate mapping (KB5014754).  Without it, an attacker can
    bypass certificate binding enforcement and impersonate other principals.
    """
    templates = ctx.get_certificate_templates()

    names = []
    for tpl in templates:
        enrollment_flag = int(tpl.get("msPKI-Enrollment-Flag", 0) or 0)
        if enrollment_flag & CT_FLAG_NO_SECURITY_EXTENSION:
            names.append(tpl.get("displayName") or tpl.get("cn", "?"))
    if not names:
        return []
    return [Finding(
        title=f"ESC9: {len(names)} Template(s) Without Security Extension",
        description=(
            "Templates with CT_FLAG_NO_SECURITY_EXTENSION (0x80000) omit the "
            "szOID_NTDS_CA_SECURITY_EXT extension from issued certificates. This "
            "extension embeds the requester's SID for strong certificate mapping. "
            "Without it, an attacker may bypass KB5014754 enforcement and "
            "impersonate other users via certificate-based authentication."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.ADCS,
        check_id="adcs_007",
        affected_objects=names,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certipy",),
        ),
        remediation=Remediation(
            "Remove the CT_FLAG_NO_SECURITY_EXTENSION flag from the template's "
            "msPKI-Enrollment-Flag attribute and enable Full Enforcement mode "
            "(StrongCertificateBindingEnforcement=2) on domain controllers",
            reference_url="https://support.microsoft.com/en-us/topic/kb5014754",
            effort="medium",
        ),
    )]


# ── adcs_008: ESC11 — Unencrypted RPC certificate enrollment ──────────────


@register_check(
    check_id="adcs_008",
    name="Unencrypted RPC Certificate Enrollment (ESC11)",
    category=CheckCategory.ADCS,
    description="CAs without IF_ENFORCEENCRYPTICERTREQUEST allow NTLM relay via RPC",
    tags=["privilege_escalation", "adcs", "ntlm_relay"],
)
def check_esc11_rpc_encryption(ctx) -> list[Finding]:
    """Detect CAs that may lack IF_ENFORCEENCRYPTICERTREQUEST (0x200).

    The CA interface flags (including IF_ENFORCEENCRYPTICERTREQUEST) are stored
    in the CA's local registry, not in LDAP. This check can only flag CAs as
    *potentially* vulnerable — manual verification via ``certutil -getreg
    CA\\InterfaceFlags`` on the CA server is required to confirm.
    """
    cas = ctx.get_enrollment_services()
    if not cas:
        return []

    # The LDAP 'flags' attribute on pKIEnrollmentService is NOT the CA
    # interface flags — those live in the CA's local registry and are not
    # exposed via LDAP.  We flag all CAs as needing manual review.
    ca_names: list[str] = []
    for ca in cas:
        name = ca.get("dNSHostName") or ca.get("cn", "?")
        ca_names.append(name)

    if not ca_names:
        return []

    return [Finding(
        title=f"ESC11: {len(ca_names)} CA(s) Require Manual RPC Encryption Check",
        description=(
            "CA interface flags (IF_ENFORCEENCRYPTICERTREQUEST) are stored in "
            "the CA's local registry and cannot be verified via LDAP. Run "
            "'certutil -getreg CA\\InterfaceFlags' on each CA server to check "
            "whether encrypted RPC enrollment is enforced. Without this flag, "
            "an attacker can relay NTLM authentication to the CA's ICPR "
            "interface to enroll certificates."
        ),
        severity=Severity.INFO,
        category=CheckCategory.ADCS,
        check_id="adcs_008",
        affected_objects=ca_names,
        mitre=MitreAttack(
            "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay",
            "Credential Access",
            known_tools=("Certipy", "ntlmrelayx", "Coercer"),
        ),
        remediation=Remediation(
            "Enable IF_ENFORCEENCRYPTICERTREQUEST on each CA: "
            "certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
            powershell="certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
            reference_url="https://support.microsoft.com/en-us/topic/kb5005413",
            effort="low",
        ),
    )]


# ── adcs_009: ESC13 — Group-linked issuance policies ──────────────────────


@register_check(
    check_id="adcs_009",
    name="Group-Linked Issuance Policies (ESC13)",
    category=CheckCategory.ADCS,
    description="Templates referencing OID objects with msDS-OIDToGroupLink enable group membership via enrollment",
    tags=["privilege_escalation", "adcs"],
)
def check_esc13_group_linked_oid(ctx) -> list[Finding]:
    """Detect certificate templates whose issuance policy OID links to an AD group.

    When a template's msPKI-Certificate-Policy references an OID object that has
    msDS-OIDToGroupLink set, enrolling in that template effectively grants the
    certificate holder membership in the linked group.  If the linked group is
    privileged, this is a direct escalation path.
    """
    config_dn = ctx.configuration_dn

    # Step 1: Find OID objects with group links
    oid_objects = ctx.ldap.search(
        "(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))",
        ["cn", "displayName", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
        search_base=config_dn,
    )
    if not oid_objects:
        return []

    # Build map: OID value -> linked group DN
    oid_to_group: dict[str, str] = {}
    for obj in oid_objects:
        oid_value = obj.get("msPKI-Cert-Template-OID", "")
        group_link = obj.get("msDS-OIDToGroupLink", "")
        if oid_value and group_link:
            oid_to_group[oid_value] = group_link

    if not oid_to_group:
        return []

    # Step 2: Find templates referencing those OIDs
    templates = ctx.get_certificate_templates()

    vulnerable: list[str] = []
    for tpl in templates:
        name = tpl.get("displayName") or tpl.get("cn", "?")
        policies = _attr_list(tpl, "msPKI-Certificate-Policy")
        for policy_oid in policies:
            if policy_oid in oid_to_group:
                group_dn = oid_to_group[policy_oid]
                vulnerable.append(f"{name} -> {group_dn}")
                break

    if not vulnerable:
        return []

    return [Finding(
        title=f"ESC13: {len(vulnerable)} Template(s) with Group-Linked Issuance Policy",
        description=(
            "Certificate templates reference issuance policy OIDs with "
            "msDS-OIDToGroupLink set. Enrolling in these templates effectively "
            "grants membership in the linked AD group. If the linked group is "
            "privileged, any user who can enroll gains elevated access."
        ),
        severity=Severity.HIGH,
        category=CheckCategory.ADCS,
        check_id="adcs_009",
        affected_objects=vulnerable,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certipy", "Certify"),
        ),
        remediation=Remediation(
            "Remove msDS-OIDToGroupLink from OID objects or restrict enrollment "
            "on affected templates to authorized users only",
            effort="medium",
        ),
    )]


# ── adcs_010: ESC14 — Weak explicit certificate mappings ──────────────────


# Weak mapping prefixes that rely on issuer/subject rather than key hash
_WEAK_MAPPING_PREFIXES = ("X509:<I>", "X509:<S>")
# Strong prefixes that should NOT be flagged even though they start with X509:<S>
_STRONG_MAPPING_PREFIXES = ("X509:<SKI>", "X509:<SHA1-PUKEY>", "X509:<RFC822>")


@register_check(
    check_id="adcs_010",
    name="Weak Explicit Certificate Mappings (ESC14)",
    category=CheckCategory.ADCS,
    description="Accounts with altSecurityIdentities using weak certificate mapping patterns",
    tags=["privilege_escalation", "adcs"],
)
def check_esc14_weak_cert_mapping(ctx) -> list[Finding]:
    """Detect accounts with weak explicit certificate-to-account mappings.

    The altSecurityIdentities attribute can map certificates to accounts.
    Weak patterns like X509:<I><S> (issuer+subject) or X509:<S> (subject only)
    can be forged by an attacker who obtains a certificate from the same CA
    with a matching subject, enabling impersonation.
    """
    results = ctx.ldap.search(
        "(&(objectClass=user)(altSecurityIdentities=*))",
        ["sAMAccountName", "altSecurityIdentities", "adminCount"],
    )
    if not results:
        return []

    weak: list[str] = []
    admin_affected = False
    for obj in results:
        name = obj.get("sAMAccountName", "?")
        identities = _attr_list(obj, "altSecurityIdentities")
        for identity in identities:
            id_upper = identity.upper()
            if (any(id_upper.startswith(p) for p in _WEAK_MAPPING_PREFIXES)
                    and not any(id_upper.startswith(p) for p in _STRONG_MAPPING_PREFIXES)):
                weak.append(name)
                if str(obj.get("adminCount", "0")) == "1":
                    admin_affected = True
                break

    if not weak:
        return []

    severity = Severity.CRITICAL if admin_affected else Severity.HIGH
    return [Finding(
        title=f"ESC14: {len(weak)} Account(s) with Weak Certificate Mapping",
        description=(
            "Accounts use altSecurityIdentities with weak explicit certificate "
            "mappings (X509:<I><S> or X509:<S>). These mappings rely on the "
            "certificate's issuer and subject fields, which an attacker can "
            "replicate by enrolling a certificate with a matching subject from "
            "the same CA. Strong mappings (SHA1 hash, SKI) should be used instead."
        ),
        severity=severity,
        category=CheckCategory.ADCS,
        check_id="adcs_010",
        affected_objects=weak,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certipy",),
        ),
        remediation=Remediation(
            "Replace weak certificate mappings with strong mappings using "
            "X509:<SHA1-PUKEY> or X509:<SKI> patterns. Enable "
            "StrongCertificateBindingEnforcement=2 on domain controllers",
            reference_url="https://support.microsoft.com/en-us/topic/kb5014754",
            effort="medium",
        ),
    )]


# ── adcs_011: ESC15 — Schema V1 template application policy abuse ─────────


@register_check(
    check_id="adcs_011",
    name="Schema V1 Certificate Templates (ESC15)",
    category=CheckCategory.ADCS,
    description="Schema V1 templates allow application policy abuse (EKUwu)",
    tags=["privilege_escalation", "adcs"],
)
def check_esc15_schema_v1(ctx) -> list[Finding]:
    """Detect Schema Version 1 certificate templates vulnerable to EKUwu.

    Schema V1 templates (msPKI-Template-Schema-Version=1) have a flaw where
    the application policies in the certificate request are processed differently
    than in V2+ templates.  An attacker can craft a CSR that adds arbitrary EKUs
    (e.g., Client Authentication) to the issued certificate, regardless of the
    template's intended EKU restrictions.
    """
    templates = ctx.get_certificate_templates()

    names = []
    for tpl in templates:
        version = str(tpl.get("msPKI-Template-Schema-Version", ""))
        if version == "1":
            names.append(tpl.get("displayName") or tpl.get("cn", "?"))
    if not names:
        return []
    return [Finding(
        title=f"ESC15: {len(names)} Schema V1 Template(s)",
        description=(
            "Schema Version 1 certificate templates do not properly enforce EKU "
            "restrictions from the template configuration. An attacker can craft "
            "a certificate signing request that injects arbitrary application "
            "policies (EKUs) such as Client Authentication into the issued "
            "certificate, bypassing the template's intended restrictions."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.ADCS,
        check_id="adcs_011",
        affected_objects=names,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certipy",),
        ),
        remediation=Remediation(
            "Upgrade Schema V1 templates to Schema V2 or later by duplicating "
            "them and incrementing msPKI-Template-Schema-Version. Restrict "
            "enrollment permissions on V1 templates that cannot be upgraded",
            effort="medium",
        ),
    )]


# ── adcs_012: excessively long certificate validity ──────────────────────

import struct


def _parse_pki_period(raw: bytes | str | None) -> int | None:
    """Parse a pKIExpirationPeriod / pKIOverlapPeriod value to days.

    These are stored as negative FILETIME intervals (100-ns units).
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            raw = bytes.fromhex(raw)
        except ValueError:
            return None
    if len(raw) != 8:
        return None
    ticks = struct.unpack("<q", raw)[0]
    if ticks >= 0:
        return None
    # Convert negative 100-ns intervals to positive days
    return int(-ticks / (10_000_000 * 86400))


@register_check(
    check_id="adcs_012",
    name="Excessively Long Certificate Validity",
    category=CheckCategory.ADCS,
    description="Certificate templates with validity periods longer than 2 years",
    tags=["adcs", "hygiene"],
)
def check_long_cert_validity(ctx) -> list[Finding]:
    config_dn = ctx.configuration_dn
    # Fetch templates with expiration period
    templates = ctx.ldap.search(
        "(objectClass=pKICertificateTemplate)",
        ["cn", "displayName", "pKIExpirationPeriod"],
        search_base=config_dn,
    )
    if not templates:
        return []

    long_validity: list[str] = []
    for tpl in templates:
        name = tpl.get("displayName") or tpl.get("cn", "?")
        days = _parse_pki_period(tpl.get("pKIExpirationPeriod"))
        if days is not None and days > 730:
            long_validity.append(f"{name} ({days} days)")

    if not long_validity:
        return []
    return [Finding(
        title=f"Certificate Templates with Long Validity ({len(long_validity)})",
        description=(
            f"{len(long_validity)} template(s) issue certificates valid for more than 2 years. "
            "Long-lived certificates persist beyond typical credential rotation cycles, "
            "meaning a compromised certificate remains usable long after the underlying "
            "account password has been changed."
        ),
        severity=Severity.MEDIUM,
        category=CheckCategory.ADCS,
        check_id="adcs_012",
        affected_objects=long_validity,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certipy", "Certify"),
        ),
        remediation=Remediation(
            "Reduce certificate validity period to 1-2 years maximum; "
            "enable short-lived certificates with auto-enrollment where possible",
            effort="medium",
        ),
    )]


# ── adcs_013: CRL distribution point availability ───────────────────────


@register_check(
    check_id="adcs_013",
    name="CA CRL Distribution Advisory",
    category=CheckCategory.ADCS,
    description="Advisory to verify CRL distribution points are configured and accessible",
    tags=["adcs", "hygiene"],
)
def check_crl_advisory(ctx) -> list[Finding]:
    cas = ctx.get_enrollment_services()
    if not cas:
        return []

    ca_names = [ca.get("dNSHostName") or ca.get("cn", "?") for ca in cas]
    return [Finding(
        title=f"CRL Distribution Advisory ({len(ca_names)} CA(s))",
        description=(
            f"{len(ca_names)} CA(s) detected. Verify that Certificate Revocation List (CRL) "
            "distribution points are configured, accessible, and regularly updated. "
            "Without functioning CRL/OCSP endpoints, revoked certificates remain trusted "
            "and compromised certificates cannot be invalidated."
        ),
        severity=Severity.INFO,
        category=CheckCategory.ADCS,
        check_id="adcs_013",
        affected_objects=ca_names,
        details={
            "note": "Verify CRL accessibility: certutil -verify -urlfetch <cert_file>",
        },
        remediation=Remediation(
            "Ensure CRL distribution points are configured and accessible; "
            "consider adding OCSP responders for real-time revocation checking",
            powershell="certutil -CRL",
            reference_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage/configure-crl-distribution-points",
        ),
    )]


# Default machine/computer-identity templates whose enrollment satisfies the
# CertiGhost precondition (lowercased cn values, as published on the CA).
_CERTIGHOST_TEMPLATES = {
    "machine", "computer", "workstation", "domaincontroller",
    "domaincontrollerauthentication", "kerberosauthentication",
}


@register_check(
    check_id="adcs_014",
    name="CertiGhost Advisory (CVE-2026-54121)",
    category=CheckCategory.ADCS,
    description="Flags AD CS deployments meeting CertiGhost preconditions to verify the July-2026 patch",
    tags=["advisory", "adcs", "privilege_escalation"],
)
def check_certighost_advisory(ctx) -> list[Finding]:
    """CertiGhost (CVE-2026-54121) — advisory, precondition-based.

    The flaw is in the Enterprise CA's enrollment directory-resolution 'chase'
    logic, not a template setting, so patch state isn't visible over LDAP. We
    flag the precondition it needs — an Enterprise CA publishing the default
    machine/computer template — and tell the operator to verify the patch.
    """
    cas = ctx.get_enrollment_services()
    if not cas:
        return []

    # A machine/computer-identity template published for enrollment on any CA.
    published: set[str] = set()
    for ca in cas:
        for t in _attr_list(ca, "certificateTemplates"):
            published.add(str(t).lower())
    machine_templates = sorted(published & _CERTIGHOST_TEMPLATES)
    if not machine_templates:
        return []

    ca_names = [ca.get("dNSHostName") or ca.get("cn", "?") for ca in cas]
    return [Finding(
        title=f"CertiGhost (CVE-2026-54121) — {len(ca_names)} Enterprise CA(s): VERIFY PATCH",
        description=(
            "An Enterprise CA publishes the default machine/computer certificate "
            "template — the precondition for CertiGhost (CVE-2026-54121), an "
            "actively-exploited (public PoC) domain-takeover flaw. A low-privileged "
            "domain account with network access to the CA can abuse an enrollment "
            "directory-resolution 'chase' fallback to make the CA issue a "
            "certificate carrying a Domain Controller's identity, enabling DC "
            "impersonation and full domain takeover, with no admin rights or user "
            "interaction. Scored CRITICAL by impact (domain takeover if unpatched), "
            "not by confirmability. The flaw is in the CA's enrollment logic, not a "
            "template setting, so patch level is NOT visible over LDAP: this scan "
            "cannot confirm exploitability — you MUST verify the July-2026 "
            "cumulative update is installed on every CA host."
        ),
        severity=Severity.CRITICAL,
        category=CheckCategory.ADCS,
        check_id="adcs_014",
        affected_objects=ca_names,
        mitre=MitreAttack(
            "T1649", "Steal or Forge Authentication Certificates",
            "Credential Access",
            known_tools=("Certighost",),
        ),
        details={
            "cve": "CVE-2026-54121",
            "published_machine_templates": machine_templates,
            "note": "Patch state is not visible over LDAP — verify the Jul-2026 "
                    "update on each CA host (this is an advisory, not confirmation).",
        },
        remediation=Remediation(
            "Apply the July-2026 (or later) cumulative update on all AD CS / CA "
            "hosts. Additionally restrict machine-template enrollment where "
            "feasible and enforce strong certificate mapping (KB5014754).",
            reference_url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121",
        ),
    )]

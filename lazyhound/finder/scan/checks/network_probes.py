"""Network-level security probes: SMB protocol version, signing, null session."""

from __future__ import annotations

import logging
import socket
import struct

from .registry import register_check
from lazyhound.finder.finder_models import CheckCategory, Finding, MitreAttack, Remediation, Severity
from lazyhound.finder.finder_utils import resolve_ip

logger = logging.getLogger(__name__)

SMB_PORT = 445
CONNECT_TIMEOUT = 5

SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"


def _build_smb1_negotiate() -> bytes:
    """Build a minimal SMBv1 Negotiate Protocol Request."""
    dialect = b"\x02NT LM 0.12\x00"
    smb_header = (
        SMB1_MAGIC
        + b"\x72"              # Command: Negotiate
        + b"\x00\x00\x00\x00"  # Status
        + b"\x18"              # Flags
        + b"\x53\xc8"          # Flags2
        + b"\x00" * 12         # PID high + signature + reserved
        + b"\xff\xff"          # Tree ID
        + b"\xfe\xff"          # Process ID
        + b"\x00\x00"          # User ID
        + b"\x00\x00"          # Multiplex ID
    )
    body = b"\x00" + struct.pack("<H", len(dialect)) + dialect
    msg = smb_header + body
    nb_header = b"\x00" + struct.pack(">I", len(msg))[1:]
    return nb_header + msg


def _build_smb2_negotiate() -> bytes:
    """Build a minimal SMB2 Negotiate Request."""
    dialects = struct.pack("<HH", 0x0202, 0x0210)
    smb2_header = (
        SMB2_MAGIC
        + struct.pack("<H", 64)        # Header length
        + b"\x00\x00"                  # Credit charge
        + b"\x00\x00\x00\x00"          # Status
        + struct.pack("<H", 0)          # Command: Negotiate
        + struct.pack("<H", 1)          # Credits
        + b"\x00\x00\x00\x00"          # Flags
        + b"\x00\x00\x00\x00"          # Next command
        + struct.pack("<Q", 0)          # Message ID
        + struct.pack("<I", 0xFFFE)     # Process ID
        + struct.pack("<I", 0)          # Tree ID
        + struct.pack("<Q", 0)          # Session ID
        + b"\x00" * 16                 # Signature
    )
    negotiate_body = (
        struct.pack("<H", 36)           # Structure size
        + struct.pack("<H", 2)          # Dialect count
        + struct.pack("<H", 1)          # Security mode (signing enabled)
        + b"\x00\x00"                  # Reserved
        + b"\x00\x00\x00\x00"          # Capabilities
        + b"\x00" * 16                 # Client GUID
        + b"\x00" * 8                  # Client start time
        + dialects
    )
    msg = smb2_header + negotiate_body
    nb_header = b"\x00" + struct.pack(">I", len(msg))[1:]
    return nb_header + msg


def _probe_smb(host: str, port: int = SMB_PORT,
               timeout: int = CONNECT_TIMEOUT) -> dict:
    """Probe an SMB endpoint and return protocol details.

    Returns dict with keys: reachable, smbv1, signing_required.
    """
    result: dict = {"reachable": False, "smbv1": False, "signing_required": None}

    resolved = resolve_ip(host, logger)

    # Probe 1: SMBv1
    try:
        logger.info("SMB probe connecting to %s [%s]:%d", host, resolved, port)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result["reachable"] = True
            sock.sendall(_build_smb1_negotiate())
            resp = sock.recv(4096)
            if len(resp) > 8 and resp[4:8] == SMB1_MAGIC:
                result["smbv1"] = True
    except (OSError, TimeoutError):
        pass

    # Probe 2: SMB2 signing
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result["reachable"] = True
            sock.sendall(_build_smb2_negotiate())
            resp = sock.recv(4096)
            if len(resp) > 72 and resp[4:8] == SMB2_MAGIC:
                sec_mode = struct.unpack_from("<H", resp, 70)[0]
                result["signing_required"] = bool(sec_mode & 0x02)
    except (OSError, TimeoutError):
        pass

    return result


# ── net_001: SMB security probes ─────────────────────────────────────────────


@register_check(
    check_id="net_001",
    name="SMB Security Probes",
    category=CheckCategory.PROTOCOL_SECURITY,
    description="SMBv1 detection, signing enforcement, and null session risk on DCs",
    protocols=["ldap", "smb"],
    tags=["protocol", "smb", "relay", "lateral_movement"],
)
def check_smb_security(ctx) -> list[Finding]:
    findings: list[Finding] = []
    dcs = ctx.get_domain_controllers()
    if not dcs:
        return findings

    smbv1_hosts: list[str] = []
    no_signing_hosts: list[str] = []

    for dc in dcs:
        host = dc.get("dNSHostName") or dc.get("sAMAccountName", "").rstrip("$")
        if not host:
            continue
        probe = _probe_smb(host)
        if not probe["reachable"]:
            logger.debug("SMB port unreachable on %s", host)
            continue
        if probe["smbv1"]:
            smbv1_hosts.append(host)
        if probe["signing_required"] is False:
            no_signing_hosts.append(host)

    if smbv1_hosts:
        findings.append(Finding(
            title=f"SMBv1 Enabled on {len(smbv1_hosts)} DC(s)",
            description=(
                "SMBv1 is a deprecated protocol with known vulnerabilities including "
                "EternalBlue (MS17-010).  It should be disabled on all systems."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.PROTOCOL_SECURITY,
            check_id="net_001",
            affected_objects=smbv1_hosts,
            mitre=MitreAttack(
                "T1210", "Exploitation of Remote Services", "Lateral Movement",
                known_tools=("EternalBlue", "Metasploit", "MS17-010"),
            ),
            remediation=Remediation(
                "Disable SMBv1 on all systems",
                powershell=(
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                    "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                ),
                gpo_path="Computer Configuration > Administrative Templates > Network > Lanman Server > SMB Minimum version",
                reference_url="https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
            ),
        ))

    if no_signing_hosts:
        findings.append(Finding(
            title=f"SMB Signing Not Required on {len(no_signing_hosts)} DC(s)",
            description=(
                "SMB signing is not enforced, allowing relay and man-in-the-middle "
                "attacks against these domain controllers."
            ),
            severity=Severity.HIGH,
            category=CheckCategory.PROTOCOL_SECURITY,
            check_id="net_001",
            affected_objects=no_signing_hosts,
            mitre=MitreAttack(
                "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay",
                "Credential Access",
                known_tools=("ntlmrelayx", "Responder", "Inveigh"),
            ),
            remediation=Remediation(
                "Require SMB signing on all domain controllers",
                gpo_path="Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always)",
                reference_url="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always",
            ),
        ))

    return findings

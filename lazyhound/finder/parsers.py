"""Binary parsers for Windows security descriptors, SIDs, and ACLs.

Lightweight parser used by security checks.  The collector module uses
``lazyhound.security`` which produces richer dataclasses with
``to_dict()`` for JSON serialisation.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

# ── ACE type constants ───────────────────────────────────────────────────────

ACCESS_ALLOWED_ACE = 0x00
ACCESS_DENIED_ACE = 0x01
ACCESS_ALLOWED_OBJECT_ACE = 0x05
ACCESS_DENIED_OBJECT_ACE = 0x06

# ── Access mask constants ────────────────────────────────────────────────────

GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_WRITE_PROP = 0x00000020

DANGEROUS_MASK = GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER | ADS_RIGHT_DS_WRITE_PROP

# ── Well-known SIDs ─────────────────────────────────────────────────────────

LOW_PRIVILEGE_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-7",       # Anonymous Logon
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # Users
})

ADMIN_SIDS = frozenset({
    "S-1-5-18",      # SYSTEM
    "S-1-5-32-544",  # Administrators
    "S-1-5-9",       # Enterprise Domain Controllers
})

# ── Well-known extended-rights GUIDs ────────────────────────────────────────

DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


# ── Data structures ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ACE:
    ace_type: int
    flags: int
    access_mask: int
    sid: str
    object_type: str = ""
    inherited_object_type: str = ""


@dataclass
class SecurityDescriptor:
    owner_sid: str = ""
    group_sid: str = ""
    dacl: list[ACE] = field(default_factory=list)
    sacl: list[ACE] = field(default_factory=list)


# ── Parsing helpers ─────────────────────────────────────────────────────────


def parse_sid(data: bytes, offset: int = 0) -> tuple[str, int]:
    """Parse a Windows SID from binary data.  Returns (sid_string, bytes_consumed)."""
    if offset + 8 > len(data):
        return "", 0
    revision = data[offset]
    sub_count = data[offset + 1]
    auth = int.from_bytes(data[offset + 2 : offset + 8], "big")
    subs: list[int] = []
    pos = offset + 8
    for _ in range(sub_count):
        if pos + 4 > len(data):
            break
        (sub,) = struct.unpack_from("<I", data, pos)
        subs.append(sub)
        pos += 4
    sid_str = f"S-{revision}-{auth}" + "".join(f"-{s}" for s in subs)
    return sid_str, pos - offset


def parse_guid(data: bytes, offset: int = 0) -> str:
    """Parse a 16-byte GUID in Microsoft mixed-endian format."""
    if offset + 16 > len(data):
        return ""
    raw = data[offset : offset + 16]
    return str(uuid.UUID(bytes_le=raw))


def _parse_acl(data: bytes, offset: int) -> list[ACE]:
    """Parse an ACL (access control list) at *offset* in *data*."""
    if offset == 0 or offset + 8 > len(data):
        return []
    _rev, _sbz, _size, count, _sbz2 = struct.unpack_from("<BBHHH", data, offset)
    aces: list[ACE] = []
    pos = offset + 8
    for _ in range(count):
        if pos + 4 > len(data):
            break
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, pos)
        if ace_size < 4 or pos + ace_size > len(data):
            break

        if ace_type in (ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE):
            if pos + 8 <= len(data):
                (mask,) = struct.unpack_from("<I", data, pos + 4)
                sid, _ = parse_sid(data, pos + 8)
                aces.append(ACE(ace_type=ace_type, flags=ace_flags,
                                access_mask=mask, sid=sid))

        elif ace_type in (ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE):
            if pos + 12 <= len(data):
                (mask,) = struct.unpack_from("<I", data, pos + 4)
                (obj_flags,) = struct.unpack_from("<I", data, pos + 8)
                sid_off = pos + 12
                obj_type = ""
                inh_type = ""
                if obj_flags & 0x1:
                    obj_type = parse_guid(data, sid_off)
                    sid_off += 16
                if obj_flags & 0x2:
                    inh_type = parse_guid(data, sid_off)
                    sid_off += 16
                sid, _ = parse_sid(data, sid_off)
                aces.append(ACE(ace_type=ace_type, flags=ace_flags,
                                access_mask=mask, sid=sid,
                                object_type=obj_type,
                                inherited_object_type=inh_type))
        pos += ace_size
    return aces


def parse_security_descriptor(data: bytes) -> SecurityDescriptor | None:
    """Parse a binary Windows SECURITY_DESCRIPTOR (self-relative format)."""
    if not data or len(data) < 20:
        return None
    _rev, _sbz, _ctrl, off_owner, off_group, off_sacl, off_dacl = struct.unpack_from(
        "<BBHIIII", data,
    )
    sd = SecurityDescriptor()
    if off_owner and off_owner < len(data):
        sd.owner_sid, _ = parse_sid(data, off_owner)
    if off_group and off_group < len(data):
        sd.group_sid, _ = parse_sid(data, off_group)
    if off_dacl:
        sd.dacl = _parse_acl(data, off_dacl)
    if off_sacl:
        sd.sacl = _parse_acl(data, off_sacl)
    return sd


# ── Classification helpers ──────────────────────────────────────────────────


def is_low_privilege_sid(sid: str, domain_sid: str = "") -> bool:
    """Return True if *sid* represents a broadly-granted low-privilege principal."""
    if sid in LOW_PRIVILEGE_SIDS:
        return True
    if domain_sid:
        # Domain Users (513), Domain Computers (515)
        if sid in (f"{domain_sid}-513", f"{domain_sid}-515"):
            return True
    return False


def is_admin_sid(sid: str, domain_sid: str = "") -> bool:
    """Return True if *sid* is an expected high-privilege principal."""
    if sid in ADMIN_SIDS:
        return True
    if domain_sid:
        # Domain Admins (512), Enterprise Admins (519), Schema Admins (518)
        if sid in (f"{domain_sid}-512", f"{domain_sid}-519", f"{domain_sid}-518"):
            return True
    return False


def has_dangerous_access(ace: ACE) -> bool:
    """Return True if *ace* grants dangerous write-level access."""
    if ace.ace_type in (ACCESS_DENIED_ACE, ACCESS_DENIED_OBJECT_ACE):
        return False
    return bool(ace.access_mask & DANGEROUS_MASK)

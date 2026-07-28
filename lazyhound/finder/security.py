"""Binary parser for Windows Security Descriptors (SD, ACL, ACE, SID).

Parses the raw nTSecurityDescriptor bytes returned by LDAP into structured
Python objects suitable for attack path analysis.  Used by the collector
for rich JSON serialisation.  Security checks use the lighter
``lazyhound.parsers`` module instead.

References:
    MS-DTYP 2.4.6  - SECURITY_DESCRIPTOR
    MS-DTYP 2.4.4  - ACL
    MS-DTYP 2.4.4.1 - ACE_HEADER / ACE types
    MS-DTYP 2.4.2  - SID
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag


# ---------------------------------------------------------------------------
# Access mask flags (MS-DTYP 2.4.3)
# ---------------------------------------------------------------------------
class AccessMask(IntEnum):
    GENERIC_ALL = 0x10000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000
    WRITE_OWNER = 0x00080000
    WRITE_DAC = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000
    # AD-specific (DS_RIGHT_*)
    DS_CONTROL_ACCESS = 0x00000100
    DS_CREATE_CHILD = 0x00000001
    DS_DELETE_CHILD = 0x00000002
    DS_LIST_CONTENTS = 0x00000004
    DS_SELF = 0x00000008  # ADS_RIGHT_DS_SELF (validated writes)
    DS_READ_PROPERTY = 0x00000010
    DS_WRITE_PROPERTY = 0x00000020
    DS_DELETE_TREE = 0x00000040
    DS_LIST_OBJECT = 0x00000080


# Friendly labels for attack-relevant rights
RIGHT_LABELS = {
    AccessMask.GENERIC_ALL: "GenericAll",
    AccessMask.WRITE_DAC: "WriteDACL",
    AccessMask.WRITE_OWNER: "WriteOwner",
    AccessMask.GENERIC_WRITE: "GenericWrite",
    AccessMask.DS_WRITE_PROPERTY: "WriteProperty",
    AccessMask.DS_CONTROL_ACCESS: "ExtendedRight",
    AccessMask.DS_SELF: "Self",
}


def mask_rights(mask: int) -> list[str]:
    """Return human-readable right names present in an access mask."""
    rights = []
    for flag, label in RIGHT_LABELS.items():
        if mask & flag:
            rights.append(label)
    return rights


def has_write_dacl(mask: int) -> bool:
    """Return True if the mask grants WriteDACL (directly or via GenericAll)."""
    return bool(mask & (AccessMask.WRITE_DAC | AccessMask.GENERIC_ALL))


# ---------------------------------------------------------------------------
# Extended-right / property-set GUIDs (MS-ADTS / AD schema)
# ---------------------------------------------------------------------------
# DCSync rights
GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"

# Password / credential rights
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_USER_CHANGE_PASSWORD = "ab721a53-1e2f-11d0-9819-00aa0040529b"

# LAPS password read GUIDs
GUID_LAPS_LEGACY = "e6075277-72a6-4559-9571-a1a086a898a3"  # ms-Mcs-AdmPwd (legacy LAPS)
GUID_LAPS_PASSWORD = "b913d02b-1579-4eee-82ff-61dd69ad4fe6"  # ms-LAPS-Password
GUID_LAPS_ENCRYPTED_PASSWORD = "ab6a8f8f-7c09-4ef3-a08e-ac8ee3f8a986"  # ms-LAPS-EncryptedPassword

# gMSA password read GUID
GUID_GMSA_MANAGED_PASSWORD = "0e78295a-c6d0-4b74-b6f2-52c7563aaca4"  # msDS-ManagedPassword (property set)

# WriteProperty attribute GUIDs
GUID_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GUID_MSDS_ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
GUID_MSDS_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"

# PKI template property GUIDs (for WritePKI checks)
GUID_PKI_NAME_FLAG = "ea1dddc4-60ff-416e-8cc0-17cee534bce7"  # msPKI-Certificate-Name-Flag
GUID_PKI_ENROLLMENT_FLAG = "d15ef7d8-f226-46db-ae79-b34e560bd12c"  # msPKI-Enrollment-Flag

# Self / validated write GUIDs
GUID_SELF_MEMBERSHIP = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# GPO / OU property GUIDs
GUID_GPLINK = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
GUID_GPOPTIONS = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"

# Property-set GUIDs
GUID_ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"

# ADCS extended rights
GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Friendly names for extended rights / property GUIDs
GUID_LABELS: dict[str, str] = {
    GUID_DS_REPL_GET_CHANGES: "DS-Replication-Get-Changes",
    GUID_DS_REPL_GET_CHANGES_ALL: "DS-Replication-Get-Changes-All",
    GUID_DS_REPL_GET_CHANGES_FILTERED: "DS-Replication-Get-Changes-In-Filtered-Set",
    GUID_FORCE_CHANGE_PASSWORD: "User-Force-Change-Password",
    GUID_USER_CHANGE_PASSWORD: "User-Change-Password",
    GUID_LAPS_LEGACY: "ms-Mcs-AdmPwd",
    GUID_LAPS_PASSWORD: "ms-LAPS-Password",
    GUID_LAPS_ENCRYPTED_PASSWORD: "ms-LAPS-EncryptedPassword",
    GUID_GMSA_MANAGED_PASSWORD: "msDS-ManagedPassword",
    GUID_MEMBER: "Member",
    GUID_SPN: "servicePrincipalName",
    GUID_MSDS_ALLOWED_TO_ACT: "msDS-AllowedToActOnBehalfOfOtherIdentity",
    GUID_MSDS_KEY_CREDENTIAL_LINK: "msDS-KeyCredentialLink",
    GUID_SELF_MEMBERSHIP: "Self-Membership",
    GUID_GPLINK: "gPLink",
    GUID_GPOPTIONS: "gPOptions",
    GUID_ACCOUNT_RESTRICTIONS: "User-Account-Restrictions",
    GUID_ENROLL: "Certificate-Enrollment",
    GUID_AUTOENROLL: "Certificate-AutoEnrollment",
    GUID_PKI_NAME_FLAG: "msPKI-Certificate-Name-Flag",
    GUID_PKI_ENROLLMENT_FLAG: "msPKI-Enrollment-Flag",
}


# ---------------------------------------------------------------------------
# userAccountControl flags (MS-ADTS 2.2.16)
# ---------------------------------------------------------------------------
class UAC(IntEnum):
    ACCOUNT_DISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST = 0x0800
    WORKSTATION_TRUST = 0x1000
    SERVER_TRUST = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000


# ---------------------------------------------------------------------------
# ACE types (MS-DTYP 2.4.4.1)
# ---------------------------------------------------------------------------
ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_DENIED = 0x01
ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_TYPE_ACCESS_DENIED_OBJECT = 0x06

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",
}

# ACE flags
ACE_INHERITED = 0x10

# Object ACE flags
ACE_OBJECT_TYPE_PRESENT = 0x01
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02


# ---------------------------------------------------------------------------
# SID parsing (MS-DTYP 2.4.2)
# ---------------------------------------------------------------------------
@dataclass
class SID:
    revision: int
    authority: int
    sub_authorities: list[int]

    def __str__(self) -> str:
        parts = [f"S-{self.revision}-{self.authority}"]
        parts.extend(str(sa) for sa in self.sub_authorities)
        return "-".join(parts)

    @property
    def rid(self) -> int | None:
        return self.sub_authorities[-1] if self.sub_authorities else None


def parse_sid(data: bytes, offset: int = 0) -> tuple[SID, int]:
    """Parse a SID from raw bytes. Returns (SID, bytes_consumed)."""
    if offset + 8 > len(data):
        raise ValueError(f"SID data too short at offset {offset}: need 8 bytes, have {len(data) - offset}")
    revision = data[offset]
    sub_count = data[offset + 1]
    # Authority is 6 bytes big-endian
    authority = int.from_bytes(data[offset + 2 : offset + 8], "big")
    subs = []
    pos = offset + 8
    for _ in range(sub_count):
        (sa,) = struct.unpack_from("<I", data, pos)
        subs.append(sa)
        pos += 4
    return SID(revision, authority, subs), pos - offset


def sid_size(data: bytes, offset: int = 0) -> int:
    sub_count = data[offset + 1]
    return 8 + 4 * sub_count


# ---------------------------------------------------------------------------
# ACE parsing
# ---------------------------------------------------------------------------
@dataclass
class ACE:
    ace_type: int
    ace_flags: int
    access_mask: int
    trustee: SID
    object_type: str | None = None  # GUID string for object ACEs
    inherited_object_type: str | None = None
    inherited: bool = False

    @property
    def type_name(self) -> str:
        return ACE_TYPE_NAMES.get(self.ace_type, f"UNKNOWN(0x{self.ace_type:02x})")

    @property
    def rights(self) -> list[str]:
        return mask_rights(self.access_mask)

    @property
    def is_allow(self) -> bool:
        return self.ace_type in (ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT)

    def to_dict(self) -> dict:
        return {
            "ace_type": self.type_name,
            "trustee_sid": str(self.trustee),
            "access_mask": self.access_mask,
            "rights": self.rights,
            "object_type": self.object_type,
            "inherited_object_type": self.inherited_object_type,
            "inherited": self.inherited,
        }


def parse_ace(data: bytes, offset: int) -> tuple[ACE, int]:
    """Parse a single ACE. Returns (ACE, total_ace_size)."""
    if offset + 8 > len(data):
        raise ValueError(f"ACE data too short at offset {offset}: need 8 bytes, have {len(data) - offset}")
    ace_type = data[offset]
    ace_flags = data[offset + 1]
    (ace_size,) = struct.unpack_from("<H", data, offset + 2)
    (access_mask,) = struct.unpack_from("<I", data, offset + 4)

    inherited = bool(ace_flags & ACE_INHERITED)
    object_type_guid = None
    inherited_object_type_guid = None

    if ace_type in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT):
        (obj_flags,) = struct.unpack_from("<I", data, offset + 8)
        pos = offset + 12
        if obj_flags & ACE_OBJECT_TYPE_PRESENT:
            object_type_guid = str(uuid.UUID(bytes_le=data[pos : pos + 16]))
            pos += 16
        if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
            inherited_object_type_guid = str(uuid.UUID(bytes_le=data[pos : pos + 16]))
            pos += 16
        trustee, _ = parse_sid(data, pos)
    else:
        trustee, _ = parse_sid(data, offset + 8)

    ace = ACE(
        ace_type=ace_type,
        ace_flags=ace_flags,
        access_mask=access_mask,
        trustee=trustee,
        object_type=object_type_guid,
        inherited_object_type=inherited_object_type_guid,
        inherited=inherited,
    )
    return ace, ace_size


# ---------------------------------------------------------------------------
# ACL parsing (MS-DTYP 2.4.4)
# ---------------------------------------------------------------------------
@dataclass
class ACL:
    revision: int
    aces: list[ACE] = field(default_factory=list)


def parse_acl(data: bytes, offset: int) -> ACL:
    """Parse an ACL (DACL or SACL) from raw bytes."""
    if offset + 8 > len(data):
        raise ValueError(f"ACL data too short at offset {offset}: need 8 bytes, have {len(data) - offset}")
    revision = data[offset]
    (ace_count,) = struct.unpack_from("<H", data, offset + 4)
    acl = ACL(revision=revision)
    pos = offset + 8  # skip ACL header (8 bytes)
    for _ in range(ace_count):
        ace, ace_size = parse_ace(data, pos)
        acl.aces.append(ace)
        pos += ace_size
    return acl


# ---------------------------------------------------------------------------
# Security Descriptor parsing (MS-DTYP 2.4.6)
# ---------------------------------------------------------------------------
@dataclass
class SecurityDescriptor:
    revision: int
    owner: SID | None
    group: SID | None
    dacl: ACL | None
    sacl: ACL | None


def parse_security_descriptor(data: bytes) -> SecurityDescriptor:
    """Parse a self-relative SECURITY_DESCRIPTOR from raw bytes."""
    if len(data) < 20:
        raise ValueError(f"Security descriptor too short: {len(data)} bytes")

    revision = data[0]
    (control,) = struct.unpack_from("<H", data, 2)
    (off_owner, off_group, off_sacl, off_dacl) = struct.unpack_from("<IIII", data, 4)

    owner = None
    if off_owner:
        owner, _ = parse_sid(data, off_owner)

    group = None
    if off_group:
        group, _ = parse_sid(data, off_group)

    sacl = None
    if off_sacl:
        sacl = parse_acl(data, off_sacl)

    dacl = None
    if off_dacl:
        dacl = parse_acl(data, off_dacl)

    return SecurityDescriptor(
        revision=revision,
        owner=owner,
        group=group,
        dacl=dacl,
        sacl=sacl,
    )

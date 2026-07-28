"""Stealth / noise-reduction configuration for AD collection.

Provides a :class:`StealthConfig` dataclass that centralises every
operator-tunable knob affecting the tool's network fingerprint:

  - **SDFlags**: which SD components to request (or disable entirely)
  - **LDAP pacing**: delay and jitter between paged search fetches
  - **SMB pacing**: delay between host connections
  - **Concurrency**: worker threads and batch sizes
  - **Collection scope**: which object types to collect, minimal attrs
  - **DNS behaviour**: skip GC/Kerberos SRV lookups
  - **ADCS HTTP probes**: opt-in instead of automatic

Three built-in presets (``low``, ``medium``, ``high``) bundle these
settings for common use cases.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any


# SD flag component bits
SD_OWNER = 0x01
SD_GROUP = 0x02
SD_DACL = 0x04
SD_SACL = 0x08


@dataclass
class StealthConfig:
    """Operator-tunable noise-reduction settings.

    Every field has a safe default that preserves the tool's current
    (full-speed, full-data) behaviour, so existing users are unaffected
    unless they explicitly opt in to stealth features.
    """

    # -- 1. SDFlags control ---------------------------------------------------
    # 0x07 = OWNER+GROUP+DACL (current default).  Set to 0 to skip SD
    # collection entirely (no nTSecurityDescriptor requested).
    sd_flags: int = SD_OWNER | SD_GROUP | SD_DACL  # 0x07
    # If True, nTSecurityDescriptor is removed from all attribute lists
    # and the SD_FLAGS control is not sent.
    skip_sd: bool = False

    # -- 2. LDAP query pacing -------------------------------------------------
    # Seconds to wait between each page fetch (0 = no delay).
    ldap_delay: float = 0.0
    # Random jitter factor applied to ldap_delay.  0.2 means ±20%.
    ldap_jitter: float = 0.0

    # -- 3. SMB pacing --------------------------------------------------------
    # Seconds to wait between starting SMB connections to different hosts.
    smb_delay: float = 0.0
    # Random jitter factor applied to smb_delay.
    smb_jitter: float = 0.0
    # If True, skip all SMB/RPC enumeration (LDAP-only / DCOnly mode).
    skip_smb: bool = False

    # -- 4. Concurrency -------------------------------------------------------
    # Override defaults for network collection workers and batch size.
    # None means "use the existing default".
    smb_workers: int | None = None
    smb_batch_size: int | None = None
    ldap_page_size: int | None = None

    # -- 5. Collection scope --------------------------------------------------
    # Restrict collection to these object types (empty = collect all).
    # Valid values: user, group, computer, ou, gpo, container, domain,
    #   trusteddomain, certtemplate, pki, oidobject, gmsa
    collect_types: list[str] = field(default_factory=list)
    # If True, request only the minimal attribute set per object type
    # (dn, sAMAccountName, objectSid, objectClass, nTSecurityDescriptor).
    minimal_attrs: bool = False

    # -- 6. DNS ---------------------------------------------------------------
    # Skip GC and Kerberos SRV record lookups.
    skip_gc_lookup: bool = False
    skip_kerberos_lookup: bool = False
    # Seconds to wait between DNS queries.
    dns_delay: float = 0.0

    # -- 7. ADCS HTTP ---------------------------------------------------------
    # When True, ADCS HTTP enrollment probing (ESC8 check) is enabled — an
    # active HTTP request to the CA. Default True (full ESC8 coverage, kept by
    # the 'low' preset); the 'medium' and 'high' presets set this False to
    # avoid the active probe.
    adcs_http_probe: bool = True

    # -- helpers --------------------------------------------------------------

    def effective_sd_flags(self) -> int:
        """Return the SD flags value to use, or 0 if SD is skipped."""
        if self.skip_sd:
            return 0
        return self.sd_flags

    def apply_delay(self, base_delay: float, jitter: float) -> None:
        """Sleep for *base_delay* ± *jitter* fraction.

        A jitter of 0.2 on a 1.0 s delay sleeps between 0.8 and 1.2 s.
        """
        if base_delay <= 0:
            return
        if jitter > 0:
            low = base_delay * (1.0 - jitter)
            high = base_delay * (1.0 + jitter)
            actual = random.uniform(low, high)
        else:
            actual = base_delay
        time.sleep(actual)

    def ldap_pace(self) -> None:
        """Apply LDAP query pacing delay."""
        self.apply_delay(self.ldap_delay, self.ldap_jitter)

    def smb_pace(self) -> None:
        """Apply SMB connection pacing delay."""
        self.apply_delay(self.smb_delay, self.smb_jitter)

    def dns_pace(self) -> None:
        """Apply DNS query pacing delay."""
        self.apply_delay(self.dns_delay, 0.0)

    def should_collect(self, obj_type: str) -> bool:
        """Return True if *obj_type* should be collected."""
        if not self.collect_types:
            return True  # no filter = collect everything
        return obj_type in self.collect_types

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (for meta/logging)."""
        return {
            "sd_flags": hex(self.sd_flags),
            "skip_sd": self.skip_sd,
            "ldap_delay": self.ldap_delay,
            "ldap_jitter": self.ldap_jitter,
            "smb_delay": self.smb_delay,
            "smb_jitter": self.smb_jitter,
            "skip_smb": self.skip_smb,
            "smb_workers": self.smb_workers,
            "smb_batch_size": self.smb_batch_size,
            "ldap_page_size": self.ldap_page_size,
            "collect_types": self.collect_types,
            "minimal_attrs": self.minimal_attrs,
            "skip_gc_lookup": self.skip_gc_lookup,
            "skip_kerberos_lookup": self.skip_kerberos_lookup,
            "dns_delay": self.dns_delay,
            "adcs_http_probe": self.adcs_http_probe,
        }

    def describe(self) -> list[str]:
        """Human-readable bullets of the active measures, from actual values."""
        lines: list[str] = []
        if self.skip_sd:
            lines.append("Security descriptors skipped (no nTSecurityDescriptor / ACLs)")
        else:
            comps = []
            if self.sd_flags & SD_OWNER:
                comps.append("owner")
            if self.sd_flags & SD_GROUP:
                comps.append("group")
            if self.sd_flags & SD_DACL:
                comps.append("DACL")
            if self.sd_flags & SD_SACL:
                comps.append("SACL")
            lines.append(f"Security descriptors: {', '.join(comps) if comps else 'none'}")
        if self.ldap_delay > 0:
            jitter = f" ±{int(self.ldap_jitter * 100)}%" if self.ldap_jitter else ""
            lines.append(f"LDAP paced {self.ldap_delay}s{jitter} between pages")
        if self.ldap_page_size is not None:
            lines.append(f"LDAP page size {self.ldap_page_size}")
        if self.minimal_attrs:
            lines.append("Minimal attribute set only")
        if self.collect_types:
            lines.append(f"Object types limited to: {', '.join(self.collect_types)}")
        if self.skip_smb:
            lines.append("SMB/RPC enumeration skipped — affects crawl")
        elif self.smb_workers is not None:
            lines.append(f"SMB workers limited to {self.smb_workers} — affects crawl")
        if self.skip_gc_lookup or self.skip_kerberos_lookup:
            lines.append("GC / Kerberos SRV DNS lookups skipped")
        if self.dns_delay > 0:
            lines.append(f"DNS queries paced {self.dns_delay}s")
        if not self.adcs_http_probe:
            lines.append("ADCS HTTP enrollment probing disabled")
        return lines

    def summary(self) -> str:
        """Compact one-line summary of the active measures (from actual values)."""
        parts: list[str] = []
        if self.skip_sd:
            parts.append("no SDs")
        elif self.sd_flags != (SD_OWNER | SD_GROUP | SD_DACL):
            parts.append("DACL-only SDs")
        if self.minimal_attrs:
            parts.append("minimal attrs")
        if self.skip_smb:
            parts.append("LDAP-only")
        if self.ldap_delay > 0:
            parts.append(f"LDAP {self.ldap_delay}s")
        if self.ldap_page_size is not None:
            parts.append(f"page {self.ldap_page_size}")
        if self.dns_delay > 0:
            parts.append(f"DNS {self.dns_delay}s")
        if self.skip_gc_lookup or self.skip_kerberos_lookup:
            parts.append("no SRV lookups")
        if not self.adcs_http_probe:
            parts.append("no ADCS probe")
        return ", ".join(parts) if parts else "full speed, full data (no evasion)"


# ---------------------------------------------------------------------------
# Built-in presets
# ---------------------------------------------------------------------------

# The three presets are DCOnly (`collect run`) LDAP profiles. They ALL collect
# the same full data — full security descriptors (OWNER+GROUP+DACL) and the
# full attribute set — so every level yields a complete, analysable dataset.
# They differ in LDAP query pacing and in two optional active side-lookups that
# reach beyond the bound LDAP session:
#
#   knob                 low          medium        high
#   ------------------   ----------   -----------   -----------
#   LDAP delay/jitter    none         0.3s ±20%     1.0s ±30%
#   LDAP page size       1000         500           300
#   ADCS HTTP probe      on           off           off
#   GC/Kerberos SRV      on           off           off
#
# Slower pacing spreads the same queries over more time, lowering the per-second
# request rate a DC (or its monitoring) sees. The ADCS HTTP probe (ESC8) and the
# GC/Kerberos DNS SRV lookups are extra active touches beyond core LDAP; low
# keeps them for convenience/coverage, medium and high drop them. Nothing here
# touches member hosts — SMB session/local-admin enumeration is the separate
# `collect crawl` command, which has its own throttle flags and ignores presets.

# Preset: low — full speed, full data, active side-lookups enabled
STEALTH_LOW = StealthConfig()

# Preset: medium — full data, moderate LDAP pacing, side-lookups off
STEALTH_MEDIUM = StealthConfig(
    ldap_delay=0.3,
    ldap_jitter=0.2,
    ldap_page_size=500,
    skip_gc_lookup=True,
    skip_kerberos_lookup=True,
    adcs_http_probe=False,
)

# Preset: high — full data, slow LDAP pacing, side-lookups off
STEALTH_HIGH = StealthConfig(
    ldap_delay=1.0,
    ldap_jitter=0.3,
    ldap_page_size=300,
    skip_gc_lookup=True,
    skip_kerberos_lookup=True,
    adcs_http_probe=False,
)

STEALTH_PRESETS: dict[str, StealthConfig] = {
    "low": STEALTH_LOW,
    "medium": STEALTH_MEDIUM,
    "high": STEALTH_HIGH,
}


def get_preset(name: str) -> StealthConfig:
    """Return a *copy* of the named preset.

    Raises ``ValueError`` for unknown names.
    """
    import copy
    preset = STEALTH_PRESETS.get(name.lower())
    if preset is None:
        valid = ", ".join(sorted(STEALTH_PRESETS))
        raise ValueError(f"Unknown stealth preset {name!r}. Choose from: {valid}")
    return copy.deepcopy(preset)

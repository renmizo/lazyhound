"""YAML configuration file support with sensible defaults."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path resolution helper
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge *override* into *base* (mutates *base*)."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


def resolve_path(path: str, base_dir: str | Path) -> Path:
    """Resolve *path* relative to *base_dir*.

    - Absolute paths are returned as-is.
    - Empty strings return *base_dir* itself.
    - Relative paths are joined to *base_dir*.
    - Environment variables (``$HOME``, ``${VAR}``) are expanded first.
    """
    if not path:
        return Path(base_dir).expanduser().resolve()
    expanded = os.path.expandvars(os.path.expanduser(path))
    p = Path(expanded)
    if p.is_absolute():
        return p
    return (Path(base_dir).expanduser().resolve() / p)


@dataclass
class ConnectionConfig:
    dc: str = ""
    domain: str = ""
    username: str = ""
    password: str = ""
    port: int = 389
    use_ssl: bool = False
    auth_method: str = "ntlm"
    nthash: str = ""
    ccache: str = ""  # Kerberos credential cache path (forces GSSAPI)
    validate_cert: bool = True
    timeout: int = 30
    use_start_tls: bool = True
    nameserver: str = ""  # DNS nameserver; defaults to DC if empty
    auto_negotiate: bool = False

    def __repr__(self) -> str:
        pw = "***" if self.password else "''"
        nt = "***" if self.nthash else "''"
        return (
            f"ConnectionConfig(dc={self.dc!r}, domain={self.domain!r}, "
            f"username={self.username!r}, password={pw}, "
            f"port={self.port}, use_ssl={self.use_ssl}, "
            f"auth_method={self.auth_method!r}, nthash={nt}, "
            f"validate_cert={self.validate_cert}, timeout={self.timeout}, "
            f"use_start_tls={self.use_start_tls}, "
            f"nameserver={self.nameserver!r})"
        )


@dataclass
class ScanConfig:
    include_checks: list[str] = field(default_factory=list)
    exclude_checks: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    max_workers: int = 1


@dataclass
class OutputConfig:
    json_path: str = ""
    html_path: str = ""
    csv_path: str = ""
    markdown_path: str = ""
    save_collection_path: str = ""
    quiet: bool = False


@dataclass
class HistoryConfig:
    enabled: bool = True
    db_path: str = ""


@dataclass
class ScoringConfig:
    """Scoring profile selection and overrides."""

    profile: str = "balanced"  # "strict", "balanced", "lenient", or custom
    curve: str | None = None  # override curve type
    coefficient: float | None = None  # override coefficient
    health_weight: float | None = None  # override health blend weight (0.0-1.0)
    grade_thresholds: dict[str, int] | None = None
    severity_points: dict[str, int] | None = None
    category_weights: dict[str, float] | None = None


@dataclass
class StealthYAMLConfig:
    """Stealth / noise-reduction settings loadable from YAML."""

    preset: str = ""  # "low", "medium", "high", or empty for custom
    sd_flags: int | None = None
    skip_sd: bool | None = None
    ldap_delay: float | None = None
    ldap_jitter: float | None = None
    smb_delay: float | None = None
    smb_jitter: float | None = None
    skip_smb: bool | None = None
    smb_workers: int | None = None
    smb_batch_size: int | None = None
    ldap_page_size: int | None = None
    collect_types: list[str] | None = None
    minimal_attrs: bool | None = None
    skip_gc_lookup: bool | None = None
    skip_kerberos_lookup: bool | None = None
    dns_delay: float | None = None
    adcs_http_probe: bool | None = None

    def to_stealth_config(self):
        """Convert to a runtime ``StealthConfig`` instance.

        Starts from the named preset (if any), then overlays any
        explicitly-set fields.
        """
        from .stealth import StealthConfig, get_preset

        if self.preset:
            cfg = get_preset(self.preset)
        else:
            cfg = StealthConfig()

        # Overlay any explicitly-set values
        if self.sd_flags is not None:
            cfg.sd_flags = self.sd_flags
        if self.skip_sd is not None:
            cfg.skip_sd = self.skip_sd
        if self.ldap_delay is not None:
            cfg.ldap_delay = self.ldap_delay
        if self.ldap_jitter is not None:
            cfg.ldap_jitter = self.ldap_jitter
        if self.smb_delay is not None:
            cfg.smb_delay = self.smb_delay
        if self.smb_jitter is not None:
            cfg.smb_jitter = self.smb_jitter
        if self.skip_smb is not None:
            cfg.skip_smb = self.skip_smb
        if self.smb_workers is not None:
            cfg.smb_workers = self.smb_workers
        if self.smb_batch_size is not None:
            cfg.smb_batch_size = self.smb_batch_size
        if self.ldap_page_size is not None:
            cfg.ldap_page_size = self.ldap_page_size
        if self.collect_types is not None:
            cfg.collect_types = self.collect_types
        if self.minimal_attrs is not None:
            cfg.minimal_attrs = self.minimal_attrs
        if self.skip_gc_lookup is not None:
            cfg.skip_gc_lookup = self.skip_gc_lookup
        if self.skip_kerberos_lookup is not None:
            cfg.skip_kerberos_lookup = self.skip_kerberos_lookup
        if self.dns_delay is not None:
            cfg.dns_delay = self.dns_delay
        if self.adcs_http_probe is not None:
            cfg.adcs_http_probe = self.adcs_http_probe

        return cfg


@dataclass
class DisplayConfig:
    """Display style configuration."""

    style: int = 2  # 1=compact, 2=clean, 3=boxed, 4=detailed


@dataclass
class LoggingConfig:
    """Logging configuration for scan output capture."""

    enabled: bool = True
    log_dir: str = "logs"
    log_level: str = "INFO"
    console_capture: bool = True  # also capture console report to log file


@dataclass
class PathsConfig:
    """Centralised write-location configuration.

    All relative paths are resolved against *base_dir*.  Absolute paths
    are used as-is.  ``base_dir`` itself defaults to the current working
    directory (``"."``).
    """

    base_dir: str = "."
    collection_dir: str = "."       # where collect writes JSON
    log_dir: str = "logs"           # scan log files
    history_db: str = "lazyhound_finder_history.db"
    reports_dir: str = "."          # default dir for scan reports

    # -- resolved helpers ------------------------------------------------

    def resolve(self, path: str) -> Path:
        """Resolve *path* relative to *base_dir*."""
        return resolve_path(path, self.base_dir)

    @property
    def resolved_collection_dir(self) -> Path:
        return self.resolve(self.collection_dir)

    @property
    def resolved_log_dir(self) -> Path:
        return self.resolve(self.log_dir)

    @property
    def resolved_history_db(self) -> Path:
        return self.resolve(self.history_db)

    @property
    def resolved_reports_dir(self) -> Path:
        return self.resolve(self.reports_dir)


@dataclass
class AppConfig:
    """Top-level configuration assembled from file + CLI overrides."""

    connection: ConnectionConfig = field(default_factory=ConnectionConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    display: DisplayConfig = field(default_factory=DisplayConfig)
    stealth: StealthYAMLConfig = field(default_factory=StealthYAMLConfig)

    @classmethod
    def from_yaml(cls, path: str | Path, profile: str | None = None) -> AppConfig:
        """Load config from a YAML file.

        If *profile* is given and a ``profiles.<name>`` section exists,
        its values are merged over the top-level defaults (profile wins).
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        with p.open() as f:
            raw = yaml.safe_load(f) or {}

        # Feature 7: named profiles
        profiles = raw.pop("profiles", {})
        if profile and profile in profiles:
            profile_data = profiles[profile]
            if isinstance(profile_data, dict):
                _deep_merge(raw, profile_data)

        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> AppConfig:
        cfg = cls()
        if raw.get("connection"):
            c = raw["connection"]
            cfg.connection = ConnectionConfig(
                dc=c.get("dc", ""),
                domain=c.get("domain", ""),
                username=c.get("username", ""),
                password=c.get("password", ""),
                port=c.get("port", 389),
                use_ssl=c.get("use_ssl", False),
                auth_method=c.get("auth_method", "ntlm"),
                nthash=c.get("nthash", ""),
                ccache=c.get("ccache", ""),
                validate_cert=c.get("validate_cert", True),
                timeout=c.get("timeout", 30),
                use_start_tls=c.get("use_start_tls", True),
                nameserver=c.get("nameserver", ""),
                auto_negotiate=c.get("auto_negotiate", False),
            )
        if raw.get("scan"):
            s = raw["scan"]
            cfg.scan = ScanConfig(
                include_checks=s.get("include_checks", []),
                exclude_checks=s.get("exclude_checks", []),
                categories=s.get("categories", []),
                tags=s.get("tags", []),
                max_workers=s.get("max_workers", 1),
            )
        if raw.get("output"):
            o = raw["output"]
            cfg.output = OutputConfig(
                json_path=o.get("json", ""),
                html_path=o.get("html", ""),
                csv_path=o.get("csv", ""),
                markdown_path=o.get("markdown", ""),
                save_collection_path=o.get("save_collection", ""),
                quiet=o.get("quiet", False),
            )
        if raw.get("history"):
            h = raw["history"]
            cfg.history = HistoryConfig(
                enabled=h.get("enabled", True),
                db_path=h.get("db_path", ""),
            )
        if raw.get("scoring"):
            s = raw["scoring"]
            cfg.scoring = ScoringConfig(
                profile=s.get("profile", "balanced"),
                curve=s.get("curve"),
                coefficient=s.get("coefficient"),
                grade_thresholds=s.get("grade_thresholds"),
                severity_points=s.get("severity_points"),
                category_weights=s.get("category_weights"),
            )
        if raw.get("logging"):
            lg = raw["logging"]
            cfg.logging = LoggingConfig(
                enabled=lg.get("enabled", True),
                log_dir=lg.get("log_dir", "logs"),
                log_level=lg.get("log_level", "INFO"),
                console_capture=lg.get("console_capture", True),
            )
        if raw.get("paths"):
            p = raw["paths"]
            cfg.paths = PathsConfig(
                base_dir=p.get("base_dir", "."),
                collection_dir=p.get("collection_dir", "."),
                log_dir=p.get("log_dir", "logs"),
                history_db=p.get("history_db", "lazyhound_finder_history.db"),
                reports_dir=p.get("reports_dir", "."),
            )
        if raw.get("display"):
            d = raw["display"]
            cfg.display = DisplayConfig(
                style=d.get("style", 2),
            )
        if raw.get("stealth"):
            st = raw["stealth"]
            sd_flags_raw = st.get("sd_flags")
            # Support hex strings like "0x04" or integers
            if isinstance(sd_flags_raw, str):
                sd_flags_raw = int(sd_flags_raw, 0)
            cfg.stealth = StealthYAMLConfig(
                preset=st.get("preset", ""),
                sd_flags=sd_flags_raw,
                skip_sd=st.get("skip_sd"),
                ldap_delay=st.get("ldap_delay"),
                ldap_jitter=st.get("ldap_jitter"),
                smb_delay=st.get("smb_delay"),
                smb_jitter=st.get("smb_jitter"),
                skip_smb=st.get("skip_smb"),
                smb_workers=st.get("smb_workers"),
                smb_batch_size=st.get("smb_batch_size"),
                ldap_page_size=st.get("ldap_page_size"),
                collect_types=st.get("collect_types"),
                minimal_attrs=st.get("minimal_attrs"),
                skip_gc_lookup=st.get("skip_gc_lookup"),
                skip_kerberos_lookup=st.get("skip_kerberos_lookup"),
                dns_delay=st.get("dns_delay"),
                adcs_http_probe=st.get("adcs_http_probe"),
            )
        return cfg

    def merge_cli(self, **overrides: Any) -> None:
        """Merge CLI arguments over config file values (CLI wins)."""
        for key, val in overrides.items():
            if val is None:
                continue
            parts = key.split(".", 1)
            if len(parts) == 2:
                section, attr = parts
                obj = getattr(self, section, None)
                if obj and hasattr(obj, attr):
                    setattr(obj, attr, val)

    def apply_paths(self) -> None:
        """Push resolved *paths* into legacy config sections.

        Call this after all CLI overrides have been merged so that
        ``paths.*`` values cascade into ``logging.log_dir``,
        ``history.db_path``, and report output paths where the user
        hasn't set them explicitly via CLI.
        """
        p = self.paths

        # Logging — only override if still at the default
        if self.logging.log_dir == "logs":
            self.logging.log_dir = str(p.resolved_log_dir)

        # History DB — only override if still empty (default)
        if not self.history.db_path:
            self.history.db_path = str(p.resolved_history_db)

        # Reports — if no explicit path given, derive from reports_dir
        reports = p.resolved_reports_dir
        if self.output.json_path and not Path(self.output.json_path).is_absolute():
            self.output.json_path = str(reports / self.output.json_path)
        if self.output.html_path and not Path(self.output.html_path).is_absolute():
            self.output.html_path = str(reports / self.output.html_path)
        if self.output.csv_path and not Path(self.output.csv_path).is_absolute():
            self.output.csv_path = str(reports / self.output.csv_path)
        if self.output.markdown_path and not Path(self.output.markdown_path).is_absolute():
            self.output.markdown_path = str(reports / self.output.markdown_path)

    @staticmethod
    def default_yaml(project_dir: str | None = None) -> str:
        """Return a commented default YAML config suitable for ``init``.

        If *project_dir* is given it is written as the ``paths.base_dir``
        value so every relative path in the config resolves to the
        project folder.  When omitted, ``"."`` is used (legacy behaviour).
        """
        base = project_dir or "."
        return f"""\
# LazyHound configuration file
# ================================
# All relative paths are resolved against paths.base_dir (the project directory).
# Absolute paths are used as-is.
# Environment variables ($HOME, ${{VAR}}) are expanded.

paths:
  base_dir: {base:<30s} # project directory — all relative paths resolve from here
  collection_dir: .                     # where 'collect' writes JSON files
  log_dir: logs                         # scan log files
  history_db: lazyhound_finder_history.db   # scan history database
  reports_dir: .                        # default directory for scan reports

connection:
  # dc: dc01.corp.local
  # domain: corp.local
  # username: admin
  # port: 389
  # use_ssl: false
  # use_start_tls: true             # STARTTLS on port 389 (recommended)
  # auth_method: ntlm              # ntlm | simple | kerberos
  # timeout: 30
  # nameserver:                    # DNS server for resolution (defaults to DC)

scan:
  # include_checks: []
  # exclude_checks: []
  # categories: []
  # max_workers: 1

output:
  # json: report.json              # relative to paths.reports_dir
  # html: report.html
  # csv: report.csv
  # markdown: report.md
  # save_collection: collection.json  # save LDAP data during scan
  # quiet: false

history:
  enabled: true
  # db_path:                       # override paths.history_db

scoring:
  profile: balanced                # strict | balanced | lenient

logging:
  enabled: true
  # log_dir:                       # override paths.log_dir
  log_level: INFO
  console_capture: true

display:
  style: 2                          # 1=compact, 2=clean, 3=boxed, 4=detailed

stealth:
  # preset: low                     # low | medium | high (or leave empty for custom)
  # sd_flags: 0x07                  # SD components: 0x01=owner 0x02=group 0x04=DACL
  # skip_sd: false                  # skip nTSecurityDescriptor entirely
  # ldap_delay: 0.0                 # seconds between LDAP page fetches
  # ldap_jitter: 0.0                # random jitter factor (0.2 = +/-20%)
  # smb_delay: 0.0                  # seconds between SMB host connections
  # smb_jitter: 0.0                 # random jitter factor for SMB
  # skip_smb: false                 # skip all SMB/RPC (LDAP-only / DCOnly)
  # smb_workers: 10                 # concurrent SMB threads
  # smb_batch_size: 50              # hosts per SMB batch
  # ldap_page_size: 1000            # LDAP paged search page size
  # collect_types: []               # restrict to specific types (user,group,computer,...)
  # minimal_attrs: false            # request only essential attributes
  # skip_gc_lookup: false           # skip Global Catalog SRV lookups
  # skip_kerberos_lookup: false     # skip Kerberos KDC SRV lookups
  # dns_delay: 0.0                  # seconds between DNS queries
  # adcs_http_probe: true           # probe ADCS HTTP enrollment endpoints

# Named profiles — override any top-level section per environment.
# Usage: load with AppConfig.from_yaml("config.yml", profile="dev")
# profiles:
#   corp:
#     connection:
#       dc: dc01.corp.local
#       domain: corp.local
#       username: admin
#   dev:
#     connection:
#       dc: dc01.dev.local
#       domain: dev.local
#       username: devadmin
"""

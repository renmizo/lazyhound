"""Legacy argparse CLI entry point for LazyHound.

The primary CLI is ``cli.py`` (Click-based).  This module is retained for
its helper functions (``_setup_logging``, ``_handle_list_checks``,
``_handle_history_show``, ``_reconstruct_scan_result``, etc.) that are
imported by the Click CLI.  The ``main()`` / ``build_parser()`` entry
point here is **deprecated** — use ``lazyhound.cli:main`` instead.
"""

from __future__ import annotations

import argparse
import logging
import sys

from lazyhound import __version__
from .checks.registry import CheckRegistry
from ..finder_config import AppConfig, PathsConfig
from ..storage.history import ScanHistory


def _resolve_history_db(history_db: str | None, config_path: str | None) -> str:
    """Resolve the finder history DB path for the utility commands.

    An explicit ``--history-db`` wins.  Otherwise, if a project config was
    given, the DB is anchored to that config's ``paths.base_dir``.  Falling
    back to the default resolves against the current directory.
    """
    if history_db:
        return history_db
    if config_path:
        try:
            cfg = AppConfig.from_yaml(config_path)
            cfg.apply_paths()
            return cfg.history.db_path or str(cfg.paths.resolved_history_db)
        except Exception:
            pass
    return str(PathsConfig().resolved_history_db)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lazyhound",
        description="LazyHound — Active Directory Security Assessment Tool",
    )
    parser.add_argument("--version", action="version", version=f"lazyhound {__version__}")

    # -- connection --
    conn = parser.add_argument_group("connection")
    conn.add_argument("--dc", help="Domain controller hostname or IP")
    conn.add_argument("--domain", help="Target domain (e.g. corp.local)")
    conn.add_argument("--username", "-u", help="Username for authentication")
    conn.add_argument("--password", "-p", help="Password (use --nthash for PtH)")
    conn.add_argument("--nthash", help="NT hash for pass-the-hash authentication")
    conn.add_argument("--auth", choices=["ntlm", "simple", "kerberos"], default=None,
                       help="Authentication method (default: ntlm)")
    conn.add_argument("--port", type=int, default=None, help="LDAP port (default: 389)")
    conn.add_argument("--no-ssl", action="store_true", help="Disable LDAPS (use port 389)")
    conn.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636)")
    conn.add_argument("--no-starttls", action="store_true", help="Disable STARTTLS on port 389")
    conn.add_argument("--no-verify-cert", action="store_true", help="Skip TLS certificate validation")
    conn.add_argument("--timeout", type=int, default=None, help="Connection timeout in seconds")

    # -- scan --
    scan = parser.add_argument_group("scan options")
    scan.add_argument("--include", nargs="+", metavar="ID", help="Only run these check IDs")
    scan.add_argument("--exclude", nargs="+", metavar="ID", help="Skip these check IDs")
    scan.add_argument("--categories", nargs="+", metavar="CAT", help="Only run these categories")
    scan.add_argument("--workers", type=int, default=None, help="Concurrent check workers")

    # -- output --
    out = parser.add_argument_group("output")
    out.add_argument("--json", dest="json_path", metavar="PATH", help="Write JSON report")
    out.add_argument("--html", dest="html_path", metavar="PATH", help="Write HTML report")
    out.add_argument("--csv", dest="csv_path", metavar="PATH", help="Write CSV report")
    out.add_argument("--quiet", "-q", action="store_true", help="Suppress console output")

    # -- config --
    parser.add_argument("--config", "-c", metavar="FILE", help="YAML configuration file")

    # -- history --
    hist = parser.add_argument_group("history")
    hist.add_argument("--no-history", action="store_true", help="Disable scan history")
    hist.add_argument("--history-db", metavar="PATH", help="History database path")
    hist.add_argument("--history-list", action="store_true", help="List past scans and exit")
    hist.add_argument("--history-diff", nargs=2, metavar=("OLD_ID", "NEW_ID"),
                       help="Diff two historical scans and exit")
    hist.add_argument("--history-trend", metavar="DOMAIN", help="Show score trend and exit")

    # -- scoring --
    scoring = parser.add_argument_group("scoring")
    scoring.add_argument("--score-profile", choices=["strict", "balanced", "lenient"],
                          default=None,
                          help="Scoring model: strict (linear), balanced (sqrt), lenient (log)")

    # -- logging --
    log_grp = parser.add_argument_group("logging")
    log_grp.add_argument("--log-dir", default=None, help="Directory for scan log files")
    log_grp.add_argument("--no-log", action="store_true", help="Disable file logging")

    # -- utility --
    parser.add_argument("--list-checks", action="store_true", help="List all checks and exit")
    parser.add_argument("--verbose", "-v", action="count", default=0,
                         help="Increase verbosity (-v, -vv)")

    return parser


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _handle_list_checks() -> None:
    registry = CheckRegistry.get_instance()
    registry.discover_checks()
    checks = sorted(registry.all_checks(), key=lambda c: c.check_id)
    print(f"\n{'ID':<14} {'Name':<40} {'Category':<22} Tags")
    print("─" * 95)
    for c in checks:
        tags = ", ".join(c.tags) if c.tags else ""
        print(f"{c.check_id:<14} {c.name:<40} {c.category.label:<22} {tags}")
    print(f"\nTotal: {len(checks)} checks\n")


def _handle_history_list(db_path: str | None, domain: str | None = None) -> None:
    path = db_path or "lazyhound_finder_history.db"
    with ScanHistory(path) as hist:
        scans = hist.list_scans(domain=domain)
    if not scans:
        print("No scan history found.")
        return
    print(f"\n{'Scan ID':<14} {'Domain':<25} {'User':<20} {'Date':<22} {'Score':>6} {'Rating':>12} {'Findings':>9}")
    print("─" * 116)
    for s in scans:
        user = s.run_as_user or ""
        print(f"{s.scan_id:<14} {s.domain:<25} {user:<20} {s.started_at[:19]:<22} "
              f"{s.risk_score:>6} {s.rating:>12} {s.total_findings:>9}")
    print()


def _handle_history_diff(old_id: str, new_id: str, db_path: str | None) -> None:
    path = db_path or "lazyhound_finder_history.db"
    with ScanHistory(path) as hist:
        diff = hist.diff(old_id, new_id)
    if not diff:
        print("Could not find one or both scans.")
        return
    arrow = "▲" if diff.score_delta > 0 else "▼" if diff.score_delta < 0 else "="
    print(f"\nScore change: {arrow} {diff.score_delta:+d}")
    print(f"New findings:      {len(diff.new_findings)}")
    print(f"Resolved findings: {len(diff.resolved_findings)}")
    print(f"Unchanged:         {diff.unchanged_count}")
    if diff.new_findings:
        print("\n  New:")
        for f in diff.new_findings:
            print(f"    [{f.get('severity', '?').upper()}] {f.get('title', '?')}")
    if diff.resolved_findings:
        print("\n  Resolved:")
        for f in diff.resolved_findings:
            print(f"    [{f.get('severity', '?').upper()}] {f.get('title', '?')}")
    print()


def _handle_history_show(scan_id: str | None, db_path: str | None, domain: str | None, style: int = 2) -> None:
    """Re-render a stored scan to the console with full color output."""
    from ..reports.console import ConsoleReport

    path = db_path or "lazyhound_finder_history.db"
    with ScanHistory(path) as hist:
        if scan_id:
            scan_dict = hist.get_scan(scan_id)
        elif domain:
            scan_dict = hist.get_latest(domain)
        else:
            # Get most recent overall
            scans = hist.list_scans(limit=1)
            if scans:
                scan_dict = hist.get_scan(scans[0].scan_id)
            else:
                scan_dict = None

    if not scan_dict:
        target = scan_id or domain or "latest"
        print(f"Scan not found: {target}")
        return

    # Reconstruct ScanResult from stored dict
    result = _reconstruct_scan_result(scan_dict)
    ConsoleReport(style=style).render(result)


def _reconstruct_scan_result(scan_dict: dict) -> "ScanResult":
    """Reconstruct a ScanResult from a stored JSON dict."""
    from ..finder_models import (
        CheckCategory, CheckResult, DomainInfo, Finding,
        MitreAttack, Remediation, ScanResult, Severity,
    )
    from datetime import datetime

    # Parse timestamps
    started_at = datetime.fromisoformat(scan_dict["started_at"])
    completed_at = None
    if scan_dict.get("completed_at"):
        completed_at = datetime.fromisoformat(scan_dict["completed_at"])

    # Reconstruct domain info
    di_dict = scan_dict.get("domain_info", {})
    domain_info = DomainInfo(
        domain=di_dict.get("domain", ""),
        domain_dn=di_dict.get("domain_dn", ""),
        domain_sid=di_dict.get("domain_sid", ""),
        forest_name=di_dict.get("forest_name", ""),
        dc_hostname=di_dict.get("dc_hostname", ""),
        dc_ip=di_dict.get("dc_ip", ""),
        functional_level=di_dict.get("functional_level", ""),
        domain_controllers=di_dict.get("domain_controllers", []),
        total_users=di_dict.get("total_users", 0),
        total_computers=di_dict.get("total_computers", 0),
        total_groups=di_dict.get("total_groups", 0),
    )

    # Reconstruct check results
    check_results = []
    for cr_dict in scan_dict.get("check_results", []):
        cat_val = cr_dict.get("category", "account_hygiene")
        try:
            category = CheckCategory(cat_val)
        except ValueError:
            category = CheckCategory.ACCOUNT_HYGIENE

        findings = []
        for f_dict in cr_dict.get("findings", []):
            sev_val = f_dict.get("severity", "info")
            try:
                severity = Severity(sev_val)
            except ValueError:
                severity = Severity.INFO

            f_cat_val = f_dict.get("category", cat_val)
            try:
                f_cat = CheckCategory(f_cat_val)
            except ValueError:
                f_cat = category

            mitre = None
            if f_dict.get("mitre"):
                m = f_dict["mitre"]
                mitre = MitreAttack(
                    technique_id=m.get("technique_id", ""),
                    technique_name=m.get("technique_name", ""),
                    tactic=m.get("tactic", ""),
                    url=m.get("url", ""),
                    known_tools=tuple(m.get("known_tools", [])),
                )

            remediation = None
            if f_dict.get("remediation"):
                r = f_dict["remediation"]
                remediation = Remediation(
                    description=r.get("description", ""),
                    powershell=r.get("powershell"),
                    gpo_path=r.get("gpo_path"),
                    reference_url=r.get("reference_url"),
                    effort=r.get("effort", "medium"),
                )

            findings.append(Finding(
                title=f_dict.get("title", ""),
                description=f_dict.get("description", ""),
                severity=severity,
                category=f_cat,
                check_id=f_dict.get("check_id", cr_dict.get("check_id", "")),
                affected_objects=f_dict.get("affected_objects", []),
                details=f_dict.get("details", {}),
                mitre=mitre,
                remediation=remediation,
                risk_points=f_dict.get("risk_points"),
            ))

        check_results.append(CheckResult(
            check_id=cr_dict.get("check_id", ""),
            check_name=cr_dict.get("check_name", ""),
            category=category,
            findings=findings,
            error=cr_dict.get("error"),
            duration_ms=cr_dict.get("duration_ms", 0.0),
        ))

    return ScanResult(
        scan_id=scan_dict.get("scan_id", ""),
        target_domain=scan_dict.get("target_domain", ""),
        run_as_user=scan_dict.get("run_as_user", ""),
        started_at=started_at,
        completed_at=completed_at,
        check_results=check_results,
        domain_info=domain_info,
    )


def _handle_history_trend(domain: str, db_path: str | None) -> None:
    path = db_path or "lazyhound_finder_history.db"
    with ScanHistory(path) as hist:
        trend = hist.trend(domain)
    if not trend:
        print(f"No history for domain: {domain}")
        return
    from ..finder_models import ScoringProfile
    print(f"\nScore trend for {domain}:")
    print(f"{'Date':<22} {'Score':>6} {'Rating':>12} {'Findings':>9}")
    print("─" * 56)
    for t in trend:
        rating = ScoringProfile.grade_to_rating(t['grade'])
        print(f"{t['started_at'][:19]:<22} {t['risk_score']:>6} "
              f"{rating:>12} {t['total_findings']:>9}")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    # Utility commands that don't require connection
    if args.list_checks:
        _handle_list_checks()
        return 0

    if args.history_list or args.history_diff or args.history_trend:
        hist_db = _resolve_history_db(getattr(args, "history_db", None),
                                      getattr(args, "config", None))
        if args.history_list:
            _handle_history_list(hist_db)
        elif args.history_diff:
            _handle_history_diff(args.history_diff[0], args.history_diff[1], hist_db)
        else:
            _handle_history_trend(args.history_trend, hist_db)
        return 0

    # Load config (file + CLI overrides)
    if args.config:
        config = AppConfig.from_yaml(args.config)
    else:
        config = AppConfig()

    # Merge CLI args over config
    cli_overrides: dict[str, object] = {}
    if args.dc:
        cli_overrides["connection.dc"] = args.dc
    if args.domain:
        cli_overrides["connection.domain"] = args.domain
    if args.username:
        cli_overrides["connection.username"] = args.username
    if args.password:
        cli_overrides["connection.password"] = args.password
    if args.nthash:
        cli_overrides["connection.nthash"] = args.nthash
    if args.auth:
        cli_overrides["connection.auth_method"] = args.auth
    if args.port is not None:
        cli_overrides["connection.port"] = args.port
    if args.ssl:
        cli_overrides["connection.use_ssl"] = True
        if args.port is None:
            cli_overrides["connection.port"] = 636
    if args.no_ssl:
        cli_overrides["connection.use_ssl"] = False
        if args.port is None:
            cli_overrides["connection.port"] = 389
    if args.no_starttls:
        cli_overrides["connection.use_start_tls"] = False
    if args.no_verify_cert:
        cli_overrides["connection.validate_cert"] = False
    if args.timeout is not None:
        cli_overrides["connection.timeout"] = args.timeout
    if args.include:
        cli_overrides["scan.include_checks"] = args.include
    if args.exclude:
        cli_overrides["scan.exclude_checks"] = args.exclude
    if args.categories:
        cli_overrides["scan.categories"] = args.categories
    if args.workers is not None:
        cli_overrides["scan.max_workers"] = args.workers
    if args.json_path:
        cli_overrides["output.json_path"] = args.json_path
    if args.html_path:
        cli_overrides["output.html_path"] = args.html_path
    if args.csv_path:
        cli_overrides["output.csv_path"] = args.csv_path
    if args.quiet:
        cli_overrides["output.quiet"] = True
    if args.no_history:
        cli_overrides["history.enabled"] = False
    if args.history_db:
        cli_overrides["history.db_path"] = args.history_db
    if args.score_profile:
        cli_overrides["scoring.profile"] = args.score_profile
    if args.log_dir:
        cli_overrides["logging.log_dir"] = args.log_dir
    if args.no_log:
        cli_overrides["logging.enabled"] = False

    config.merge_cli(**cli_overrides)

    # Cascade paths.base_dir into history DB, log dir, and report outputs so
    # nothing is written to a stray CWD when a project config is in use.
    config.apply_paths()

    # Activate the scoring profile
    from ..finder_models import set_scoring_profile, ScoringProfile, SCORING_PROFILES

    profile_name = config.scoring.profile
    if profile_name in SCORING_PROFILES:
        import copy
        profile = copy.copy(SCORING_PROFILES[profile_name])
    else:
        profile = ScoringProfile(name=profile_name)
    if config.scoring.curve is not None:
        profile.curve = config.scoring.curve
    if config.scoring.coefficient is not None:
        profile.coefficient = config.scoring.coefficient
    if config.scoring.health_weight is not None:
        profile.health_weight = config.scoring.health_weight
    if config.scoring.grade_thresholds is not None:
        profile.grade_thresholds = config.scoring.grade_thresholds
    if config.scoring.severity_points is not None:
        profile.severity_points = config.scoring.severity_points
    if config.scoring.category_weights is not None:
        profile.category_weights = config.scoring.category_weights
    set_scoring_profile(profile)

    # Validate required connection params
    missing = []
    if not config.connection.dc:
        missing.append("--dc")
    if not config.connection.domain:
        missing.append("--domain")
    if not config.connection.username:
        missing.append("--username / -u")
    if missing:
        parser.error(f"the following arguments are required: {', '.join(missing)}")

    if not config.connection.password and not config.connection.nthash:
        parser.error("either --password or --nthash is required")

    # Run scan
    from .scanner import Scanner

    try:
        scanner = Scanner(config)
        result = scanner.run()
        return 1 if result.risk_score >= 50 else 0  # non-zero exit for high risk
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 130
    except Exception as exc:
        logging.getLogger(__name__).exception("Scan failed")
        print(f"\nError: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

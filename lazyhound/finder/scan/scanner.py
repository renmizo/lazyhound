"""Scanner orchestrator — ties connectors, checks, and reports together."""

from __future__ import annotations

import io
import logging
import threading
from datetime import datetime, timezone
from typing import Any

from .checks.registry import CheckRegistry
from ..finder_config import AppConfig
from ..connectors.dns import DNSConnector
from ..connectors.ldap import LDAPConfig, LDAPConnector
from ..context import ScanContext
from ..finder_models import CheckCategory, DomainInfo, ScanResult
from lazyhound.finder.reports.console import ConsoleReport
from lazyhound.finder.reports.csv_report import CSVReport
from lazyhound.finder.reports.html_report import HTMLReport
from lazyhound.finder.reports.json_report import JSONReport
from lazyhound.finder.reports.markdown_report import MarkdownReport
from lazyhound.finder.storage.history import ScanHistory
from lazyhound.finder.storage.scan_log import ScanLogger

logger = logging.getLogger(__name__)


class Scanner:
    """End-to-end scan orchestrator."""

    def __init__(self, config: AppConfig, collection: dict | None = None) -> None:
        self.config = config
        self.registry = CheckRegistry.get_instance()
        self.cancel_event = threading.Event()
        self.collection = collection

    def _enrich(self, result: ScanResult) -> int:
        """Annotate findings with Tier-Zero reachability from a loaded collection."""
        if not self.collection:
            return 0
        from .enrich import enrich_findings
        findings = [f for cr in result.check_results for f in cr.findings]
        return enrich_findings(findings, self.collection)

    def run(self) -> ScanResult:
        """Execute a full scan and return the result."""
        # 0. Set up scan logging
        self._scan_logger: ScanLogger | None = None
        log_cfg = self.config.logging
        if log_cfg.enabled:
            self._scan_logger = ScanLogger(
                log_dir=log_cfg.log_dir,
                domain=self.config.connection.domain,
                scan_id="pending",  # will be updated
            )

        # 1. Discover check modules
        self.registry.discover_checks()

        # 2. Build LDAP connector
        conn_cfg = self.config.connection
        ldap_cfg = LDAPConfig(
            server=conn_cfg.dc,
            port=conn_cfg.port,
            use_ssl=conn_cfg.use_ssl,
            username=conn_cfg.username,
            password=conn_cfg.password,
            domain=conn_cfg.domain,
            auth_method=conn_cfg.auth_method,
            nthash=conn_cfg.nthash,
            ccache=conn_cfg.ccache,
            validate_cert=conn_cfg.validate_cert,
            timeout=conn_cfg.timeout,
            use_start_tls=conn_cfg.use_start_tls,
            auto_negotiate=conn_cfg.auto_negotiate,
        )
        ldap = LDAPConnector(config=ldap_cfg)
        ldap.connect()

        try:
            # 3. Optionally build DNS connector (#19: warn on failure)
            #    Use explicit nameserver if configured, otherwise fall back to DC.
            dns_conn: DNSConnector | None = None
            try:
                dns_conn = DNSConnector(
                    nameserver=conn_cfg.nameserver or conn_cfg.dc,
                    domain=conn_cfg.domain,
                )
            except Exception:
                logger.warning("DNS connector not available — DNS-dependent checks will be skipped")

            # 4. Build scan context
            domain_dn = ldap.base_dn
            domain_sid = ldap.get_domain_sid()
            if not domain_sid:
                logger.warning(
                    "Could not retrieve domain SID — ACL-based checks may produce incorrect results"
                )
            root_dse = ldap.get_root_dse()

            # #15: Resolve DC IP from hostname
            from ..finder_utils import resolve_ip
            dc_ip = resolve_ip(conn_cfg.dc, logger)

            # #4: Get configuration naming context from rootDSE (correct for child domains)
            config_naming_ctx = ""
            raw_config_nc = root_dse.get("configurationNamingContext", [])
            if raw_config_nc:
                config_naming_ctx = (
                    str(raw_config_nc[0]) if isinstance(raw_config_nc, list) else str(raw_config_nc)
                )

            ctx = ScanContext(
                ldap=ldap,
                dns=dns_conn,
                domain_dn=domain_dn,
                domain_sid=domain_sid,
                dc_hostname=conn_cfg.dc,
                dc_ip=dc_ip,
                domain_functional_level=_extract_functional_level(root_dse),
                forest_name=conn_cfg.domain,
                config_naming_ctx=config_naming_ctx,
            )

            # 5. Store scan context for --save-collection
            self._scan_context = ctx

            # 5. Run checks
            result = ScanResult(target_domain=conn_cfg.domain,
                                run_as_user=conn_cfg.username)
            scan_cfg = self.config.scan

            categories = None
            if scan_cfg.categories:
                categories = [
                    CheckCategory(c) for c in scan_cfg.categories
                    if c in {cat.value for cat in CheckCategory}
                ]

            result.check_results = self.registry.run_all(
                context=ctx,
                include=scan_cfg.include_checks or None,
                exclude=scan_cfg.exclude_checks or None,
                categories=categories,
                max_workers=scan_cfg.max_workers,
                cancel_event=self.cancel_event,
            )
            result.completed_at = datetime.now(timezone.utc)

            # 5b. Collection-aware enrichment: prioritise findings whose
            # affected principals can reach Tier Zero.
            enriched = self._enrich(result)
            if enriched:
                logger.info("Collection-aware: %d finding(s) touch Tier-Zero-reachable "
                            "principals", enriched)

            # 6. Collect domain info
            result.domain_info = _collect_domain_info(ctx, conn_cfg.domain, domain_dn, domain_sid)
        finally:
            # 7. Close LDAP — always, even on exception
            ldap.close()

        # 8. Set up file logging now that we have a scan_id
        if self._scan_logger:
            self._scan_logger.scan_id = result.scan_id
            try:
                log_path = self._scan_logger.open()
                self._scan_logger.info(f"Scan started for {result.target_domain}")
                logger.info("Scan log: %s", log_path)
            except Exception:
                logger.warning("Failed to open scan log", exc_info=True)
                self._scan_logger = None

        # 9. Reports
        self._emit_reports(result)

        # 10. History
        self._save_history(result)

        # 11. Finalize log
        if self._scan_logger:
            try:
                scan_dict = result.to_dict()
                self._scan_logger.write_summary(scan_dict)
                self._scan_logger.info("Scan completed")
                self._scan_logger.close()
            except Exception:
                logger.warning("Failed to finalize scan log", exc_info=True)

        return result

    def _emit_reports(self, result: ScanResult) -> None:
        out = self.config.output
        style = self.config.display.style
        if not out.quiet:
            # Capture console output to both stdout and the log file
            if self._scan_logger and self.config.logging.console_capture:
                capture = io.StringIO()
                ConsoleReport(stream=capture, style=style).render(result)
                console_text = capture.getvalue()
                import sys
                sys.stdout.write(console_text)
                self._scan_logger.capture_console(console_text)
            else:
                ConsoleReport(style=style).render(result)
        if out.json_path:
            path = JSONReport.write(result, out.json_path)
            logger.info("JSON report written to %s", path)
        if out.html_path:
            path = HTMLReport.write(result, out.html_path)
            logger.info("HTML report written to %s", path)
        if out.csv_path:
            path = CSVReport.write(result, out.csv_path)
            logger.info("CSV report written to %s", path)
        if out.markdown_path:
            path = MarkdownReport.write(result, out.markdown_path)
            logger.info("Markdown report written to %s", path)
        if out.save_collection_path:
            self._save_collection(out.save_collection_path)

    def _save_collection(self, path: str) -> None:
        """Save LDAP cache data as a collection JSON.

        Exports the scan context's cached LDAP queries as a collection
        JSON file compatible with the offline ``analyze`` / ``query`` commands.
        """
        try:
            import json
            from pathlib import Path

            ctx = getattr(self, "_scan_context", None)
            if ctx is None:
                logger.debug("No scan context available for collection export")
                return

            # Build a collection-compatible structure from cached LDAP data
            cache = getattr(ctx, "_cache", {})
            if not cache:
                logger.debug("Scan context cache is empty — nothing to save")
                return

            collection: dict = {
                "meta": {
                    "domain": self.config.connection.domain,
                    "dc": self.config.connection.dc,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "collection_method": "scan-export",
                    "source": "lazyhound scan --save-collection",
                },
                "objects": [],
                "sid_map": {},
            }

            # Export cached LDAP results — each cache entry is a list of dicts
            # with raw LDAP attributes.  Store them grouped by query key.
            for key, entries in cache.items():
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            collection["objects"].append({
                                "query_key": key,
                                **entry,
                            })

            collection["meta"]["object_count"] = len(collection["objects"])

            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(
                json.dumps(collection, indent=2, default=str),
                encoding="utf-8",
            )
            logger.info("Collection saved to %s", p)
        except Exception:
            logger.warning("Failed to save collection export", exc_info=True)

    def _save_history(self, result: ScanResult) -> None:
        hist_cfg = self.config.history
        if not hist_cfg.enabled:
            return
        db_path = hist_cfg.db_path or "lazyhound_finder_history.db"
        log_path = ""
        if self._scan_logger and self._scan_logger.log_path:
            log_path = str(self._scan_logger.log_path)
        try:
            with ScanHistory(db_path) as hist:
                hist.save(result.to_dict(), log_path=log_path)
        except Exception:
            logger.exception("Failed to save scan history")


_FUNCTIONAL_LEVEL_NAMES = {
    "0": "2000", "1": "2003 Interim", "2": "2003",
    "3": "2008", "4": "2008 R2", "5": "2012",
    "6": "2012 R2", "7": "2016",
}


def _extract_functional_level(root_dse: dict[str, Any]) -> str:
    """Return the raw numeric functional level string (e.g. '3', '7').

    Name resolution (e.g. '7' -> '2016') is done by consumers.
    """
    raw = root_dse.get("domainFunctionality", [""])[0] if root_dse else ""
    return str(raw)


def _collect_domain_info(
    ctx: ScanContext, domain: str, domain_dn: str, domain_sid: str
) -> DomainInfo:
    info = DomainInfo(
        domain=domain,
        domain_dn=domain_dn,
        domain_sid=domain_sid,
        forest_name=ctx.forest_name,
        dc_hostname=ctx.dc_hostname,
        dc_ip=ctx.dc_ip,
        functional_level=_FUNCTIONAL_LEVEL_NAMES.get(
            ctx.domain_functional_level, ctx.domain_functional_level
        ),
    )
    try:
        info.domain_controllers = [
            dc.get("dNSHostName") or dc.get("sAMAccountName", "?")
            for dc in ctx.get_domain_controllers()
        ]
    except Exception:
        pass
    try:
        users = ctx.ldap.search(
            "(&(objectClass=user)(!(objectClass=computer)))",
            ["cn"],
            search_base=domain_dn,
        )
        info.total_users = len(users)
    except Exception:
        pass
    try:
        computers = ctx.ldap.search(
            "(objectClass=computer)", ["cn"], search_base=domain_dn
        )
        info.total_computers = len(computers)
    except Exception:
        pass
    try:
        groups = ctx.ldap.search(
            "(objectClass=group)", ["cn"], search_base=domain_dn
        )
        info.total_groups = len(groups)
    except Exception:
        pass
    return info

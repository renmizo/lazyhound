"""File-based logging for scan and collection runs.

Creates one log file per run containing:
  - Structured logging messages (check start/pass/fail, errors)
  - Console report output (the full ANSI-stripped text)
  - Timestamps and run metadata

Log files are stored in a configurable directory with naming:
  lazyhound_scan_<domain>_<timestamp>_<id>.log
  lazyhound_collect_<domain>_<timestamp>_<id>.log
"""

from __future__ import annotations

import io
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ANSI escape sequence pattern for stripping from console capture
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return _ANSI_RE.sub("", text)


class _BaseRunLogger:
    """Shared plumbing for per-run file loggers."""

    _kind: str = "run"  # overridden by subclasses

    def __init__(
        self,
        log_dir: str | Path,
        domain: str,
        run_id: str,
    ) -> None:
        self.log_dir = Path(log_dir)
        self.domain = domain
        self.run_id = run_id
        self._file: io.TextIOWrapper | None = None
        self._file_handler: logging.FileHandler | None = None
        self.log_path: Path | None = None

    def open(self) -> Path:
        """Create the log file and attach a logging handler."""
        if self._file is not None:
            self.close()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_domain = self.domain.replace(".", "_")
        filename = f"lazyhound_{self._kind}_{safe_domain}_{ts}_{self.run_id}.log"
        self.log_path = self.log_dir / filename

        self._file = open(self.log_path, "w", encoding="utf-8")  # noqa: SIM115

        # Attach a file handler to the root lazyhound finder logger
        self._file_handler = logging.FileHandler(str(self.log_path), mode="a", encoding="utf-8")
        self._file_handler.setLevel(logging.DEBUG)
        self._file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logging.getLogger("lazyhound").addHandler(self._file_handler)

        self._write_header()
        return self.log_path

    def close(self) -> None:
        """Close the log file and detach the logging handler."""
        if self._file_handler:
            logging.getLogger("lazyhound").removeHandler(self._file_handler)
            self._file_handler.close()
            self._file_handler = None
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):  # type: ignore[override]
        self.open()
        return self

    def __exit__(self, *a: Any) -> None:
        self.close()

    def _write_header(self) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        title = f"LazyHound {self._kind.title()} Log"
        self._write(f"{'=' * 72}")
        self._write(title)
        self._write(f"Domain:   {self.domain}")
        self._write(f"ID:       {self.run_id}")
        self._write(f"Started:  {ts}")
        self._write(f"{'=' * 72}")
        self._write("")

    def _write(self, text: str) -> None:
        if self._file:
            self._file.write(text + "\n")
            self._file.flush()

    def info(self, msg: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self._write(f"[{ts}] INFO  {msg}")

    def error(self, msg: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self._write(f"[{ts}] ERROR {msg}")

    def warning(self, msg: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self._write(f"[{ts}] WARN  {msg}")

    def capture_console(self, console_text: str) -> None:
        """Append console report output (ANSI-stripped) to the log."""
        self._write("")
        self._write(f"{'─' * 72}")
        self._write("CONSOLE REPORT OUTPUT")
        self._write(f"{'─' * 72}")
        self._write(strip_ansi(console_text))


class ScanLogger(_BaseRunLogger):
    """Manages per-scan log files.

    Usage:
        log = ScanLogger("logs", "corp.local", "abc123")
        log.open()
        log.info("Starting scan...")
        log.capture_console(console_text)
        log.close()
    """

    _kind = "scan"

    # Backwards-compatible alias for run_id
    @property
    def scan_id(self) -> str:
        return self.run_id

    @scan_id.setter
    def scan_id(self, value: str) -> None:
        self.run_id = value

    def __init__(
        self,
        log_dir: str | Path,
        domain: str,
        scan_id: str,
    ) -> None:
        super().__init__(log_dir, domain, scan_id)

    def write_summary(self, scan_dict: dict[str, Any]) -> None:
        """Write a summary block from the scan result dict."""
        self._write("")
        self._write(f"{'─' * 72}")
        self._write("SCAN SUMMARY")
        self._write(f"{'─' * 72}")
        self._write(f"Risk Score:      {scan_dict.get('risk_score', '?')}/100")
        from ..finder_models import ScoringProfile
        rating = ScoringProfile.grade_to_rating(scan_dict.get('grade', '?'))
        self._write(f"Rating:          {rating}")
        self._write(f"Scoring Profile: {scan_dict.get('scoring_profile', '?')}")
        self._write(f"Total Findings:  {scan_dict.get('total_findings', '?')}")
        self._write(f"Risk Points:     {scan_dict.get('total_risk_points', '?')} raw, "
                     f"{scan_dict.get('weighted_risk_points', '?')} weighted")
        self._write(f"Checks Passed:   {scan_dict.get('checks_passed', '?')}")
        self._write(f"Checks Failed:   {scan_dict.get('checks_failed', '?')}")
        self._write(f"Duration:        {scan_dict.get('duration_ms', '?')} ms")
        self._write("")


class CollectionLogger(_BaseRunLogger):
    """Manages per-collection log files.

    Usage:
        log = CollectionLogger("logs", "corp.local", "abc123")
        log.open()
        log.info("Starting LDAP collection...")
        log.write_summary(stats)
        log.close()
    """

    _kind = "collect"

    # Backwards-compatible alias for run_id
    @property
    def collection_id(self) -> str:
        return self.run_id

    @collection_id.setter
    def collection_id(self, value: str) -> None:
        self.run_id = value

    def __init__(
        self,
        log_dir: str | Path,
        domain: str,
        collection_id: str,
    ) -> None:
        super().__init__(log_dir, domain, collection_id)

    def write_summary(
        self,
        *,
        object_count: int = 0,
        sessions: int = 0,
        local_group_members: int = 0,
        network_hosts_scanned: int = 0,
        network_hosts_failed: int = 0,
        duration_ms: float = 0,
        output_file: str = "",
    ) -> None:
        """Write a summary block from collection stats."""
        self._write("")
        self._write(f"{'─' * 72}")
        self._write("COLLECTION SUMMARY")
        self._write(f"{'─' * 72}")
        self._write(f"Objects:              {object_count}")
        if sessions or local_group_members:
            self._write(f"Sessions:             {sessions}")
            self._write(f"Local Group Members:  {local_group_members}")
            self._write(f"Hosts Scanned:        {network_hosts_scanned}")
            if network_hosts_failed:
                self._write(f"Hosts Failed:         {network_hosts_failed}")
        if duration_ms:
            self._write(f"Duration:             {duration_ms:.0f} ms")
        if output_file:
            self._write(f"Output:               {output_file}")
        self._write("")

"""SQLite-backed scan history and collection storage."""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_DB = "lazyhound_finder_history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    run_as_user TEXT NOT NULL DEFAULT '',
    started_at  TEXT NOT NULL,
    completed_at TEXT,
    risk_score  INTEGER,
    grade       TEXT,
    total_findings INTEGER,
    total_risk_points INTEGER,
    weighted_risk_points REAL,
    checks_passed INTEGER,
    checks_failed INTEGER,
    duration_ms  REAL,
    raw_json    TEXT NOT NULL,
    log_path    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);

CREATE TABLE IF NOT EXISTS collections (
    collection_id     TEXT PRIMARY KEY,
    domain            TEXT NOT NULL,
    run_as_user       TEXT NOT NULL DEFAULT '',
    dc                TEXT,
    collected_at      TEXT NOT NULL,
    object_count      INTEGER NOT NULL,
    collection_method TEXT,
    data              BLOB NOT NULL,
    log_path          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_collections_domain ON collections(domain);
CREATE INDEX IF NOT EXISTS idx_collections_collected ON collections(collected_at);

CREATE TABLE IF NOT EXISTS command_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    submenu     TEXT NOT NULL DEFAULT '',
    command     TEXT NOT NULL,
    args        TEXT NOT NULL DEFAULT '',
    duration_ms REAL,
    status      TEXT NOT NULL DEFAULT 'ok'
);

CREATE INDEX IF NOT EXISTS idx_command_log_ts ON command_log(timestamp);

CREATE TABLE IF NOT EXISTS marks (
    object_sid   TEXT NOT NULL,
    domain       TEXT NOT NULL DEFAULT '',
    label        TEXT NOT NULL DEFAULT 'owned',
    display_name TEXT NOT NULL DEFAULT '',
    marked_at    TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (object_sid, label)
);

CREATE INDEX IF NOT EXISTS idx_marks_label ON marks(label);
CREATE INDEX IF NOT EXISTS idx_marks_domain ON marks(domain);
"""


@dataclass
class ScanSummary:
    """Lightweight summary of a stored scan."""

    scan_id: str
    domain: str
    run_as_user: str
    started_at: str
    risk_score: int
    grade: str
    total_findings: int

    @property
    def rating(self) -> str:
        """Human-readable rating label."""
        from ..finder_models import ScoringProfile
        return ScoringProfile.grade_to_rating(self.grade)


@dataclass
class CollectionSummary:
    """Lightweight summary of a stored collection."""

    collection_id: str
    domain: str
    run_as_user: str
    dc: str | None
    collected_at: str
    object_count: int
    collection_method: str | None


@dataclass
class ScanDiff:
    """Difference between two scans."""

    old_scan_id: str
    new_scan_id: str
    score_delta: int
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    unchanged_count: int = 0


@dataclass
class MarkEntry:
    """A persistent mark on an AD object (owned, high-value, target, etc.)."""

    object_sid: str
    domain: str
    label: str
    display_name: str
    marked_at: str
    notes: str


class ScanHistory:
    """Manages scan history in a SQLite database."""

    def __init__(self, db_path: str | Path = DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate(self._conn)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> ScanHistory:
        self.open()
        return self

    def __exit__(self, *a: Any) -> None:
        self.close()

    def _ensure_open(self) -> sqlite3.Connection:
        if not self._conn:
            raise RuntimeError("History DB not open")
        return self._conn

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns introduced after the initial schema."""
        for table in ("scans", "collections"):
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if "run_as_user" not in cols:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN run_as_user TEXT NOT NULL DEFAULT ''"
                )
                conn.commit()
            if "log_path" not in cols:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN log_path TEXT NOT NULL DEFAULT ''"
                )
                conn.commit()

    # -- storage --

    def save(self, scan_dict: dict[str, Any], log_path: str = "") -> None:
        """Save a scan result dict to history."""
        conn = self._ensure_open()
        try:
            conn.execute(
                """INSERT INTO scans
                   (scan_id, domain, run_as_user, started_at, completed_at,
                    risk_score, grade, total_findings, total_risk_points,
                    weighted_risk_points, checks_passed, checks_failed,
                    duration_ms, raw_json, log_path)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_dict["scan_id"],
                    scan_dict["target_domain"],
                    scan_dict.get("run_as_user", ""),
                    scan_dict["started_at"],
                    scan_dict.get("completed_at"),
                    scan_dict["risk_score"],
                    scan_dict["grade"],
                    scan_dict["total_findings"],
                    scan_dict["total_risk_points"],
                    scan_dict["weighted_risk_points"],
                    scan_dict["checks_passed"],
                    scan_dict["checks_failed"],
                    scan_dict["duration_ms"],
                    json.dumps(scan_dict, default=str),
                    log_path,
                ),
            )
        except sqlite3.IntegrityError:
            logger.warning(
                "Scan %s already exists in history — skipping duplicate",
                scan_dict["scan_id"],
            )
            return
        conn.commit()
        logger.info("Saved scan %s to history", scan_dict["scan_id"])

    # -- retrieval --

    def list_scans(self, domain: str | None = None, limit: int = 20) -> list[ScanSummary]:
        conn = self._ensure_open()
        if domain:
            rows = conn.execute(
                "SELECT scan_id, domain, run_as_user, started_at, risk_score, "
                "grade, total_findings "
                "FROM scans WHERE domain = ? ORDER BY started_at DESC LIMIT ?",
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT scan_id, domain, run_as_user, started_at, risk_score, "
                "grade, total_findings "
                "FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            ScanSummary(
                scan_id=r["scan_id"],
                domain=r["domain"],
                run_as_user=r["run_as_user"],
                started_at=r["started_at"],
                risk_score=r["risk_score"],
                grade=r["grade"],
                total_findings=r["total_findings"],
            )
            for r in rows
        ]

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        conn = self._ensure_open()
        row = conn.execute(
            "SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row:
            return json.loads(row["raw_json"])
        return None

    def get_latest(self, domain: str) -> dict[str, Any] | None:
        conn = self._ensure_open()
        row = conn.execute(
            "SELECT raw_json FROM scans WHERE domain = ? ORDER BY started_at DESC LIMIT 1",
            (domain,),
        ).fetchone()
        if row:
            return json.loads(row["raw_json"])
        return None

    # -- diffing --

    def diff(self, old_id: str, new_id: str) -> ScanDiff | None:
        """Compare two scans and return the delta."""
        old = self.get_scan(old_id)
        new = self.get_scan(new_id)
        if not old or not new:
            return None

        old_findings = _extract_finding_keys(old)
        new_findings = _extract_finding_keys(new)

        old_keys = set(old_findings.keys())
        new_keys = set(new_findings.keys())

        resolved = [old_findings[k] for k in old_keys - new_keys]
        added = [new_findings[k] for k in new_keys - old_keys]
        unchanged = len(old_keys & new_keys)

        return ScanDiff(
            old_scan_id=old_id,
            new_scan_id=new_id,
            score_delta=new.get("risk_score", 0) - old.get("risk_score", 0),
            new_findings=added,
            resolved_findings=resolved,
            unchanged_count=unchanged,
        )

    def trend(self, domain: str, limit: int = 10) -> list[dict[str, Any]]:
        """Return risk score trend for a domain."""
        conn = self._ensure_open()
        rows = conn.execute(
            "SELECT scan_id, started_at, risk_score, grade, total_findings "
            "FROM scans WHERE domain = ? ORDER BY started_at DESC LIMIT ?",
            (domain, limit),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    # -- collection storage -------------------------------------------------

    def save_collection(self, collection_data: dict[str, Any],
                        collection_id: str | None = None,
                        log_path: str = "") -> str:
        """Store a collection dict in the database (zlib-compressed).

        Returns the assigned *collection_id*.
        """
        conn = self._ensure_open()
        meta = collection_data.get("meta", {})
        cid = collection_id or str(uuid.uuid4())[:12]
        blob = zlib.compress(
            json.dumps(collection_data, default=str).encode(), level=6,
        )
        try:
            conn.execute(
                """INSERT INTO collections
                   (collection_id, domain, run_as_user, dc, collected_at,
                    object_count, collection_method, data, log_path)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    cid,
                    meta.get("domain", "unknown"),
                    meta.get("run_as_user", ""),
                    meta.get("dc"),
                    meta.get("collected_at", datetime.now(timezone.utc).isoformat()),
                    meta.get("object_count", len(collection_data.get("objects", []))),
                    meta.get("collection_method"),
                    blob,
                    log_path,
                ),
            )
        except sqlite3.IntegrityError:
            logger.warning("Collection %s already exists — skipping", cid)
            return cid
        conn.commit()
        logger.info("Saved collection %s (%d bytes compressed)", cid, len(blob))
        return cid

    def update_collection(self, collection_id: str,
                          collection_data: dict[str, Any]) -> bool:
        """Update an existing collection's data and metadata in-place.

        Returns True if a row was updated.
        """
        conn = self._ensure_open()
        meta = collection_data.get("meta", {})
        blob = zlib.compress(
            json.dumps(collection_data, default=str).encode(), level=6,
        )
        cursor = conn.execute(
            """UPDATE collections
               SET data = ?, object_count = ?, collection_method = ?
               WHERE collection_id = ?""",
            (
                blob,
                meta.get("object_count", len(collection_data.get("objects", []))),
                meta.get("collection_method"),
                collection_id,
            ),
        )
        conn.commit()
        updated = cursor.rowcount > 0
        if updated:
            logger.info("Updated collection %s (%d bytes compressed)",
                        collection_id, len(blob))
        return updated

    def list_collections(self, domain: str | None = None,
                         limit: int = 20) -> list[CollectionSummary]:
        """List stored collections, newest first."""
        conn = self._ensure_open()
        if domain:
            rows = conn.execute(
                "SELECT collection_id, domain, run_as_user, dc, collected_at, "
                "object_count, collection_method FROM collections "
                "WHERE domain = ? ORDER BY collected_at DESC LIMIT ?",
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT collection_id, domain, run_as_user, dc, collected_at, "
                "object_count, collection_method FROM collections "
                "ORDER BY collected_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            CollectionSummary(
                collection_id=r["collection_id"],
                domain=r["domain"],
                run_as_user=r["run_as_user"],
                dc=r["dc"],
                collected_at=r["collected_at"],
                object_count=r["object_count"],
                collection_method=r["collection_method"],
            )
            for r in rows
        ]

    def get_collection(self, collection_id: str) -> dict[str, Any] | None:
        """Retrieve and decompress a stored collection by ID."""
        conn = self._ensure_open()
        row = conn.execute(
            "SELECT data FROM collections WHERE collection_id = ?",
            (collection_id,),
        ).fetchone()
        if row:
            return json.loads(zlib.decompress(row["data"]))
        return None

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan by ID. Returns True if a row was deleted."""
        conn = self._ensure_open()
        cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Deleted scan %s", scan_id)
        return deleted

    def delete_collection(self, collection_id: str) -> bool:
        """Delete a collection by ID. Returns True if a row was deleted."""
        conn = self._ensure_open()
        cursor = conn.execute(
            "DELETE FROM collections WHERE collection_id = ?", (collection_id,),
        )
        conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Deleted collection %s", collection_id)
        return deleted

    def get_latest_collection(self, domain: str) -> dict[str, Any] | None:
        """Get the most recent collection for a domain."""
        conn = self._ensure_open()
        row = conn.execute(
            "SELECT data FROM collections WHERE domain = ? "
            "ORDER BY collected_at DESC LIMIT 1",
            (domain,),
        ).fetchone()
        if row:
            return json.loads(zlib.decompress(row["data"]))
        return None

    # -- log_path retrieval -------------------------------------------------

    def get_scan_log_path(self, scan_id: str) -> str:
        """Return the log_path for a scan, or empty string."""
        conn = self._ensure_open()
        row = conn.execute(
            "SELECT log_path FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return row["log_path"] if row else ""

    def get_collection_log_path(self, collection_id: str) -> str:
        """Return the log_path for a collection, or empty string."""
        conn = self._ensure_open()
        row = conn.execute(
            "SELECT log_path FROM collections WHERE collection_id = ?",
            (collection_id,),
        ).fetchone()
        return row["log_path"] if row else ""

    # -- command audit log --------------------------------------------------

    def log_command(
        self,
        submenu: str,
        command: str,
        args: str = "",
        duration_ms: float | None = None,
        status: str = "ok",
    ) -> None:
        """Record a shell command execution."""
        conn = self._ensure_open()
        conn.execute(
            """INSERT INTO command_log (timestamp, submenu, command, args, duration_ms, status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                submenu,
                command,
                args,
                duration_ms,
                status,
            ),
        )
        conn.commit()

    # -- object marks (owned / high-value / target) -------------------------

    def add_mark(
        self,
        object_sid: str,
        label: str = "owned",
        display_name: str = "",
        domain: str = "",
        notes: str = "",
    ) -> None:
        """Mark an AD object with a persistent label (owned, high-value, target, etc.)."""
        conn = self._ensure_open()
        conn.execute(
            """INSERT OR REPLACE INTO marks
               (object_sid, domain, label, display_name, marked_at, notes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                object_sid,
                domain,
                label,
                display_name,
                datetime.now(timezone.utc).isoformat(),
                notes,
            ),
        )
        conn.commit()

    def remove_mark(self, object_sid: str, label: str | None = None) -> int:
        """Remove mark(s) for an object. If label is None, remove all labels."""
        conn = self._ensure_open()
        if label:
            cursor = conn.execute(
                "DELETE FROM marks WHERE object_sid = ? AND label = ?",
                (object_sid, label),
            )
        else:
            cursor = conn.execute(
                "DELETE FROM marks WHERE object_sid = ?", (object_sid,)
            )
        conn.commit()
        return cursor.rowcount

    def list_marks(
        self,
        label: str | None = None,
        domain: str | None = None,
    ) -> list[MarkEntry]:
        """List marked objects, optionally filtered by label and/or domain."""
        conn = self._ensure_open()
        clauses: list[str] = []
        params: list[str] = []
        if label:
            clauses.append("label = ?")
            params.append(label)
        if domain:
            clauses.append("domain = ?")
            params.append(domain)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            f"SELECT object_sid, domain, label, display_name, marked_at, notes "
            f"FROM marks{where} ORDER BY marked_at DESC",
            params,
        ).fetchall()
        return [
            MarkEntry(
                object_sid=r["object_sid"],
                domain=r["domain"],
                label=r["label"],
                display_name=r["display_name"],
                marked_at=r["marked_at"],
                notes=r["notes"],
            )
            for r in rows
        ]

    def get_marked_sids(self, label: str = "owned", domain: str | None = None) -> set[str]:
        """Return all SIDs with a given label (fast lookup for analysis)."""
        conn = self._ensure_open()
        if domain:
            rows = conn.execute(
                "SELECT object_sid FROM marks WHERE label = ? AND domain = ?",
                (label, domain),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT object_sid FROM marks WHERE label = ?", (label,)
            ).fetchall()
        return {r["object_sid"] for r in rows}

    def clear_marks(self, label: str | None = None, domain: str | None = None) -> int:
        """Clear all marks, optionally filtered by label and/or domain."""
        conn = self._ensure_open()
        clauses: list[str] = []
        params: list[str] = []
        if label:
            clauses.append("label = ?")
            params.append(label)
        if domain:
            clauses.append("domain = ?")
            params.append(domain)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        cursor = conn.execute(f"DELETE FROM marks{where}", params)
        conn.commit()
        return cursor.rowcount

    # -- command audit log --------------------------------------------------

    def list_commands(
        self,
        *,
        since: str | None = None,
        command: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query the command audit log."""
        conn = self._ensure_open()
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if command:
            clauses.append("command = ?")
            params.append(command)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM command_log{where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def _extract_finding_keys(scan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build a dict keyed by (check_id, title) for diffing."""
    findings: dict[str, dict[str, Any]] = {}
    for cr in scan.get("check_results", []):
        for f in cr.get("findings", []):
            key = f"{f.get('check_id', '')}:{f.get('title', '')}"
            findings[key] = f
    return findings

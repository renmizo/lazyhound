"""SQLite-backed local store for shell state, options, identities, and the
scan index / command audit log (``lazyhound_history.db``)."""

from __future__ import annotations

import json
import sqlite3
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any


class HistoryStore:
    """Persistent per-project store for shell state and history.

    Holds the operator's saved ``options`` (shell_state), the command audit
    log (command_log), saved credential identities (identities), and a
    lightweight scan index (scans; full scan data lives in the finder DB).
    """

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_tables(self) -> None:
        c = self._conn
        c.executescript("""
            CREATE TABLE IF NOT EXISTS command_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT NOT NULL,
                submenu    TEXT DEFAULT '',
                command    TEXT NOT NULL,
                args       TEXT DEFAULT '',
                duration   REAL DEFAULT 0,
                status     TEXT DEFAULT 'ok'
            );

            CREATE TABLE IF NOT EXISTS identities (
                identity_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                domain         TEXT DEFAULT '',
                username       TEXT NOT NULL,
                password       TEXT DEFAULT '',
                nthash         TEXT DEFAULT '',
                cred_type      TEXT DEFAULT 'password',
                source         TEXT DEFAULT 'manual',
                source_action  TEXT DEFAULT '',
                discovered_at  TEXT NOT NULL,
                is_active      INTEGER DEFAULT 0,
                admin_on_json  TEXT DEFAULT '[]',
                notes          TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_identity_domain ON identities(domain);
            CREATE INDEX IF NOT EXISTS idx_identity_user ON identities(username);

            CREATE TABLE IF NOT EXISTS shell_state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                domain      TEXT DEFAULT '',
                score       REAL DEFAULT 0,
                grade       TEXT DEFAULT '',
                findings    INTEGER DEFAULT 0,
                checks_run  INTEGER DEFAULT 0,
                started_at  TEXT NOT NULL,
                completed_at TEXT DEFAULT '',
                result_json BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_scan_domain ON scans(domain);
        """)
        c.commit()

    # ------------------------------------------------------------------
    # Command audit log
    # ------------------------------------------------------------------

    def log_command(self, submenu: str, command: str, args: str = "",
                    duration: float = 0.0, status: str = "ok") -> None:
        self._conn.execute(
            "INSERT INTO command_log (timestamp, submenu, command, args, duration, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), submenu, command, args, duration, status),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Identities (saved credentials)
    # ------------------------------------------------------------------

    @staticmethod
    def detect_cred_type(username: str, password: str = "",
                         nthash: str = "", source: str = "") -> str:
        """Auto-detect the credential type from the supplied secret."""
        if username.endswith("$"):
            return "machine"
        if nthash and len(nthash) == 32:
            return "nthash"
        if password:
            return "password"
        if source == "responder" and not password:
            return "ntlmv2"
        return "password"

    def save_identity(self, domain: str, username: str,
                      password: str = "", nthash: str = "",
                      source: str = "manual", source_action: str = "",
                      notes: str = "", cred_type: str = "") -> int:
        """Store a discovered/entered identity. Returns the identity_id."""
        if not cred_type:
            cred_type = self.detect_cred_type(username, password, nthash, source)

        existing = self._conn.execute(
            "SELECT identity_id FROM identities WHERE domain=? AND username=?",
            (domain, username),
        ).fetchone()
        if existing:
            updates, params = [], []  # type: list[str], list[Any]
            if password:
                updates.append("password=?"); params.append(password)
            if nthash:
                updates.append("nthash=?"); params.append(nthash)
            if source:
                updates.append("source=?"); params.append(source)
            if cred_type:
                updates.append("cred_type=?"); params.append(cred_type)
            if updates:
                params.append(existing[0])
                self._conn.execute(
                    f"UPDATE identities SET {', '.join(updates)} WHERE identity_id=?",
                    params,
                )
                self._conn.commit()
            return existing[0]

        cur = self._conn.execute(
            "INSERT INTO identities "
            "(domain, username, password, nthash, cred_type, source, source_action, "
            "discovered_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (domain, username, password, nthash, cred_type, source, source_action,
             datetime.utcnow().isoformat(), notes),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    # ------------------------------------------------------------------
    # Scan index (lightweight; full data lives in the finder DB)
    # ------------------------------------------------------------------

    def save_scan(self, scan_id: str, domain: str, score: float,
                  grade: str, findings: int, checks_run: int,
                  started_at: str, completed_at: str = "",
                  result_json: str = "") -> None:
        result_blob = zlib.compress(result_json.encode("utf-8")) if result_json else b""
        self._conn.execute(
            "INSERT OR REPLACE INTO scans "
            "(scan_id, domain, score, grade, findings, checks_run, "
            "started_at, completed_at, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, domain, score, grade, findings, checks_run,
             started_at, completed_at, result_blob),
        )
        self._conn.commit()

    def list_scans(self, domain: str = "", limit: int = 50) -> list[dict]:
        sql = ("SELECT scan_id, domain, score, grade, findings, checks_run, "
               "started_at, completed_at FROM scans")
        params: list[Any] = []
        if domain:
            sql += " WHERE domain=?"
            params.append(domain)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def delete_scan(self, scan_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Shell state / options (persisted key-value)
    # ------------------------------------------------------------------

    def save_state(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO shell_state (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    def get_state(self, key: str, default: str = "") -> str:
        row = self._conn.execute(
            "SELECT value FROM shell_state WHERE key=?", (key,),
        ).fetchone()
        return row[0] if row else default

    def save_options(self, options: dict) -> None:
        """Persist all shell options."""
        self.save_state("shell_options", json.dumps(
            {k: str(v) for k, v in options.items()}
        ))

    def load_options(self) -> dict:
        """Load persisted shell options."""
        raw = self.get_state("shell_options", "{}")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()


# Backwards-compatible alias (the store was formerly named ValidationHistory).
ValidationHistory = HistoryStore

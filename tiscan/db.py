"""SQLite storage: API response cache (with stale fallback) and scan history."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    expires REAL NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc            TEXT NOT NULL,
    type           TEXT NOT NULL,
    mode           TEXT NOT NULL,
    risk           INTEGER,
    risk_level     TEXT,
    exposure       INTEGER,
    exposure_level TEXT,
    created        REAL NOT NULL,
    report         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_created ON scans(created DESC);
CREATE INDEX IF NOT EXISTS scans_ioc ON scans(ioc);
CREATE TABLE IF NOT EXISTS watchlist (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    value          TEXT NOT NULL UNIQUE,
    type           TEXT NOT NULL,
    label          TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created        REAL NOT NULL,
    last_checked   REAL,
    last_scan_id   INTEGER,
    risk           INTEGER,
    risk_level     TEXT,
    exposure       INTEGER,
    exposure_level TEXT,
    known_findings INTEGER NOT NULL DEFAULT 0,
    state          TEXT,
    last_error     TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id  INTEGER,
    value     TEXT NOT NULL,
    kind      TEXT NOT NULL,
    level     TEXT NOT NULL,
    title     TEXT NOT NULL,
    findings  TEXT NOT NULL,
    scan_id   INTEGER,
    created   REAL NOT NULL,
    delivery  TEXT
);
CREATE INDEX IF NOT EXISTS alerts_created ON alerts(created DESC);
"""

# Expired cache rows are kept this long so a source that is down or rate-limited can serve stale data.
STALE_KEEP_SECONDS = 7 * 86400


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- cache -------------------------------------------------------------------------------
    def cache_get(self, key: str, allow_stale: bool = False) -> tuple[str, bool] | None:
        """Return (value, is_fresh) or None. Stale rows are only returned when allow_stale is set."""
        with self._lock:
            row = self._conn.execute("SELECT value, expires FROM cache WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        fresh = row["expires"] > time.time()
        if not fresh and not allow_stale:
            return None
        return row["value"], fresh

    def cache_set(self, key: str, value: str, ttl: float) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires, created) VALUES (?, ?, ?, ?)",
                (key, value, now + ttl, now),
            )

    def cache_clear(self) -> int:
        with self._lock:
            return self._conn.execute("DELETE FROM cache").rowcount

    def cache_stats(self) -> dict:
        now = time.time()
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            fresh = self._conn.execute("SELECT COUNT(*) FROM cache WHERE expires > ?", (now,)).fetchone()[0]
        return {"entries": total, "fresh": fresh, "stale": total - fresh}

    def purge(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM cache WHERE expires < ?", (time.time() - STALE_KEEP_SECONDS,))

    # ---- scan history ------------------------------------------------------------------------
    def save_scan(self, report: dict) -> int:
        risk = report.get("risk") or {}
        exposure = report.get("exposure") or {}
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (ioc, type, mode, risk, risk_level, exposure, exposure_level, created, report)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report["ioc"]["value"], report["ioc"]["type"], report["mode"],
                    risk.get("score"), risk.get("level"), exposure.get("score"), exposure.get("level"),
                    time.time(), json.dumps(report, default=str),
                ),
            )
            return int(cur.lastrowid)

    def list_scans(self, limit: int = 100, offset: int = 0, query: str = "") -> dict:
        where, args = "", []
        if query:
            where = "WHERE ioc LIKE ? ESCAPE '\\'"
            args.append("%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM scans {where}", args).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT id, ioc, type, mode, risk, risk_level, exposure, exposure_level, created"
                f" FROM scans {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}

    def get_scan(self, scan_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT id, report FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        report = json.loads(row["report"])
        report["id"] = row["id"]
        return report

    def get_scans(self, ids: list[int]) -> list[dict]:
        return [r for r in (self.get_scan(i) for i in ids) if r is not None]

    def delete_scan(self, scan_id: int) -> bool:
        with self._lock:
            return self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0

    def clear_scans(self) -> int:
        with self._lock:
            return self._conn.execute("DELETE FROM scans").rowcount

    def scan_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    # ---- watchlist ---------------------------------------------------------------------------
    def add_watch(self, value: str, ioc_type: str, label: str | None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO watchlist (value, type, label, created) VALUES (?, ?, ?, ?)",
                (value, ioc_type, label, time.time()),
            )
            return int(cur.lastrowid)

    def list_watch(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM watchlist ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def get_watch(self, watch_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM watchlist WHERE id = ?", (watch_id,)).fetchone()
        return dict(row) if row else None

    def set_watch_enabled(self, watch_id: int, enabled: bool) -> bool:
        with self._lock:
            return self._conn.execute("UPDATE watchlist SET enabled = ? WHERE id = ?",
                                      (int(enabled), watch_id)).rowcount > 0

    def delete_watch(self, watch_id: int) -> bool:
        with self._lock:
            return self._conn.execute("DELETE FROM watchlist WHERE id = ?", (watch_id,)).rowcount > 0

    def save_watch_check(self, watch_id: int, report: dict, state: dict) -> None:
        risk, exposure = report.get("risk") or {}, report.get("exposure") or {}
        with self._lock:
            self._conn.execute(
                "UPDATE watchlist SET last_checked = ?, last_scan_id = ?, risk = ?, risk_level = ?, exposure = ?,"
                " exposure_level = ?, known_findings = ?, state = ?, last_error = NULL WHERE id = ?",
                (time.time(), report.get("id"), risk.get("score"), risk.get("level"), exposure.get("score"),
                 exposure.get("level"), len(state.get("seen", {})), json.dumps(state), watch_id),
            )

    def set_watch_state(self, watch_id: int, state: dict) -> None:
        with self._lock:
            self._conn.execute("UPDATE watchlist SET state = ?, known_findings = ? WHERE id = ?",
                               (json.dumps(state), len(state.get("seen", {})), watch_id))

    def save_watch_error(self, watch_id: int, error: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE watchlist SET last_checked = ?, last_error = ? WHERE id = ?",
                               (time.time(), error[:300], watch_id))

    # ---- alerts ------------------------------------------------------------------------------
    def add_alert(self, alert: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (watch_id, value, kind, level, title, findings, scan_id, created, delivery)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (alert.get("watch_id"), alert["value"], alert["kind"], alert["level"], alert["title"],
                 json.dumps(alert.get("findings", [])), alert.get("scan_id"), time.time(),
                 json.dumps(alert.get("delivery", {}))),
            )
            return int(cur.lastrowid)

    def list_alerts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["findings"] = json.loads(item["findings"] or "[]")
            item["delivery"] = json.loads(item["delivery"] or "{}")
            out.append(item)
        return out

    def clear_alerts(self) -> int:
        with self._lock:
            return self._conn.execute("DELETE FROM alerts").rowcount

"""Continuous monitoring: re-scan watched assets on a schedule and alert only on NEW findings.

Each check runs a normal TIScan scan, turns the report into a set of findings (ransomware leak post,
infostealer infection, breach, onion mention, blocklisting...) and diffs them against everything
already seen for that asset. A finding is alerted once; counters (e.g. compromised employees)
alert when they grow; risk/exposure levels alert when they rise to medium or worse.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from .config import settings
from .db import Database
from .engine import Engine
from .ioc import detect
from .notify import Notifier

log = logging.getLogger("tiscan")

WATCH_TYPES = {"domain", "email", "ip", "keyword"}
LEVEL_RANK = {"unknown": -1, "clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
METRIC_LABELS = {
    "infostealer_employees": ("Infostealer-compromised employees", "critical"),
    "infostealer_users": ("Infostealer-compromised users / customers", "medium"),
}
MAX_SEEN = 3000
MAX_LISTED = 15


def scan_mode(ioc_type: str) -> str:
    return "darkweb" if ioc_type == "keyword" else "full"


def _f(text: str, severity: str) -> dict:
    return {"text": text, "severity": severity}


def extract_findings(report: dict) -> tuple[dict[str, dict], dict[str, int]]:
    """Turn a scan report into {stable finding key: finding} plus numeric metrics."""
    findings: dict[str, dict] = {}
    metrics: dict[str, int] = {}
    for r in report.get("results", []):
        if r.get("status") not in ("ok", "not_found"):
            continue
        sid, data = r.get("source"), r.get("data") or {}
        if r.get("category") != "darkweb":
            if r.get("verdict") in ("malicious", "suspicious"):
                findings[f"flag:{sid}"] = _f(f"{r['name']}: {r.get('summary', '')}",
                                             "high" if r["verdict"] == "malicious" else "medium")
            continue
        if sid == "ransomware_live":
            for row in data.get("Listings") or []:
                confirmed = row.get("match") != "name only"
                text = f'Ransomware leak site: "{row.get("victim")}" posted by {row.get("group")} on {row.get("date")}'
                findings[f"rw:{row.get('group')}:{row.get('victim')}".lower()] = _f(
                    text if confirmed else text + " (name match - verify)", "critical" if confirmed else "medium")
        elif sid == "hudsonrock":
            if "Compromised employees" in data:
                metrics["infostealer_employees"] = int(data.get("Compromised employees") or 0)
                metrics["infostealer_users"] = int(data.get("Compromised users / customers") or 0)
            for row in data.get("Infections") or []:
                findings[f"stealer:{row.get('computer')}:{row.get('compromised')}".lower()] = _f(
                    f"Infostealer infection on {row.get('computer')} ({row.get('os') or 'unknown OS'}), "
                    f"compromised {row.get('compromised')}", "critical")
        elif sid == "leakcheck":
            for row in data.get("Breach sources") or []:
                name = str(row.get("breach") or "")
                findings[f"breach:{name}".lower()] = _f(f"Data breach: {name} ({row.get('date')})",
                                                        "high" if "stealer" in name.lower() else "medium")
        elif sid == "xposedornot":
            for name in data.get("Breach names") or []:
                findings[f"breach:{name}".lower()] = _f(f"Data breach: {name}", "medium")
        elif sid == "hibp":
            for row in data.get("Breach list") or []:
                findings[f"breach:{row.get('breach')}".lower()] = _f(
                    f"Data breach: {row.get('breach')} ({row.get('date')}) - {row.get('data')}", "high")
        elif sid == "ahmia":
            for row in data.get("Pages") or []:
                findings[f"onion:{row.get('url') or row.get('onion')}".lower()] = _f(
                    f"Mentioned on a Tor site: {row.get('title')} ({row.get('onion')})", "medium")
    return findings, metrics


def diff(prev: dict, findings: dict[str, dict], metrics: dict[str, int], report: dict) -> tuple[list[dict], dict]:
    """Return (new findings, next state). Findings are remembered forever, so each is alerted once."""
    seen: dict[str, str] = dict(prev.get("seen") or {})
    new = [f for key, f in findings.items() if key not in seen]

    prev_metrics: dict[str, int] = dict(prev.get("metrics") or {})
    for name, value in metrics.items():
        old = prev_metrics.get(name)
        if old is not None and value > old:
            label, severity = METRIC_LABELS.get(name, (name, "medium"))
            new.append(_f(f"{label}: {old} → {value}", severity))
        prev_metrics[name] = max(value, old if old is not None else value)

    state = {"baseline": True, "metrics": prev_metrics}
    for kind, label in (("risk", "Threat risk"), ("exposure", "Dark-web exposure")):
        cur = report.get(kind) or {}
        level, old = cur.get("level"), prev.get(f"{kind}_level")
        if level and level != "unknown":
            if old and LEVEL_RANK.get(level, -1) > LEVEL_RANK.get(old, -1) and LEVEL_RANK[level] >= 2:
                new.append(_f(f"{label} rose from {old} to {level} ({cur.get('score')}/100)",
                              level if level in ("critical", "high") else "medium"))
            state[f"{kind}_level"] = level
        elif old:
            state[f"{kind}_level"] = old

    seen.update({k: f["text"] for k, f in findings.items()})
    if len(seen) > MAX_SEEN:
        seen = dict(list(seen.items())[-MAX_SEEN:])
    state["seen"] = seen
    new.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))
    return new, state


def build_alert(item: dict, report: dict, findings: list[dict], kind: str) -> dict:
    """kind: "baseline" (first check), "change" (new findings) or "report" (scheduled status, nothing new)."""
    risk, exposure = report.get("risk") or {}, report.get("exposure") or {}
    parts = []
    if risk:
        parts.append(f"Threat risk {risk.get('score')}/100 ({risk.get('level')})")
    if exposure:
        parts.append(f"Dark-web exposure {exposure.get('score')}/100 ({exposure.get('level')})")
    name = item["value"] + (f" ({item['label']})" if item.get("label") else "")
    ordered = sorted(findings, key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))
    level = ordered[0]["severity"] if ordered and kind != "report" else "info"
    if kind == "baseline":
        title = (f"Monitoring started: {name} - {len(findings)} existing finding(s)" if findings
                 else f"Monitoring started: {name} - nothing found")
    elif kind == "report":
        title = (f"Daily report: {name} - no new findings ({len(findings)} known)" if findings
                 else f"Daily report: {name} - all clear")
    else:
        title = f"{level.upper()}: {len(findings)} new finding(s) for {name}"
    return {
        "watch_id": item["id"], "value": item["value"], "label": item.get("label"),
        "kind": kind, "level": level, "title": title,
        "summary": " · ".join(parts), "findings": ordered[:MAX_LISTED], "more": max(0, len(ordered) - MAX_LISTED),
        "scan_id": report.get("id"),
        "link": f"{settings.base_url}/#report/{report.get('id')}" if report.get("id") else "",
    }


class Monitor:
    def __init__(self, engine: Engine, db: Database, notifier: Notifier) -> None:
        self.engine, self.db, self.notifier = engine, db, notifier
        self.running: set[int] = set()
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task] = set()

    # ---- watchlist management ------------------------------------------------------------------
    def add(self, value: str, label: str | None) -> dict:
        try:
            ioc = detect(value, allow_keyword=True)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if ioc.type not in WATCH_TYPES:
            raise ValueError("Monitoring supports domains, emails, public IPs and company names")
        if ioc.private:
            raise ValueError("Private / internal addresses cannot be monitored externally")
        if any(w["value"] == ioc.value for w in self.db.list_watch()):
            raise FileExistsError(f"{ioc.value} is already on the watchlist")
        watch_id = self.db.add_watch(ioc.value, ioc.type, (label or "").strip()[:80] or None)
        self.trigger(watch_id)
        return self.db.get_watch(watch_id) or {}

    def items(self) -> list[dict]:
        out = []
        for w in self.db.list_watch():
            state = w.pop("state", None)
            w["enabled"] = bool(w["enabled"])
            w["checking"] = w["id"] in self.running
            w["next_check"] = (w["last_checked"] or w["created"]) + settings.monitor_interval if w["enabled"] else None
            w["baseline_done"] = bool(state and json.loads(state).get("baseline"))
            out.append(w)
        return out

    # ---- checking ------------------------------------------------------------------------------
    def trigger(self, watch_id: int) -> bool:
        if watch_id in self.running:
            return False
        self.running.add(watch_id)
        task = asyncio.create_task(self._safe_check(watch_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    async def _safe_check(self, watch_id: int, scheduled: bool = False) -> None:
        try:
            await self.check(watch_id, scheduled=scheduled)
        except Exception as exc:
            log.warning("monitor check %s failed: %s", watch_id, exc)
            self.db.save_watch_error(watch_id, f"{type(exc).__name__}: {exc}")
        finally:
            self.running.discard(watch_id)

    async def check(self, watch_id: int, scheduled: bool = False) -> dict | None:
        """Scan one watched asset, diff, store and alert. Returns the alert created (if any).

        Scheduled checks also send a status report when nothing changed, if MONITOR_DAILY_REPORT is on.
        """
        async with self._lock:  # one check at a time keeps free API quotas safe
            item = self.db.get_watch(watch_id)
            if item is None:
                return None
            ioc = detect(item["value"], allow_keyword=True)
            report = await self.engine.scan(ioc, mode=scan_mode(ioc.type), nocache=True)
            prev = json.loads(item.get("state") or "{}")
            findings, metrics = extract_findings(report)
            baseline = not prev.get("baseline")
            new, state = diff(prev, findings, metrics, report)
            self.db.save_watch_check(watch_id, report, state)

            if baseline:
                if not settings.monitor_notify_baseline:
                    return None
                alert = build_alert(item, report, list(findings.values()), "baseline")
            elif new:
                alert = build_alert(item, report, new, "change")
            elif scheduled and settings.monitor_daily_report:
                alert = build_alert(item, report, list(findings.values()), "report")
            else:
                return None
            return await self.dispatch(alert)

    async def dispatch(self, alert: dict) -> dict:
        alert["delivery"] = await self.notifier.send(alert)
        alert["id"] = self.db.add_alert(alert)
        return alert

    async def check_due(self) -> None:
        now = time.time()
        for w in self.db.list_watch():
            if not w["enabled"] or w["id"] in self.running:
                continue
            if w["last_checked"] is None or w["last_checked"] + settings.monitor_interval <= now:
                self.running.add(w["id"])
                await self._safe_check(w["id"], scheduled=True)

    async def loop(self) -> None:
        await asyncio.sleep(30)
        while True:
            if settings.monitor_enabled:
                try:
                    await self.check_due()
                except Exception as exc:  # keep the scheduler alive
                    log.warning("monitor loop error: %s", exc)
            await asyncio.sleep(300)

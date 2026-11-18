"""Scan orchestration: picks sources for an IOC, runs them concurrently with caching, scores the result."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Callable

import httpx

from . import __version__, scoring
from .config import settings
from .db import Database
from .ioc import IOC, detect
from .sources import SOURCE_CLASSES
from .sources.base import Result, Source, SourceError
from .sources.darkweb import RansomwareLive

log = logging.getLogger("tiscan")

MODES = ("full", "fast", "darkweb")
VERDICT_RANK = {"malicious": 0, "suspicious": 1, "info": 2, "clean": 3, "unknown": 4}
STATUS_RANK = {"ok": 0, "not_found": 1, "rate_limited": 2, "timeout": 2, "error": 2, "auth_error": 2,
               "no_key": 3, "unsupported": 4, "skipped": 4}


class FeedStore:
    """Bulk feeds (blocklists) downloaded once, parsed in memory and persisted in the cache table."""

    def __init__(self, client: httpx.AsyncClient, db: Database) -> None:
        self.client, self.db = client, db
        self._mem: dict[str, tuple[float, object]] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def clear(self) -> None:
        self._mem.clear()

    async def get(self, name: str, url: str, parser: Callable[[str], object], ttl: int = 3600) -> object:
        hit = self._mem.get(name)
        if hit and hit[0] > time.time():
            return hit[1]
        async with self._locks[name]:
            hit = self._mem.get(name)
            if hit and hit[0] > time.time():
                return hit[1]
            key = f"feed|{name}"
            cached = self.db.cache_get(key, allow_stale=True)
            stale = False
            if cached and cached[1]:
                raw = cached[0]
            else:
                try:
                    resp = await self.client.get(url, timeout=60)
                    resp.raise_for_status()
                    raw = resp.text
                    self.db.cache_set(key, raw, ttl)
                except httpx.HTTPError as exc:
                    if not cached:
                        raise SourceError(f"Feed download failed: {type(exc).__name__}") from exc
                    raw, stale = cached[0], True
            parsed = parser(raw)
            self._mem[name] = (time.time() + (300 if stale else min(ttl, 3600)), parsed)
            return parsed


@dataclass
class Context:
    client: httpx.AsyncClient
    db: Database
    feeds: FeedStore
    extra: dict = field(default_factory=dict)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Engine:
    def __init__(self, client: httpx.AsyncClient, db: Database) -> None:
        self.db = db
        self.ctx = Context(client=client, db=db, feeds=FeedStore(client, db))
        self.sources: list[Source] = [cls() for cls in SOURCE_CLASSES]
        self.by_id = {s.id: s for s in self.sources}

    # ---- planning ------------------------------------------------------------------------------
    def plan(self, ioc: IOC, mode: str, only: list[str] | None = None) -> list[Source]:
        selected = []
        for src in self.sources:
            if not src.supports(ioc) or (only and src.id not in only):
                continue
            if mode == "fast" and (src.slow or src.darkweb):
                continue
            if mode == "darkweb" and not src.darkweb:
                continue
            selected.append(src)
        return selected

    # ---- running a single source ---------------------------------------------------------------
    async def _run(self, src: Source, ioc: IOC, nocache: bool) -> Result:
        key = f"src|{src.id}|{ioc.type}|{ioc.value}"
        cached = self.db.cache_get(key, allow_stale=True)
        if cached and cached[1] and not nocache:
            res = Result.from_dict(json.loads(cached[0]))
            res.cached, res.elapsed_ms = True, 0
            return res
        if not src.configured:
            return src.result(status="no_key", verdict="unknown",
                              summary=f"Add {src.key_env} to .env to enable this source")

        started = time.monotonic()
        budget = (src.timeout or settings.http_timeout) * 2 + (src.max_wait if src.limiter else 0)
        try:
            res = await asyncio.wait_for(src.lookup(ioc, self.ctx), timeout=budget)
        except SourceError as exc:
            res = src.result(status=exc.status, verdict="unknown", error=str(exc) or exc.status,
                             summary=str(exc) or exc.status.replace("_", " ").capitalize())
        except asyncio.TimeoutError:
            res = src.result(status="timeout", verdict="unknown", error="Timed out",
                             summary=f"No answer within {int(budget)}s")
        except httpx.HTTPError as exc:
            res = src.result(status="error", verdict="unknown", error=type(exc).__name__,
                             summary=f"Network error: {type(exc).__name__}")
        except Exception as exc:  # a bug in one source must never break the whole scan
            log.exception("source %s crashed on %s", src.id, ioc.value)
            res = src.result(status="error", verdict="unknown", error=f"{type(exc).__name__}: {exc}",
                             summary="Internal error while parsing the response")
        res.elapsed_ms = int((time.monotonic() - started) * 1000)

        if res.status in ("ok", "not_found"):
            self.db.cache_set(key, json.dumps(res.to_dict(), default=str), src.ttl or settings.cache_ttl)
        elif cached and res.status in ("rate_limited", "timeout", "error"):
            stale = Result.from_dict(json.loads(cached[0]))
            stale.cached, stale.stale = True, True
            stale.summary = f"{stale.summary} (cached - live lookup failed: {res.summary})"
            return stale
        return res

    # ---- scanning ------------------------------------------------------------------------------
    async def stream(self, ioc: IOC, mode: str = "full", nocache: bool = False, only: list[str] | None = None,
                     save: bool = True) -> AsyncIterator[dict]:
        if mode not in MODES:
            raise ValueError(f"Unknown mode {mode!r}")
        sources = self.plan(ioc, mode, only)
        started = time.monotonic()
        yield {"event": "start", "ioc": ioc.to_dict(), "mode": mode,
               "sources": [{"id": s.id, "name": s.name, "category": s.category} for s in sources]}

        results: list[Result] = []
        if ioc.private:
            for src in sources:
                res = src.result(status="skipped", verdict="unknown",
                                 summary="Private / reserved address - not sent to external sources")
                results.append(res)
                yield {"event": "result", "result": res.to_dict()}
        else:
            tasks = [asyncio.create_task(self._run(s, ioc, nocache)) for s in sources]
            try:
                for fut in asyncio.as_completed(tasks):
                    res = await fut
                    results.append(res)
                    yield {"event": "result", "result": res.to_dict()}
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()

        report = self._report(ioc, mode, results, time.monotonic() - started)
        if save:
            report["id"] = self.db.save_scan(report)
        yield {"event": "done", "report": report}

    async def scan(self, ioc: IOC, mode: str = "full", nocache: bool = False, only: list[str] | None = None,
                   save: bool = True) -> dict:
        report: dict = {}
        async for event in self.stream(ioc, mode, nocache, only, save):
            if event["event"] == "done":
                report = event["report"]
        return report

    def _report(self, ioc: IOC, mode: str, results: list[Result], elapsed: float) -> dict:
        results.sort(key=lambda r: (STATUS_RANK.get(r.status, 5), VERDICT_RANK.get(r.verdict, 5),
                                    -max(r.score, r.exposure), r.name))
        risk = scoring.risk(results) if mode != "darkweb" else None
        exposure = scoring.exposure(results)

        related, seen = [], {(ioc.type, ioc.value)}
        for r in results:
            for item in r.related:
                key = (item.get("type"), str(item.get("value", "")).lower())
                if not key[1] or key in seen:
                    continue
                if item.get("type") == "ip":
                    try:
                        if detect(item["value"]).private:
                            continue
                    except ValueError:
                        continue
                seen.add(key)
                related.append({**item, "value": key[1], "source": r.name})
        tags = Counter(t.lower() for r in results for t in r.tags if t)
        verdicts = Counter(r.verdict for r in results if r.status in ("ok", "not_found"))
        return {
            "version": __version__,
            "ioc": ioc.to_dict(),
            "mode": mode,
            "scanned_at": _now_iso(),
            "duration_ms": int(elapsed * 1000),
            "risk": risk,
            "exposure": exposure,
            "verdicts": dict(verdicts),
            "tags": [t for t, _ in tags.most_common(20)],
            "related": related[:150],
            "results": [r.to_dict() for r in results],
        }

    # ---- pivoting ------------------------------------------------------------------------------
    async def pivot(self, values: list[str], mode: str = "fast") -> list[dict]:
        sem = asyncio.Semaphore(4)

        async def one(value: str) -> dict:
            async with sem:
                try:
                    ioc = detect(value)
                except ValueError as exc:
                    return {"value": value, "error": str(exc)}
                report = await self.scan(ioc, mode=mode)
                return compact(report)

        return await asyncio.gather(*(one(v) for v in values))

    # ---- ransomware monitor --------------------------------------------------------------------
    @property
    def ransomware(self) -> RansomwareLive:
        return self.by_id["ransomware_live"]  # type: ignore[return-value]

    async def ransomware_monitor(self, countries: list[str], include_recent: bool, max_fetch: int = 2) -> dict:
        victims, status = [], {}
        fetched = 0
        targets = [("recent", "recentvictims")] if include_recent else []
        targets += [(cc, f"countryvictims/{cc}") for cc in countries]
        for label, path in targets:
            hit = self.db.cache_get(f"rwlive|{path}")
            allow_fetch = bool(hit) or fetched < max_fetch
            try:
                items, meta = await self.ransomware.cached_list(self.ctx, path, ttl=3 * 3600, allow_fetch=allow_fetch)
                if not meta.get("cached") and not meta.get("pending"):
                    fetched += 1
                status[label] = "pending" if meta.get("pending") else "stale" if meta.get("stale") else "ok"
                if meta.get("error"):
                    status[label] = f"stale ({meta['error']})"
            except SourceError as exc:
                items, status[label] = [], f"error: {exc}"
                fetched += 1
            victims.extend(items)

        unique, seen = [], set()
        for v in sorted(victims, key=lambda x: x.get("date") or "", reverse=True):
            key = (v["victim"].lower(), v["group"].lower())
            if key not in seen:
                seen.add(key)
                unique.append(v)
        by_month = Counter((v.get("date") or "")[:7] for v in unique if v.get("date"))
        months = sorted(by_month)[-12:]
        return {
            "fetched_at": _now_iso(),
            "countries": countries,
            "status": status,
            "total": len(unique),
            "stats": {
                "groups_total": len({v["group"] for v in unique if v["group"]}),
                "groups": Counter(v["group"] for v in unique if v["group"]).most_common(12),
                "sectors": Counter(v["sector"] for v in unique if v["sector"]).most_common(10),
                "countries": Counter(v["country"] for v in unique if v["country"]).most_common(20),
                "months": [[m, by_month[m]] for m in months],
            },
            "victims": unique[:1500],
        }

    async def ransomware_refresher(self) -> None:
        """Keeps the configured countries warm in the cache, pacing calls to respect the free API."""
        await asyncio.sleep(10)
        while True:
            for cc in settings.ransomware_countries:
                path = f"countryvictims/{cc}"
                if self.db.cache_get(f"rwlive|{path}"):
                    continue
                try:
                    await self.ransomware.cached_list(self.ctx, path, ttl=3 * 3600)
                except Exception as exc:  # keep the loop alive whatever happens
                    log.info("ransomware refresh %s failed: %s", cc, exc)
                await asyncio.sleep(75)
            await asyncio.sleep(1800)


def compact(report: dict) -> dict:
    risk = report.get("risk") or {}
    exposure = report.get("exposure") or {}
    flagged = [r for r in report.get("results", []) if r.get("verdict") in ("malicious", "suspicious")]
    return {
        "id": report.get("id"),
        "value": report["ioc"]["value"],
        "type": report["ioc"]["type"],
        "private": report["ioc"].get("private", False),
        "risk": risk.get("score"),
        "level": risk.get("level"),
        "exposure": exposure.get("score"),
        "exposure_level": exposure.get("level"),
        "flagged": [r["name"] for r in flagged],
        "top": flagged[0]["summary"] if flagged else "",
    }

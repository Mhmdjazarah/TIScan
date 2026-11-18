"""FastAPI application: JSON/NDJSON API plus the single-page dashboard."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, misp
from .config import settings, update_env
from .db import Database
from .engine import Engine
from .ioc import EMAIL_RE, IOC, detect, extract
from .monitor import Monitor
from .notify import Notifier

log = logging.getLogger("tiscan")
logging.getLogger("httpx").setLevel(logging.WARNING)  # never log request URLs (they can carry API keys)
STATIC = Path(__file__).parent / "static"
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = Database(settings.db_path)
    db.purge()
    client = httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
        timeout=settings.http_timeout,
        limits=httpx.Limits(max_connections=60, max_keepalive_connections=20),
    )
    engine = Engine(client, db)
    monitor = Monitor(engine, db, Notifier())
    app.state.db, app.state.engine, app.state.monitor = db, engine, monitor
    background = [asyncio.create_task(monitor.loop())]
    if settings.ransomware_refresh and settings.ransomware_countries:
        background.append(asyncio.create_task(engine.ransomware_refresher()))
    if not settings.loopback_only and not settings.api_token:
        log.warning("TIScan is listening on %s without TISCAN_API_TOKEN - anyone on the network can use it",
                    settings.host)
    try:
        yield
    finally:
        for task in background:
            task.cancel()
        await client.aclose()
        db.close()


app = FastAPI(title="TIScan", version=__version__, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")


def _host_only(host_header: str) -> str:
    if host_header.startswith("["):
        return host_header[1:host_header.find("]")]
    return host_header.rsplit(":", 1)[0] if host_header.count(":") == 1 else host_header


@app.middleware("http")
async def guard(request: Request, call_next):
    # DNS-rebinding protection: only answer to expected Host headers.
    if settings.allowed_hosts and _host_only(request.headers.get("host", "")).lower() not in settings.allowed_hosts:
        return JSONResponse({"detail": "Invalid Host header"}, status_code=400)
    if request.url.path.startswith("/api/"):
        supplied = request.headers.get("x-api-key", "")
        token_ok = bool(settings.api_token) and hmac.compare_digest(supplied, settings.api_token)
        client = request.client.host if request.client else ""
        if settings.api_token and client not in LOCAL_HOSTS and not token_ok:
            return JSONResponse({"detail": "Missing or invalid X-API-Key"}, status_code=401)
        # CSRF protection: browsers cannot add custom headers cross-origin without a CORS preflight.
        if request.method not in ("GET", "HEAD", "OPTIONS") and not token_ok \
                and request.headers.get("x-requested-with", "").lower() != "tiscan":
            return JSONResponse({"detail": "Missing X-Requested-With: tiscan header"}, status_code=403)
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"  # revalidate so upgrades show up immediately
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.url.path.startswith("/api/docs"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
    return response


def engine(request: Request) -> Engine:
    return request.app.state.engine


def parse_ioc(value: str, mode: str) -> IOC:
    try:
        return detect(value, allow_keyword=(mode == "darkweb"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class ScanBody(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=2048)
    mode: Literal["full", "fast", "darkweb"] = "full"
    nocache: bool = False
    sources: list[str] | None = None
    save: bool = True


class ExtractBody(BaseModel):
    text: str = Field(..., max_length=3_000_000)


class PivotBody(BaseModel):
    items: list[str] = Field(..., min_length=1, max_length=25)
    mode: Literal["full", "fast"] = "fast"


class IdsBody(BaseModel):
    ids: list[int] = Field(..., min_length=1, max_length=500)
    info: str | None = Field(default=None, max_length=200)


# ---- scanning ----------------------------------------------------------------------------------

@app.post("/api/scan")
async def api_scan(body: ScanBody, request: Request):
    ioc = parse_ioc(body.ioc, body.mode)
    return await engine(request).scan(ioc, body.mode, body.nocache, body.sources, body.save)


@app.post("/api/scan/stream")
async def api_scan_stream(body: ScanBody, request: Request):
    ioc = parse_ioc(body.ioc, body.mode)
    eng = engine(request)

    async def ndjson():
        try:
            async for event in eng.stream(ioc, body.mode, body.nocache, body.sources, body.save):
                yield json.dumps(event, default=str) + "\n"
        except Exception as exc:  # surface errors to the UI instead of silently closing the stream
            log.exception("scan stream failed")
            yield json.dumps({"event": "error", "message": f"{type(exc).__name__}: {exc}"}) + "\n"

    return StreamingResponse(ndjson(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.post("/api/detect")
async def api_detect(body: ScanBody):
    return parse_ioc(body.ioc, body.mode).to_dict()


@app.post("/api/extract")
async def api_extract(body: ExtractBody):
    iocs = extract(body.text)
    return {"iocs": iocs, "counts": dict(Counter(i["type"] for i in iocs))}


@app.post("/api/pivot")
async def api_pivot(body: PivotBody, request: Request):
    return {"results": await engine(request).pivot(body.items, body.mode)}


# ---- history & export --------------------------------------------------------------------------

@app.get("/api/history")
async def api_history(request: Request, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                      q: str = Query("", max_length=200)):
    return request.app.state.db.list_scans(limit, offset, q.strip())


@app.get("/api/history/{scan_id}")
async def api_history_item(scan_id: int, request: Request):
    report = request.app.state.db.get_scan(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return report


@app.delete("/api/history/{scan_id}")
async def api_history_delete(scan_id: int, request: Request):
    if not request.app.state.db.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}


@app.delete("/api/history")
async def api_history_clear(request: Request):
    return {"deleted": request.app.state.db.clear_scans()}


def _ids(raw: str) -> list[int]:
    ids = [int(x) for x in re.findall(r"\d+", raw)][:500]
    if not ids:
        raise HTTPException(status_code=400, detail="No scan ids given")
    return ids


@app.get("/api/export/misp")
async def api_export_misp(request: Request, ids: str = Query(..., max_length=5000)):
    reports = request.app.state.db.get_scans(_ids(ids))
    if not reports:
        raise HTTPException(status_code=404, detail="No matching scans")
    event = misp.build_event(reports)
    name = re.sub(r"[^\w.-]+", "_", reports[0]["ioc"]["value"])[:60] if len(reports) == 1 else f"bulk-{len(reports)}"
    return JSONResponse(event, headers={"Content-Disposition": f'attachment; filename="tiscan-misp-{name}.json"'})


@app.post("/api/misp/push")
async def api_misp_push(body: IdsBody, request: Request):
    reports = request.app.state.db.get_scans(body.ids)
    if not reports:
        raise HTTPException(status_code=404, detail="No matching scans")
    try:
        return await misp.push(misp.build_event(reports, body.info))
    except (ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---- ransomware monitor ------------------------------------------------------------------------

@app.get("/api/ransomware")
async def api_ransomware(request: Request, countries: str = Query("", max_length=200), recent: bool = False):
    codes = [c for c in re.findall(r"[A-Za-z]{2}", countries.upper())][:20] or settings.ransomware_countries
    return await engine(request).ransomware_monitor(codes, recent)


# ---- continuous monitoring ---------------------------------------------------------------------

class WatchBody(BaseModel):
    value: str = Field(..., min_length=2, max_length=200)
    label: str | None = Field(default=None, max_length=80)


class WatchPatch(BaseModel):
    enabled: bool


class EmailConfig(BaseModel):
    host: str = Field("", max_length=253, pattern=r"^[A-Za-z0-9.-]*$")
    port: int = Field(587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    user: str = Field("", max_length=200, pattern=r"^[^\r\n,]*$")
    password: str | None = Field(default=None, max_length=200, pattern=r"^[^\r\n]*$")
    sender: str = Field("", max_length=200)
    to: list[str] = Field(default_factory=list, max_length=10)
    daily_report: bool | None = None


class KeyBody(BaseModel):
    name: str = Field(..., pattern=r"^[A-Z0-9_]{3,40}$")
    value: str = Field("", max_length=300, pattern=r"^\S*$")


@app.post("/api/keys")
async def api_set_key(body: KeyBody, request: Request):
    """Save (or clear, with an empty value) one source API key into .env. Takes effect immediately."""
    allowed = {s.key_env for s in engine(request).sources if s.key_env}
    if body.name not in allowed:
        raise HTTPException(status_code=400, detail="Unknown API key name")
    update_env({body.name: body.value.strip()})
    return {"name": body.name, "configured": bool(body.value.strip())}


def monitor(request: Request) -> Monitor:
    return request.app.state.monitor


@app.get("/api/monitor")
async def api_monitor(request: Request):
    mon = monitor(request)
    return {"items": mon.items(), "enabled": settings.monitor_enabled,
            "interval_hours": settings.monitor_interval / 3600, "notify": mon.notifier.status(),
            "base_url": settings.base_url}


@app.post("/api/monitor/watch")
async def api_watch_add(body: WatchBody, request: Request):
    try:
        return monitor(request).add(body.value, body.label)
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/api/monitor/watch/{watch_id}")
async def api_watch_patch(watch_id: int, body: WatchPatch, request: Request):
    if not request.app.state.db.set_watch_enabled(watch_id, body.enabled):
        raise HTTPException(status_code=404, detail="Not on the watchlist")
    return {"id": watch_id, "enabled": body.enabled}


@app.delete("/api/monitor/watch/{watch_id}")
async def api_watch_delete(watch_id: int, request: Request):
    if not request.app.state.db.delete_watch(watch_id):
        raise HTTPException(status_code=404, detail="Not on the watchlist")
    return {"deleted": watch_id}


@app.post("/api/monitor/watch/{watch_id}/check")
async def api_watch_check(watch_id: int, request: Request):
    if request.app.state.db.get_watch(watch_id) is None:
        raise HTTPException(status_code=404, detail="Not on the watchlist")
    return {"started": monitor(request).trigger(watch_id)}


@app.post("/api/monitor/check-all")
async def api_watch_check_all(request: Request):
    mon = monitor(request)
    started = [w["id"] for w in request.app.state.db.list_watch() if w["enabled"] and mon.trigger(w["id"])]
    return {"started": started}


@app.get("/api/monitor/alerts")
async def api_alerts(request: Request, limit: int = Query(100, ge=1, le=500)):
    return {"items": request.app.state.db.list_alerts(limit)}


@app.delete("/api/monitor/alerts")
async def api_alerts_clear(request: Request):
    return {"deleted": request.app.state.db.clear_alerts()}


@app.post("/api/monitor/notify/email")
async def api_notify_email(body: EmailConfig, request: Request):
    recipients = [t.strip().lower() for t in body.to if t.strip()]
    for addr in recipients + ([body.sender.strip().lower()] if body.sender.strip() else []):
        if not EMAIL_RE.fullmatch(addr):
            raise HTTPException(status_code=400, detail=f"Invalid email address: {addr}")
    updates = {
        "SMTP_HOST": body.host.strip(), "SMTP_PORT": str(body.port), "SMTP_SECURITY": body.security,
        "SMTP_USER": body.user.strip(), "SMTP_FROM": body.sender.strip(), "ALERT_EMAIL_TO": ",".join(recipients),
    }
    if body.password is not None:  # None = keep the stored password
        updates["SMTP_PASSWORD"] = body.password
    if body.daily_report is not None:
        updates["MONITOR_DAILY_REPORT"] = "true" if body.daily_report else "false"
    update_env(updates)
    return monitor(request).notifier.status()


@app.post("/api/monitor/notify/test")
async def api_notify_test(request: Request):
    mon = monitor(request)
    if not settings.email_configured:
        raise HTTPException(status_code=400, detail="Email alerts are not configured yet")
    alert = await mon.dispatch({
        "watch_id": None, "value": "test", "label": None, "kind": "test", "level": "info",
        "title": "TIScan test alert - notifications are working",
        "summary": "This is what a monitoring alert looks like.",
        "findings": [{"text": 'Ransomware leak site: "Example Corp" posted by examplegroup (sample)', "severity": "critical"},
                     {"text": "Data breach: ExampleBreach (sample)", "severity": "medium"}],
        "more": 0, "scan_id": None, "link": settings.base_url,
    })
    return alert


# ---- meta --------------------------------------------------------------------------------------

@app.get("/api/config")
async def api_config(request: Request):
    eng = engine(request)
    return {
        "version": __version__,
        "sources": [s.meta() for s in eng.sources],
        "misp": {"configured": settings.misp_configured,
                 "host": urlsplit(settings.misp_url).netloc if settings.misp_url else None},
        "ransomware_countries": settings.ransomware_countries,
        "token_required": bool(settings.api_token),
    }


@app.get("/api/stats")
async def api_stats(request: Request):
    db = request.app.state.db
    return {"cache": db.cache_stats(), "scans": db.scan_count()}


@app.delete("/api/cache")
async def api_cache_clear(request: Request):
    engine(request).ctx.feeds.clear()
    return {"deleted": request.app.state.db.cache_clear()}


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")

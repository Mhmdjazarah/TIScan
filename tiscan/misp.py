"""Export scan reports as MISP events (importable JSON) and optionally push them to a MISP instance."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import httpx

from .config import settings
from .ioc import registered_domain

TYPE_MAP = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "email": ("email-src", "Payload delivery"),
}
# MISP threat_level_id: 1 High, 2 Medium, 3 Low, 4 Undefined
THREAT_LEVEL = {"critical": "1", "high": "1", "medium": "2", "low": "3", "clean": "4", "unknown": "4"}
LEVEL_ORDER = ["unknown", "clean", "low", "medium", "high", "critical"]


def _attribute(ioc_type: str, value: str, to_ids: bool, comment: str, tags: list[str] | None = None) -> dict | None:
    if ioc_type not in TYPE_MAP:
        return None
    misp_type, category = TYPE_MAP[ioc_type]
    if ioc_type == "domain" and registered_domain(value) != value:
        misp_type = "hostname"
    return {
        "uuid": str(uuid.uuid4()),
        "type": misp_type,
        "category": category,
        "value": value,
        "to_ids": to_ids,
        "comment": comment[:250],
        "distribution": "5",
        "Tag": [{"name": t} for t in (tags or [])],
    }


def build_event(reports: list[dict], info: str | None = None) -> dict:
    if not reports:
        raise ValueError("No reports to export")
    attributes, seen = [], set()
    worst = "unknown"
    event_tags = {settings.misp_tlp, 'tool:tiscan'}

    def add(attr: dict | None) -> None:
        if attr and (attr["type"], attr["value"]) not in seen:
            seen.add((attr["type"], attr["value"]))
            attributes.append(attr)

    for rep in reports:
        ioc, risk = rep["ioc"], rep.get("risk") or {}
        exposure = rep.get("exposure") or {}
        level = risk.get("level") or exposure.get("level") or "unknown"
        if LEVEL_ORDER.index(level if level in LEVEL_ORDER else "unknown") > LEVEL_ORDER.index(worst):
            worst = level
        flagged = [r["name"] for r in rep.get("results", []) if r.get("verdict") in ("malicious", "suspicious")]
        parts = []
        if risk:
            parts.append(f"TIScan risk {risk.get('score')}/100 ({risk.get('level')})")
        if exposure:
            parts.append(f"dark-web exposure {exposure.get('score')}/100")
        parts.append(f"flagged by: {', '.join(flagged) if flagged else 'none'}")
        attr_tags = [f'tiscan:risk-level="{level}"'] + [f'tiscan:tag="{t}"' for t in rep.get("tags", [])[:5]]
        add(_attribute(ioc["type"], ioc["value"], (risk.get("score") or 0) >= 60, "; ".join(parts), attr_tags))
        for item in rep.get("related", [])[:60]:
            add(_attribute(item["type"], item["value"], False,
                           f"Related to {ioc['value']}: {item.get('rel', '')} ({item.get('source', '')})"))

    first = reports[0]
    if info is None:
        if len(reports) == 1:
            risk = first.get("risk") or first.get("exposure") or {}
            info = f"TIScan: {first['ioc']['value']} - {risk.get('level', 'unknown')} ({risk.get('score', '?')}/100)"
        else:
            info = f"TIScan bulk investigation - {len(reports)} indicators"
    event_tags.add(f'tiscan:risk-level="{worst}"')
    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": info,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "threat_level_id": THREAT_LEVEL.get(worst, "4"),
            "analysis": "2",
            "distribution": settings.misp_distribution,
            "published": False,
            "Tag": [{"name": t} for t in sorted(event_tags)],
            "Attribute": attributes,
        }
    }


async def push(event: dict) -> dict:
    if not settings.misp_configured:
        raise ValueError("MISP is not configured - set MISP_URL and MISP_KEY in .env")
    async with httpx.AsyncClient(verify=settings.misp_verify_ssl, timeout=30) as client:
        resp = await client.post(
            f"{settings.misp_url}/events/add",
            json=event,
            headers={"Authorization": settings.misp_key, "Accept": "application/json",
                     "Content-Type": "application/json"},
        )
    if resp.status_code >= 400:
        raise ValueError(f"MISP rejected the event (HTTP {resp.status_code}): {resp.text[:200]}")
    created = (resp.json() or {}).get("Event") or {}
    event_id = created.get("id")
    return {"id": event_id, "uuid": created.get("uuid"),
            "url": f"{settings.misp_url}/events/view/{event_id}" if event_id else settings.misp_url}

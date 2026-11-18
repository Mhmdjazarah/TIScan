"""Shared building blocks for every intelligence source."""
from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from ..config import settings

if TYPE_CHECKING:
    from ..engine import Context
    from ..ioc import IOC


class SourceError(Exception):
    status = "error"


class NotFound(SourceError):
    status = "not_found"


class RateLimited(SourceError):
    status = "rate_limited"


class AuthError(SourceError):
    status = "auth_error"


class Unsupported(SourceError):
    status = "unsupported"


@dataclass
class Result:
    source: str
    name: str
    category: str
    status: str = "ok"          # ok | not_found | no_key | error | timeout | rate_limited | auth_error | unsupported | skipped
    verdict: str = "unknown"    # malicious | suspicious | clean | info | unknown
    score: int = 0              # 0-100: how malicious this source thinks the IOC is
    exposure: int = 0           # 0-100: dark-web exposure signal (dark-web sources only)
    weight: float = 0.5         # reliability of the source in the combined risk score
    benign: bool = False        # source vouches the IOC is known-good
    summary: str = ""
    data: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    related: list = field(default_factory=list)
    link: str = ""
    error: str = ""
    elapsed_ms: int = 0
    cached: bool = False
    stale: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Result":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


class RateLimiter:
    """Sliding-window limiter so free API quotas are respected even during bulk scans."""

    def __init__(self, per_minute: float) -> None:
        self.per_minute = max(1, int(per_minute))
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    def _prune(self, now: float) -> None:
        while self._calls and now - self._calls[0] >= 60:
            self._calls.popleft()

    async def acquire(self, max_wait: float) -> None:
        async with self._lock:
            now = time.monotonic()
            self._prune(now)
            if len(self._calls) >= self.per_minute:
                wait = 60 - (now - self._calls[0]) + 0.05
                if wait > max_wait:
                    raise RateLimited(f"Free-tier quota ({self.per_minute}/min) in use - retry in {int(wait) + 1}s")
                await asyncio.sleep(wait)
                self._prune(time.monotonic())
            self._calls.append(time.monotonic())


class Source:
    id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    category: ClassVar[str] = "reputation"      # reputation | infrastructure | feeds | darkweb
    types: ClassVar[frozenset[str]] = frozenset()
    weight: ClassVar[float] = 0.5
    key_env: ClassVar[str | None] = None
    key_required: ClassVar[bool] = False
    ttl: ClassVar[int | None] = None              # cache TTL in seconds (None = global default)
    rate_per_min: ClassVar[float | None] = None
    max_wait: ClassVar[float] = 45.0              # longest we queue behind our own rate limiter
    timeout: ClassVar[float | None] = None
    slow: ClassVar[bool] = False                  # skipped in "fast" mode
    darkweb: ClassVar[bool] = False
    homepage: ClassVar[str] = ""
    signup: ClassVar[str] = ""
    description: ClassVar[str] = ""

    def __init__(self) -> None:
        rate = self.rate_limit()
        self.limiter = RateLimiter(rate) if rate else None

    def rate_limit(self) -> float | None:
        return self.rate_per_min

    @property
    def key(self) -> str:
        return os.getenv(self.key_env, "").strip() if self.key_env else ""

    @property
    def configured(self) -> bool:
        return bool(self.key) or not self.key_required

    def supports(self, ioc: "IOC") -> bool:
        return ioc.type in self.types

    def meta(self) -> dict:
        return {
            "id": self.id, "name": self.name, "category": self.category, "types": sorted(self.types),
            "weight": self.weight, "key_env": self.key_env, "key_required": self.key_required,
            "has_key": bool(self.key), "configured": self.configured, "slow": self.slow,
            "darkweb": self.darkweb, "homepage": self.homepage, "signup": self.signup,
            "description": self.description,
        }

    def result(self, **kwargs: Any) -> Result:
        kwargs.setdefault("weight", self.weight)
        return Result(source=self.id, name=self.name, category=self.category, **kwargs)

    async def lookup(self, ioc: "IOC", ctx: "Context") -> Result:  # pragma: no cover - interface
        raise NotImplementedError

    async def request(
        self,
        ctx: "Context",
        method: str,
        url: str,
        *,
        allow: tuple[int, ...] = (),
        parse: str = "json",
        **kwargs: Any,
    ) -> Any:
        """HTTP call with uniform error mapping. Status codes in `allow` return the raw response."""
        if self.limiter:
            await self.limiter.acquire(self.max_wait)
        kwargs.setdefault("timeout", self.timeout or settings.http_timeout)
        resp: httpx.Response = await ctx.client.request(method, url, **kwargs)
        code = resp.status_code
        if code in allow:
            return resp
        if code == 404:
            raise NotFound("No record")
        if code == 429:
            raise RateLimited("Provider rate limit reached (HTTP 429) - try again shortly")
        if code in (401, 403):
            raise AuthError(f"HTTP {code} - API key missing, invalid or lacks permission")
        if code >= 400:
            raise SourceError(f"HTTP {code} from provider")
        if parse == "json":
            try:
                return resp.json()
            except ValueError as exc:
                raise SourceError("Provider returned an invalid (non-JSON) response") from exc
        if parse == "text":
            return resp.text
        return resp


# ---- small helpers used by several sources ------------------------------------------------------

def fmt_ts(epoch: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d") if epoch else None
    except (TypeError, ValueError, OSError):
        return None


def parse_dt(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    s = value.strip().replace("Z", "+00:00").replace(" UTC", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.fromisoformat(s[:10])
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def day(value: Any) -> str | None:
    dt = parse_dt(value)
    return dt.strftime("%Y-%m-%d") if dt else (str(value)[:10] if value else None)


def uniq(items: Any, limit: int | None = None) -> list:
    out, seen = [], set()
    for item in items:
        if item in (None, "") or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if limit and len(out) >= limit:
            break
    return out


def rel(ioc_type: str, value: str, relation: str) -> dict:
    return {"type": ioc_type, "value": value, "rel": relation}


def dedupe(items: list[dict], limit: int) -> list[dict]:
    """De-duplicate related-IOC dicts by (type, value), keeping the first relation seen."""
    seen, out = set(), []
    for item in items:
        key = (item["type"], item["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out

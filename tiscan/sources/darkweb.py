"""Dark-web exposure: ransomware leak sites, infostealer logs, breach databases and Tor (.onion) search.

Only metadata is collected (victim listings, breach names, counts). TIScan never downloads leaked data.
"""
from __future__ import annotations

import base64
import html
import json
import re
import time
from urllib.parse import parse_qs, quote, urlsplit

from .base import NotFound, RateLimited, Source, SourceError, day, uniq
from .infra import FREE_PROVIDERS


def _search_terms(ioc) -> tuple[str, str]:
    """(primary term, company label) used for keyword-style dark-web searches."""
    if ioc.type == "keyword":
        return ioc.value, ioc.value.lower()
    if ioc.type == "email":
        return ioc.value, ioc.value.rsplit("@", 1)[1].split(".")[0]
    apex = ioc.domain or ioc.value
    return apex, apex.split(".")[0]


# ---- ransomware.live ----------------------------------------------------------------------------

def normalise_victim(v: dict) -> dict:
    name = v.get("victim") or v.get("post_title") or ""
    group = v.get("group") or v.get("group_name") or ""
    link = v.get("url") or ""
    if not link and name and group:
        link = "https://www.ransomware.live/id/" + base64.b64encode(f"{name}@{group}".encode()).decode()
    sector = v.get("activity") or ""
    return {
        "date": day(v.get("attackdate") or v.get("discovered") or v.get("published")),
        "victim": name,
        "group": group,
        "country": (v.get("country") or "").upper(),
        "sector": "" if sector in ("Not Found", "Unknown") else sector,
        "domain": (v.get("domain") or v.get("website") or "").lower().removeprefix("www."),
        "link": link,
        "description": (v.get("description") or "")[:300],
    }


class RansomwareLive(Source):
    id = "ransomware_live"
    name = "Ransomware leak sites"
    category = "darkweb"
    types = frozenset({"domain", "email", "keyword"})
    darkweb = True
    ttl = 6 * 3600
    rate_per_min = 4
    max_wait = 20
    homepage = "https://www.ransomware.live"
    description = "ransomware.live tracks victims posted on 200+ ransomware group leak sites (.onion)."

    API = "https://api.ransomware.live/v2"

    async def _get(self, ctx, path: str) -> list:
        try:
            data = await self.request(ctx, "GET", f"{self.API}/{path}", timeout=30)
        except NotFound:  # the API answers 404 when a search has no victims
            return []
        if isinstance(data, dict):  # error envelope
            message = str(data.get("error") or data.get("message") or data)
            if "rate" in message.lower() or "limit" in message.lower():
                raise RateLimited(f"ransomware.live: {message[:120]}")
            raise SourceError(f"ransomware.live: {message[:120]}")
        return data if isinstance(data, list) else []

    async def cached_list(self, ctx, path: str, ttl: int, allow_fetch: bool = True) -> tuple[list[dict], dict]:
        """Victim list for an API path, cache-first. Returns (victims, meta) with meta.stale / meta.error."""
        key = f"rwlive|{path}"
        hit = ctx.db.cache_get(key, allow_stale=True)
        if hit and hit[1]:
            return json.loads(hit[0]), {"cached": True}
        if not allow_fetch:
            return (json.loads(hit[0]) if hit else []), {"stale": bool(hit), "pending": True}
        try:
            victims = [normalise_victim(v) for v in await self._get(ctx, path)]
        except SourceError as exc:
            if hit:
                return json.loads(hit[0]), {"stale": True, "error": str(exc)}
            raise
        ctx.db.cache_set(key, json.dumps(victims), ttl)
        return victims, {}

    async def lookup(self, ioc, ctx):
        term, label = _search_terms(ioc)
        apex = ioc.domain
        if ioc.type == "email" and apex in FREE_PROVIDERS:
            return self.result(status="skipped", verdict="unknown",
                               summary=f"{apex} is a public webmail provider - leak-site search not meaningful")
        search = label if ioc.type != "keyword" else term
        if len(search) < 3:
            raise SourceError("Search term too short for a meaningful leak-site search")
        victims, meta = await self.cached_list(ctx, f"searchvictims/{quote(search, safe='')}", self.ttl)
        strong, weak = [], []
        for v in victims:
            dom = v["domain"]
            name = v["victim"].lower()
            if apex and dom and (dom == apex or dom.endswith("." + apex)):
                strong.append({**v, "match": "domain"})
            elif apex and apex in name:
                strong.append({**v, "match": "domain in name"})
            elif ioc.type == "keyword" and label in name:
                strong.append({**v, "match": "company name"})
            elif len(label) >= 4 and (label in name or label in dom):
                weak.append({**v, "match": "name only"})
        rows = [{k: v[k] for k in ("date", "victim", "group", "country", "sector", "domain", "match", "link")}
                for v in strong + weak][:25]
        groups = uniq(v["group"] for v in strong + weak)
        if strong:
            r = self.result(verdict="malicious", exposure=95,
                            summary=f"Listed as a victim on {len(strong)} ransomware leak-site post(s) ({', '.join(groups[:3])})",
                            data={"Confirmed listings": len(strong), "Possible (name) matches": len(weak),
                                  "Groups": groups, "Listings": rows},
                            tags=["ransomware-victim", *groups[:3]], link=strong[0]["link"] or self.homepage)
        elif weak:
            r = self.result(verdict="suspicious", exposure=40,
                            summary=f"{len(weak)} leak-site post(s) with a similar name - verify manually",
                            data={"Possible (name) matches": len(weak), "Groups": groups, "Listings": rows},
                            tags=groups[:3], link=self.homepage)
        else:
            r = self.result(verdict="clean", summary="No ransomware leak-site listing found",
                            data={"Search term": search}, link=self.homepage)
        r.stale = bool(meta.get("stale"))
        return r


# ---- Hudson Rock Cavalier (infostealer intelligence) -------------------------------------------

class HudsonRock(Source):
    id = "hudsonrock"
    name = "Infostealer logs (Hudson Rock)"
    category = "darkweb"
    types = frozenset({"domain", "email", "ip"})
    darkweb = True
    ttl = 12 * 3600
    homepage = "https://www.hudsonrock.com/free-tools"
    description = "Hudson Rock Cavalier: machines infected by infostealers (RedLine, Lumma, Raccoon...) whose stolen logs contain this domain/email/IP."

    BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

    async def lookup(self, ioc, ctx):
        if ioc.type == "domain":
            return await self._domain(ioc, ctx)
        param = "email" if ioc.type == "email" else "ip"
        j = await self.request(ctx, "GET", f"{self.BASE}/search-by-{param}", params={param: ioc.value})
        stealers = j.get("stealers") or []
        if not stealers:
            return self.result(verdict="clean", summary=f"No infostealer infection associated with this {param}",
                               link=self.homepage)
        rows = [{"compromised": day(s.get("date_compromised")), "computer": s.get("computer_name"),
                 "os": s.get("operating_system"), "malware_path": s.get("malware_path"),
                 "antivirus": ", ".join(s.get("antiviruses") or []) if isinstance(s.get("antiviruses"), list) else s.get("antiviruses"),
                 "ip (masked)": s.get("ip"), "corporate logins": s.get("total_corporate_services"),
                 "personal logins": s.get("total_user_services")} for s in stealers[:10]]
        latest = max((r["compromised"] or "" for r in rows), default="")
        exposure = 90 if ioc.type == "email" else 70
        return self.result(
            verdict="malicious", exposure=exposure,
            summary=f"{len(stealers)} infostealer-infected machine(s) linked to this {param}"
                    + (f", latest {latest}" if latest else ""),
            data={"Infected machines": len(stealers), "Latest compromise": latest or None, "Infections": rows},
            tags=["infostealer"], link=self.homepage,
        )

    async def _domain(self, ioc, ctx):
        apex = ioc.domain or ioc.value
        j = await self.request(ctx, "GET", f"{self.BASE}/search-by-domain", params={"domain": apex})
        employees, users = int(j.get("employees") or 0), int(j.get("users") or 0)
        third = int(j.get("third_parties") or 0)
        families = {k: v for k, v in (j.get("stealerFamilies") or {}).items() if k != "total" and isinstance(v, int)}
        top_families = [f"{k} ({v})" for k, v in sorted(families.items(), key=lambda kv: -kv[1])[:6]]
        emp_urls = [{"url": u.get("url"), "occurrences": u.get("occurrence")}
                    for u in ((j.get("data") or {}).get("employees_urls") or [])[:12]]
        emp_score = 0 if not employees else 60 if employees <= 5 else 75 if employees <= 50 else 88
        user_score = 0 if not users else 30 if users <= 100 else 40 if users <= 1000 else 50
        exposure = max(emp_score, user_score)
        if employees:
            verdict = "malicious"
        elif users or third:
            verdict = "suspicious"
        else:
            verdict = "clean"
        summary = (f"{employees} employee and {users} user machine(s) infected by infostealers"
                   if employees or users else "No infostealer-compromised employees or users found")
        return self.result(
            verdict=verdict, exposure=exposure, summary=summary,
            data={"Compromised employees": employees, "Compromised users / customers": users,
                  "Third-party exposures": third,
                  "Last employee compromised": day(j.get("last_employee_compromised")),
                  "Last user compromised": day(j.get("last_user_compromised")),
                  "Stealer families": top_families, "Exposed employee login URLs": emp_urls},
            tags=["infostealer"] if employees or users else [], link=self.homepage,
        )


# ---- breach databases ---------------------------------------------------------------------------

class LeakCheck(Source):
    id = "leakcheck"
    name = "LeakCheck (breaches)"
    category = "darkweb"
    types = frozenset({"email", "domain"})
    darkweb = True
    ttl = 24 * 3600
    rate_per_min = 10
    homepage = "https://leakcheck.io"
    description = "Public LeakCheck API: which known data breaches / combo lists contain this email or domain."

    async def lookup(self, ioc, ctx):
        value = ioc.value if ioc.type == "email" else (ioc.domain or ioc.value)
        j = await self.request(ctx, "GET", "https://leakcheck.io/api/public", params={"check": value})
        if not j.get("success"):
            err = str(j.get("error") or "")
            if "not found" in err.lower():
                return self.result(verdict="clean", summary="Not found in LeakCheck breach index", link=self.homepage)
            if "limit" in err.lower() or "too many" in err.lower():
                raise RateLimited(f"LeakCheck: {err}")
            raise SourceError(f"LeakCheck: {err or 'unknown error'}")
        found = int(j.get("found") or 0)
        sources = [{"breach": s.get("name"), "date": s.get("date") or "unknown"} for s in j.get("sources") or []]
        stealer = any("stealer" in (s["breach"] or "").lower() for s in sources)
        if ioc.type == "email":
            exposure = min(80, 35 + 5 * len(sources))
        else:
            exposure = min(65, 25 + found // 40)
        if stealer:
            exposure = max(exposure, 80 if ioc.type == "email" else 60)
        return self.result(
            verdict="malicious" if stealer else "suspicious", exposure=exposure,
            summary=f"{found} record(s) across {len(sources)} breach source(s)"
                    + (" - includes stealer logs" if stealer else ""),
            data={"Records": found, "Breach sources": sources[:60], "Exposed fields": j.get("fields") or []},
            tags=["breached"] + (["stealer-logs"] if stealer else []), link=self.homepage,
        )


class XposedOrNot(Source):
    id = "xposedornot"
    name = "XposedOrNot (breaches)"
    category = "darkweb"
    types = frozenset({"email"})
    darkweb = True
    ttl = 24 * 3600
    rate_per_min = 10
    homepage = "https://xposedornot.com"
    description = "Free breach-notification service: data breaches that exposed this email address."

    async def lookup(self, ioc, ctx):
        resp = await self.request(ctx, "GET", f"https://api.xposedornot.com/v1/check-email/{quote(ioc.value)}",
                                  allow=(404,), parse="raw")
        try:
            j = resp.json()
        except ValueError as exc:
            raise SourceError("Invalid response from XposedOrNot") from exc
        if resp.status_code == 404 or j.get("Error"):
            return self.result(verdict="clean", summary="Not found in any breach (XposedOrNot)", link=self.homepage)
        raw = j.get("breaches") or []
        names = [n for group in raw for n in (group if isinstance(group, list) else [group])]
        return self.result(
            verdict="suspicious", exposure=min(80, 30 + 4 * len(names)),
            summary=f"Exposed in {len(names)} data breach(es)", data={"Breaches": len(names), "Breach names": names},
            tags=["breached"], link=self.homepage,
        )


class HIBP(Source):
    id = "hibp"
    name = "Have I Been Pwned"
    category = "darkweb"
    types = frozenset({"email"})
    darkweb = True
    key_env = "HIBP_API_KEY"
    key_required = True
    ttl = 24 * 3600
    rate_per_min = 10
    homepage = "https://haveibeenpwned.com"
    signup = "https://haveibeenpwned.com/API/Key"
    description = "Troy Hunt's breach database (paid API key)."

    async def lookup(self, ioc, ctx):
        resp = await self.request(
            ctx, "GET", f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(ioc.value)}",
            params={"truncateResponse": "false"}, headers={"hibp-api-key": self.key}, allow=(404,), parse="raw",
        )
        if resp.status_code == 404:
            return self.result(verdict="clean", summary="Not pwned in any known breach", link=self.homepage)
        breaches = resp.json()
        passwords = any("Passwords" in (b.get("DataClasses") or []) for b in breaches)
        rows = [{"breach": b.get("Title") or b.get("Name"), "date": b.get("BreachDate"),
                 "data": ", ".join((b.get("DataClasses") or [])[:6]), "accounts": b.get("PwnCount")}
                for b in breaches[:40]]
        exposure = min(85, 35 + 5 * len(breaches) + (10 if passwords else 0))
        return self.result(
            verdict="malicious" if passwords else "suspicious", exposure=exposure,
            summary=f"Pwned in {len(breaches)} breach(es)" + (" - passwords exposed" if passwords else ""),
            data={"Breaches": len(breaches), "Passwords exposed": passwords, "Breach list": rows},
            tags=["breached"], link=self.homepage,
        )


# ---- Ahmia (.onion search engine) -------------------------------------------------------------

_RESULT = re.compile(r'<li class="result">(.*?)</li>', re.S)
_TAG = re.compile(r"<[^>]+>")


def _clean(fragment: str) -> str:
    return html.unescape(_TAG.sub(" ", fragment)).strip()


class Ahmia(Source):
    id = "ahmia"
    name = "Tor search (Ahmia)"
    category = "darkweb"
    types = frozenset({"domain", "email", "keyword"})
    darkweb = True
    slow = True
    ttl = 12 * 3600
    rate_per_min = 6
    timeout = 30
    homepage = "https://ahmia.fi"
    description = "Searches indexed Tor hidden services (.onion) for mentions of the company, domain or email."

    _token: tuple[str, str, float] | None = None

    async def _form_token(self, ctx) -> dict:
        if self._token and self._token[2] > time.time():
            return {self._token[0]: self._token[1]}
        page = await self.request(ctx, "GET", "https://ahmia.fi/", parse="text")
        m = re.search(r'<input type="hidden" name="(\w+)" value="(\w+)"', page)
        if not m:
            return {}
        self._token = (m.group(1), m.group(2), time.time() + 900)
        return {m.group(1): m.group(2)}

    async def lookup(self, ioc, ctx):
        term, label = _search_terms(ioc)
        params = {"q": term, **(await self._form_token(ctx))}
        page = await self.request(ctx, "GET", "https://ahmia.fi/search/", params=params, parse="text")
        needles = {term.lower()}
        if ioc.type == "domain" and len(label) >= 5:
            needles.add(label)
        hits = []
        for block in _RESULT.findall(page):
            href = re.search(r'href="([^"]+)"', block)
            target = ""
            if href:
                qs = parse_qs(urlsplit(html.unescape(href.group(1))).query)
                target = (qs.get("redirect_url") or [""])[0]
            title = _clean((re.search(r"<a[^>]*>(.*?)</a>", block, re.S) or [None, ""])[1])
            snippet = _clean((re.search(r"<p>(.*?)</p>", block, re.S) or [None, ""])[1])
            onion = _clean((re.search(r"<cite>(.*?)</cite>", block, re.S) or [None, ""])[1])
            seen = (re.search(r'data-timestamp="([^"]+)"', block) or [None, ""])[1]
            haystack = f"{title} {snippet} {target}".lower()
            if any(n in haystack for n in needles):
                hits.append({"title": title[:140], "onion": onion, "url": target[:200], "last_seen": seen,
                             "snippet": snippet[:220]})
        if not hits:
            return self.result(verdict="clean", summary="No mentions on indexed .onion sites",
                               data={"Search term": term}, link=f"https://ahmia.fi/search/?q={quote(term)}")
        return self.result(
            verdict="suspicious", exposure=min(60, 20 + 8 * len(hits)),
            summary=f"Mentioned on {len(hits)} indexed .onion page(s)",
            data={"Onion mentions": len(hits), "Pages": hits[:20]},
            tags=["onion-mention"], link=f"https://ahmia.fi/search/?q={quote(term)}",
        )

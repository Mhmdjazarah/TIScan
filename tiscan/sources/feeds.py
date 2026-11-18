"""Free blocklists and reference sets downloaded in bulk and cached: Spamhaus DROP, OpenPhish, Tor exits,
plus the CIRCL hashlookup known-file service."""
from __future__ import annotations

import ipaddress
import json
from urllib.parse import urlsplit

from .base import NotFound, Source


class SpamhausDROP(Source):
    id = "spamhaus_drop"
    name = "Spamhaus DROP"
    category = "feeds"
    types = frozenset({"ip"})
    weight = 0.9
    homepage = "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"
    description = "Netblocks hijacked or leased by professional cyber-criminals (Don't Route Or Peer)."

    @staticmethod
    def _parse(raw: str) -> list:
        nets = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if "cidr" in obj:
                    nets.append((ipaddress.ip_network(obj["cidr"], strict=False), obj.get("sblid"), obj.get("rir")))
            except (ValueError, TypeError):
                continue
        return nets

    async def lookup(self, ioc, ctx):
        ip = ipaddress.ip_address(ioc.value)
        url = ("https://www.spamhaus.org/drop/drop_v6.json" if ip.version == 6
               else "https://www.spamhaus.org/drop/drop_v4.json")
        nets = await ctx.feeds.get(f"spamhaus_drop_v{ip.version}", url, self._parse, ttl=12 * 3600)
        for net, sblid, rir in nets:
            if ip.version == net.version and ip in net:
                return self.result(
                    verdict="malicious", score=90,
                    summary=f"Inside {net} - listed on Spamhaus DROP ({sblid})",
                    data={"Netblock": str(net), "SBL ID": sblid, "RIR": rir},
                    tags=["spamhaus-drop"],
                    link=f"https://check.spamhaus.org/sbl/query/{sblid}" if sblid else self.homepage,
                )
        return self.result(verdict="clean", summary="Not inside any Spamhaus DROP netblock",
                           data={"Netblocks checked": len(nets)}, link=self.homepage)


class OpenPhish(Source):
    id = "openphish"
    name = "OpenPhish"
    category = "feeds"
    types = frozenset({"url", "domain"})
    weight = 0.9
    homepage = "https://openphish.com"
    description = "Community feed of live phishing URLs, refreshed continuously."

    @staticmethod
    def _parse(raw: str) -> dict:
        urls, hosts = set(), {}
        for line in raw.splitlines():
            u = line.strip()
            if not u.startswith(("http://", "https://")):
                continue
            urls.add(u.rstrip("/").lower())
            host = (urlsplit(u).hostname or "").lower()
            if host:
                hosts.setdefault(host, []).append(u)
        return {"urls": urls, "hosts": hosts}

    async def lookup(self, ioc, ctx):
        feed = await ctx.feeds.get("openphish", "https://openphish.com/feed.txt", self._parse, ttl=3600)
        host = (ioc.host or "").lower()
        listed = feed["hosts"].get(host, [])
        if ioc.type == "url" and ioc.value.rstrip("/").lower() in feed["urls"]:
            return self.result(verdict="malicious", score=95, summary="Exact URL is a live phishing page (OpenPhish)",
                               data={"Phishing URLs on this host": listed[:10]}, tags=["phishing"],
                               link=self.homepage)
        if listed:
            return self.result(
                verdict="malicious" if ioc.type == "domain" else "suspicious",
                score=85 if ioc.type == "domain" else 60,
                summary=f"Host serves {len(listed)} live phishing URL(s) (OpenPhish)",
                data={"Phishing URLs on this host": listed[:10]}, tags=["phishing"], link=self.homepage,
            )
        return self.result(verdict="clean", summary="Not in the live OpenPhish feed",
                           data={"Feed size": len(feed["urls"])}, link=self.homepage)


class TorExits(Source):
    id = "tor_exit"
    name = "Tor exit nodes"
    category = "feeds"
    types = frozenset({"ip"})
    weight = 0.6
    homepage = "https://check.torproject.org/torbulkexitlist"
    description = "Official Tor Project list of current exit relays (traffic may be anonymised)."

    @staticmethod
    def _parse(raw: str) -> set:
        return {line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")}

    async def lookup(self, ioc, ctx):
        exits = await ctx.feeds.get("tor_exits", "https://check.torproject.org/torbulkexitlist", self._parse,
                                    ttl=3600)
        if ioc.value in exits:
            return self.result(verdict="suspicious", score=40, summary="Current Tor exit node - traffic is anonymised",
                               data={"Tor exit": True}, tags=["tor"],
                               link=f"https://metrics.torproject.org/rs.html#search/{ioc.value}")
        return self.result(verdict="clean", summary="Not a current Tor exit node",
                           data={"Tor exit": False, "Exit nodes in list": len(exits)}, link=self.homepage)


class HashLookup(Source):
    id = "hashlookup"
    name = "CIRCL hashlookup"
    category = "feeds"
    types = frozenset({"md5", "sha1", "sha256"})
    weight = 0.7
    homepage = "https://hashlookup.circl.lu"
    description = "Known-good file database (NIST NSRL and others). Flags legitimate files to cut false positives."

    async def lookup(self, ioc, ctx):
        try:
            j = await self.request(ctx, "GET", f"https://hashlookup.circl.lu/lookup/{ioc.type}/{ioc.value}")
        except NotFound:
            raise NotFound("Not a known-good file (not in NSRL / hashlookup)") from None
        product = (j.get("ProductCode") or {}).get("ProductName") if isinstance(j.get("ProductCode"), dict) else None
        name = j.get("FileName")
        if j.get("KnownMalicious"):
            return self.result(verdict="malicious", score=90, summary=f"Flagged as known malicious ({j['KnownMalicious']})",
                               data={"File name": name, "Source": j.get("KnownMalicious")},
                               link=f"https://hashlookup.circl.lu/lookup/{ioc.type}/{ioc.value}")
        return self.result(
            verdict="clean", score=0, benign=True,
            summary=f"Known legitimate file{f': {name}' if name else ''}{f' ({product})' if product else ''}",
            data={"File name": name, "Product": product, "Database": j.get("db"), "Size": j.get("FileSize"),
                  "Trust score": j.get("hashlookup:trust")},
            tags=["known-good"], link=f"https://hashlookup.circl.lu/lookup/{ioc.type}/{ioc.value}",
        )

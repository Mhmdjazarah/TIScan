"""abuse.ch platforms: URLhaus, ThreatFox, MalwareBazaar (API key) and the Feodo Tracker C2 blocklist (free)."""
from __future__ import annotations

import json
from collections import Counter

from ..ioc import parse_ip
from .base import Source, SourceError, Unsupported, day, dedupe, rel, uniq


class _AbuseCH(Source):
    key_env = "ABUSECH_API_KEY"
    key_required = True
    signup = "https://auth.abuse.ch/"

    @property
    def auth(self) -> dict:
        return {"Auth-Key": self.key}


class URLhaus(_AbuseCH):
    id = "urlhaus"
    name = "URLhaus"
    category = "feeds"
    types = frozenset({"ip", "domain", "url", "md5", "sha256"})
    weight = 0.95
    homepage = "https://urlhaus.abuse.ch"
    description = "abuse.ch database of URLs used to distribute malware, and the payloads they serve."

    async def lookup(self, ioc, ctx):
        base = "https://urlhaus-api.abuse.ch/v1"
        if ioc.type in ("ip", "domain"):
            j = await self.request(ctx, "POST", f"{base}/host/", data={"host": ioc.value}, headers=self.auth)
        elif ioc.type == "url":
            j = await self.request(ctx, "POST", f"{base}/url/", data={"url": ioc.value}, headers=self.auth)
        else:
            j = await self.request(ctx, "POST", f"{base}/payload/", data={f"{ioc.type}_hash": ioc.value},
                                   headers=self.auth)
        status = j.get("query_status")
        if status != "ok":
            if status in ("no_results", "not_found"):
                return self.result(verdict="clean", summary="Not listed in URLhaus",
                                   link="https://urlhaus.abuse.ch/browse/")
            raise SourceError(f"URLhaus: {status}")

        if ioc.type in ("ip", "domain"):
            urls = j.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            tags = Counter(t for u in urls for t in (u.get("tags") or []))
            rows = [{"date": day(u.get("date_added")), "url": u.get("url"), "status": u.get("url_status"),
                     "threat": u.get("threat"), "tags": ", ".join(u.get("tags") or [])} for u in urls[:15]]
            return self.result(
                verdict="malicious", score=95 if online else 75,
                summary=f"Hosts {j.get('url_count', len(urls))} malware URL(s), {online} still online",
                data={"Malware URLs": j.get("url_count", len(urls)), "Online now": online,
                      "First seen": day(j.get("firstseen")), "Blocklists": j.get("blacklists"), "URLs": rows},
                tags=[t for t, _ in tags.most_common(8)],
                related=dedupe([rel("url", u["url"], "Malware URL on host (URLhaus)") for u in urls[:20] if u.get("url")], 20),
                link=j.get("urlhaus_reference") or f"https://urlhaus.abuse.ch/host/{ioc.value}/",
            )

        if ioc.type == "url":
            online = j.get("url_status") == "online"
            payloads = j.get("payloads") or []
            related = [rel("domain" if parse_ip(j["host"]) is None else "ip", j["host"], "URL host")] if j.get("host") else []
            related += [rel("sha256", p["response_sha256"], "Payload served (URLhaus)") for p in payloads[:10]
                        if p.get("response_sha256")]
            return self.result(
                verdict="malicious", score=95 if online else 80,
                summary=f"Known malware-distribution URL ({j.get('threat') or 'malware'}), status: {j.get('url_status')}",
                data={"Status": j.get("url_status"), "Threat": j.get("threat"), "Added": day(j.get("date_added")),
                      "Host": j.get("host"), "Blocklists": j.get("blacklists"),
                      "Payloads": [{"file": p.get("filename"), "type": p.get("file_type"),
                                    "signature": p.get("signature"), "sha256": p.get("response_sha256")}
                                   for p in payloads[:10]]},
                tags=j.get("tags") or [], related=dedupe(related, 20),
                link=j.get("urlhaus_reference") or "https://urlhaus.abuse.ch/browse/",
            )

        urls = j.get("urls") or []
        return self.result(
            verdict="malicious", score=95,
            summary=f"Malware payload ({j.get('signature') or j.get('file_type') or 'unknown family'}) "
                    f"served from {j.get('url_count', len(urls))} URL(s)",
            data={"Signature": j.get("signature"), "File type": j.get("file_type"), "Size": j.get("file_size"),
                  "First seen": day(j.get("firstseen")), "Last seen": day(j.get("lastseen")),
                  "URL count": j.get("url_count"),
                  "URLs": [{"url": u.get("url"), "status": u.get("url_status")} for u in urls[:10]]},
            tags=uniq([j.get("signature")]),
            related=dedupe([rel("url", u["url"], "Distributed from (URLhaus)") for u in urls[:15] if u.get("url")], 15),
            link=f"https://urlhaus.abuse.ch/browse.php?search={ioc.value}",
        )


class ThreatFox(_AbuseCH):
    id = "threatfox"
    name = "ThreatFox"
    category = "feeds"
    types = frozenset({"ip", "domain", "url", "md5", "sha256", "sha1"})
    weight = 0.95
    homepage = "https://threatfox.abuse.ch"
    description = "abuse.ch IOC sharing platform: botnet C2 servers, payload delivery sites, malware hashes."

    async def lookup(self, ioc, ctx):
        if ioc.type == "sha1":
            raise Unsupported("ThreatFox indexes MD5 and SHA256 only")
        if ioc.is_hash:
            body = {"query": "search_hash", "hash": ioc.value}
        else:
            body = {"query": "search_ioc", "search_term": ioc.value, "exact_match": ioc.type != "ip"}
        j = await self.request(ctx, "POST", "https://threatfox-api.abuse.ch/api/v1/", content=json.dumps(body),
                               headers={**self.auth, "Content-Type": "application/json"})
        status = j.get("query_status")
        data = j.get("data") if isinstance(j.get("data"), list) else []
        if ioc.type == "ip":
            data = [d for d in data if str(d.get("ioc", "")).rsplit(":", 1)[0] == ioc.value or d.get("ioc") == ioc.value]
        link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc.value}"
        if status not in ("ok",) or not data:
            if status in ("ok", "no_result", "no_results"):
                return self.result(verdict="clean", summary="Not listed in ThreatFox", link=link)
            raise SourceError(f"ThreatFox: {status}")

        malware = Counter(d.get("malware_printable") for d in data if d.get("malware_printable"))
        threat_types = uniq(d.get("threat_type_desc") or d.get("threat_type") for d in data)
        confidence = max(int(d.get("confidence_level") or 0) for d in data)
        is_c2 = any(d.get("threat_type") == "botnet_cc" for d in data)
        rows = [{"ioc": d.get("ioc"), "type": d.get("ioc_type"), "threat": d.get("threat_type"),
                 "malware": d.get("malware_printable"), "confidence": d.get("confidence_level"),
                 "first_seen": day(d.get("first_seen")), "last_seen": day(d.get("last_seen"))} for d in data[:20]]
        related = []
        if ioc.is_hash:
            score = 95
            for d in data[:25]:
                value, kind = str(d.get("ioc") or ""), d.get("ioc_type") or ""
                if kind == "ip:port":
                    related.append(rel("ip", value.rsplit(":", 1)[0], f"C2 of this sample ({d.get('malware_printable')})"))
                elif kind in ("domain", "url"):
                    related.append(rel(kind, value, f"C2/delivery of this sample ({d.get('malware_printable')})"))
            summary = f"Sample linked to {len(data)} IOC(s) of {', '.join(m for m, _ in malware.most_common(2))}"
        else:
            score = max(confidence, 85 if is_c2 else 60)
            families = ", ".join(m for m, _ in malware.most_common(3)) or "malware"
            summary = f"{'Botnet C2' if is_c2 else 'Malicious IOC'} for {families} (confidence {confidence}%)"
        tags = [m for m, _ in malware.most_common(5)] + uniq(t for d in data for t in (d.get("tags") or []))[:5]
        return self.result(
            verdict="malicious", score=score, summary=summary,
            data={"Malware": [m for m, _ in malware.most_common(10)], "Threat types": threat_types,
                  "Max confidence": f"{confidence}%", "Matches": len(data), "IOCs": rows},
            tags=uniq(tags, 10), related=dedupe(related, 25), link=link,
        )


class MalwareBazaar(_AbuseCH):
    id = "malwarebazaar"
    name = "MalwareBazaar"
    category = "feeds"
    types = frozenset({"md5", "sha1", "sha256"})
    weight = 1.0
    homepage = "https://bazaar.abuse.ch"
    description = "abuse.ch repository of confirmed malware samples with family, YARA and vendor intel."

    async def lookup(self, ioc, ctx):
        j = await self.request(ctx, "POST", "https://mb-api.abuse.ch/api/v1/",
                               data={"query": "get_info", "hash": ioc.value}, headers=self.auth)
        status = j.get("query_status")
        if status != "ok" or not j.get("data"):
            if status in ("hash_not_found", "no_results"):
                return self.result(verdict="unknown", status="not_found", summary="Sample not in MalwareBazaar",
                                   link="https://bazaar.abuse.ch/browse/")
            raise SourceError(f"MalwareBazaar: {status}")
        d = j["data"][0]
        intel = d.get("intelligence") or {}
        signature = d.get("signature")
        return self.result(
            verdict="malicious", score=100,
            summary=f"Confirmed malware sample: {signature or d.get('file_type') or 'unknown family'}",
            data={"Signature": signature, "File name": d.get("file_name"), "File type": d.get("file_type"),
                  "MIME": d.get("file_type_mime"), "Size (bytes)": d.get("file_size"),
                  "First seen": day(d.get("first_seen")), "Delivery": d.get("delivery_method"),
                  "Origin country": d.get("origin_country"),
                  "YARA rules": uniq((y.get("rule_name") for y in d.get("yara_rules") or []), 10),
                  "ClamAV": intel.get("clamav"), "Downloads": intel.get("downloads"),
                  "Hashes": {"md5": d.get("md5_hash"), "sha1": d.get("sha1_hash"), "sha256": d.get("sha256_hash"),
                             "imphash": d.get("imphash"), "ssdeep": d.get("ssdeep"), "tlsh": d.get("tlsh")}},
            tags=uniq([signature] + list(d.get("tags") or []), 10),
            link=f"https://bazaar.abuse.ch/sample/{d.get('sha256_hash') or ioc.value}/",
        )


class FeodoTracker(Source):
    id = "feodo"
    name = "Feodo Tracker"
    category = "feeds"
    types = frozenset({"ip"})
    weight = 1.0
    homepage = "https://feodotracker.abuse.ch"
    description = "abuse.ch blocklist of botnet C2 servers (Dridex, Emotet, QakBot, Pikabot...). No key needed."

    @staticmethod
    def _parse(raw: str) -> dict:
        return {e["ip_address"]: e for e in json.loads(raw) if isinstance(e, dict) and e.get("ip_address")}

    async def lookup(self, ioc, ctx):
        table = await ctx.feeds.get("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                                    self._parse, ttl=3600)
        entry = table.get(ioc.value)
        if not entry:
            return self.result(verdict="clean", summary="Not on the Feodo Tracker botnet C2 blocklist",
                               data={"Blocklist size": len(table)}, link=self.homepage)
        online = entry.get("status") == "online"
        return self.result(
            verdict="malicious", score=95 if online else 85,
            summary=f"Botnet C2 server for {entry.get('malware')} ({entry.get('status')})",
            data={"Malware": entry.get("malware"), "Port": entry.get("port"), "Status": entry.get("status"),
                  "First seen": day(entry.get("first_seen")), "Last online": entry.get("last_online"),
                  "AS": entry.get("as_name"), "Country": entry.get("country")},
            tags=uniq([entry.get("malware"), "botnet-c2"]),
            link=f"https://feodotracker.abuse.ch/browse/host/{ioc.value}/",
        )

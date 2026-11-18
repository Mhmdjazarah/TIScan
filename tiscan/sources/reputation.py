"""Reputation sources: multi-engine verdicts and community threat intelligence."""
from __future__ import annotations

import base64
import hashlib
from collections import Counter
from urllib.parse import quote

from ..config import settings
from ..ioc import parse_ip, registered_domain
from .base import NotFound, Source, SourceError, Unsupported, day, dedupe, fmt_ts, rel, uniq

HASHES = frozenset({"md5", "sha1", "sha256"})

ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
    23: "IoT Targeted",
}


class VirusTotal(Source):
    id = "virustotal"
    name = "VirusTotal"
    category = "reputation"
    types = frozenset({"ip", "domain", "url"}) | HASHES
    weight = 1.0
    key_env = "VT_API_KEY"
    key_required = True
    homepage = "https://www.virustotal.com"
    signup = "https://www.virustotal.com/gui/join-us"
    description = "Verdicts from 70+ antivirus engines and URL/domain blocklists."

    def rate_limit(self) -> float:
        return settings.vt_rate_per_min

    async def lookup(self, ioc, ctx):
        v = ioc.value
        if ioc.type == "ip":
            path, gui = f"ip_addresses/{v}", f"ip-address/{v}"
        elif ioc.type == "domain":
            path, gui = f"domains/{v}", f"domain/{v}"
        elif ioc.type == "url":
            url_id = base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
            path, gui = f"urls/{url_id}", f"url/{hashlib.sha256(v.encode()).hexdigest()}"
        else:
            path, gui = f"files/{v}", f"file/{v}"
        try:
            j = await self.request(ctx, "GET", f"https://www.virustotal.com/api/v3/{path}",
                                   headers={"x-apikey": self.key})
        except NotFound:
            raise NotFound("Not in the VirusTotal dataset (never submitted)") from None

        a = (j.get("data") or {}).get("attributes") or {}
        stats = a.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected"))
        flagged = sorted(
            f"{engine}: {res.get('result') or res.get('category')}"
            for engine, res in (a.get("last_analysis_results") or {}).items()
            if res.get("category") in ("malicious", "suspicious")
        )
        votes = a.get("total_votes") or {}
        data = {
            "Detections": f"{mal}/{total}",
            "Suspicious": sus,
            "Reputation": a.get("reputation"),
            "Community votes": f"{votes.get('harmless', 0)} harmless / {votes.get('malicious', 0)} malicious",
            "Last analysis": fmt_ts(a.get("last_analysis_date")),
        }
        tags = list(a.get("tags") or [])
        related = []
        if ioc.type == "ip":
            data.update({"Owner": a.get("as_owner"), "ASN": a.get("asn"), "Country": a.get("country"),
                         "Network": a.get("network")})
        elif ioc.type == "domain":
            data.update({"Registrar": a.get("registrar"), "Created": fmt_ts(a.get("creation_date")),
                         "Categories": sorted(set((a.get("categories") or {}).values()))})
            for rec in a.get("last_dns_records") or []:
                if rec.get("type") in ("A", "AAAA") and rec.get("value"):
                    related.append(rel("ip", rec["value"], f"DNS {rec['type']} (VirusTotal)"))
        elif ioc.type == "url":
            data.update({"Final URL": a.get("last_final_url"), "Page title": a.get("title"),
                         "Categories": sorted(set((a.get("categories") or {}).values()))})
        else:
            label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label")
            if label:
                tags.insert(0, label)
            data.update({
                "Threat label": label, "Name": a.get("meaningful_name"), "File type": a.get("type_description"),
                "Size (bytes)": a.get("size"), "First seen": fmt_ts(a.get("first_submission_date")),
                "Names": (a.get("names") or [])[:8], "MD5": a.get("md5"), "SHA1": a.get("sha1"),
                "SHA256": a.get("sha256"),
            })
        data["Flagged by"] = flagged[:30]

        if mal >= 3:
            verdict = "malicious"
        elif mal >= 1 or sus >= 2:
            verdict = "suspicious"
        else:
            verdict = "clean" if total else "unknown"
        summary = f"{mal}/{total} engines flagged it malicious" + (f", {sus} suspicious" if sus else "")
        return self.result(verdict=verdict, score=min(100, mal * 12 + sus * 5), summary=summary, data=data,
                           tags=uniq(tags, 12), related=related, link=f"https://www.virustotal.com/gui/{gui}")


class AbuseIPDB(Source):
    id = "abuseipdb"
    name = "AbuseIPDB"
    category = "reputation"
    types = frozenset({"ip"})
    weight = 0.85
    key_env = "ABUSEIPDB_API_KEY"
    key_required = True
    homepage = "https://www.abuseipdb.com"
    signup = "https://www.abuseipdb.com/register"
    description = "Crowd-sourced abuse reports (brute force, scanning, spam) for IP addresses."

    async def lookup(self, ioc, ctx):
        j = await self.request(
            ctx, "GET", "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ioc.value, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": self.key, "Accept": "application/json"},
        )
        d = j.get("data") or {}
        conf = int(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        cats = Counter()
        for report in d.get("reports") or []:
            for c in report.get("categories") or []:
                cats[ABUSEIPDB_CATEGORIES.get(c, f"Category {c}")] += 1
        top_cats = [name for name, _ in cats.most_common(6)]
        if conf >= 75:
            verdict = "malicious"
        elif conf >= 25:
            verdict = "suspicious"
        else:
            verdict = "clean"
        related = [rel("domain", h, "Reverse DNS (AbuseIPDB)") for h in (d.get("hostnames") or [])[:5]]
        summary = (f"Abuse confidence {conf}% from {reports} report(s)" if reports
                   else "No abuse reports in the last 90 days")
        return self.result(
            verdict=verdict, score=conf, benign=bool(d.get("isWhitelisted")), summary=summary,
            data={
                "Abuse confidence": f"{conf}%", "Reports (90d)": reports,
                "Distinct reporters": d.get("numDistinctUsers"), "Last reported": day(d.get("lastReportedAt")),
                "Attack categories": top_cats, "ISP": d.get("isp"), "Usage type": d.get("usageType"),
                "Domain": d.get("domain"), "Country": d.get("countryCode"), "Tor exit": d.get("isTor"),
                "Allow-listed": d.get("isWhitelisted"),
            },
            tags=top_cats[:4], related=related, link=f"https://www.abuseipdb.com/check/{ioc.value}",
        )


class OTX(Source):
    id = "otx"
    name = "AlienVault OTX"
    category = "reputation"
    types = frozenset({"ip", "domain", "url"}) | HASHES
    weight = 0.5
    key_env = "OTX_API_KEY"
    key_required = False
    homepage = "https://otx.alienvault.com"
    signup = "https://otx.alienvault.com/accounts/signup"
    description = "Open Threat Exchange community pulses: campaigns, malware families, adversaries."

    # OTX "validation" entries that mean known-good (others, e.g. tor_exits, are just context).
    ALLOW_LIST_SOURCES = {"whitelist", "false_positive", "majestic", "alexa", "akamai", "ad_network",
                          "tranco", "umbrella", "cisco_umbrella"}

    @staticmethod
    def _section(ioc) -> tuple[str, str]:
        if ioc.type == "ip":
            return ("IPv6" if ":" in ioc.value else "IPv4"), "ip"
        if ioc.type == "domain":
            return ("domain", "domain") if registered_domain(ioc.value) == ioc.value else ("hostname", "hostname")
        if ioc.type == "url":
            return "url", "url"
        return "file", "file"

    async def lookup(self, ioc, ctx):
        section, link_section = self._section(ioc)
        value = quote(ioc.value, safe="") if ioc.type == "url" else ioc.value
        headers = {"X-OTX-API-KEY": self.key} if self.key else {}
        j = await self.request(ctx, "GET", f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
                               headers=headers)
        pulse_info = j.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        count = int(pulse_info.get("count") or len(pulses))
        families, adversaries, tags = Counter(), Counter(), Counter()
        for p in pulses:
            for fam in p.get("malware_families") or []:
                families[fam.get("display_name") if isinstance(fam, dict) else str(fam)] += 1
            if p.get("adversary"):
                adversaries[p["adversary"]] += 1
            for t in p.get("tags") or []:
                tags[str(t).lower()] += 1
        entries = [v for v in (j.get("validation") or []) if isinstance(v, dict)]
        validation = [v.get("message") or v.get("name") or v.get("source") for v in entries]
        benign = any(v.get("source") in self.ALLOW_LIST_SOURCES for v in entries) or any(
            isinstance(f, dict) and f.get("assessment") == "accepted" for f in (j.get("false_positive") or [])
        )
        if any(v.get("source") == "tor_exits" for v in entries):
            tags["tor"] += 1

        score = 0 if count == 0 else 30 if count <= 2 else 50 if count <= 9 else 70
        if benign:
            score = min(score, 10)
        if count == 0 or benign:
            verdict = "clean"
        elif count >= 10 and families:
            verdict = "malicious"
        else:
            verdict = "suspicious"

        related = []
        if self.key and ioc.type in ("ip", "domain"):
            related = await self._passive_dns(ioc, section, ctx)

        summary = f"Referenced in {count} OTX pulse(s)" if count else "Not referenced in any OTX pulse"
        if benign:
            summary += " - allow-listed by OTX validation"
        data = {
            "Pulses": count,
            "Pulse names": uniq((p.get("name") for p in pulses), 12),
            "Malware families": [k for k, _ in families.most_common(10)],
            "Adversaries": [k for k, _ in adversaries.most_common(5)],
            "Validation": uniq(validation, 5),
        }
        if ioc.type == "ip":
            data.update({"Country": j.get("country_name"), "ASN": j.get("asn")})
        return self.result(
            verdict=verdict, score=score, benign=benign, summary=summary, data=data,
            tags=[k for k, _ in families.most_common(3)] + [k for k, _ in tags.most_common(5)],
            related=related,
            link=f"https://otx.alienvault.com/indicator/{link_section}/{quote(ioc.value, safe='')}",
        )

    async def _passive_dns(self, ioc, section, ctx) -> list[dict]:
        try:
            j = await self.request(ctx, "GET",
                                   f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc.value}/passive_dns",
                                   headers={"X-OTX-API-KEY": self.key})
        except SourceError:
            return []
        out = []
        for rec in (j.get("passive_dns") or [])[:300]:
            if ioc.type == "ip" and rec.get("hostname"):
                out.append(rel("domain", rec["hostname"].lower(), "Passive DNS (OTX)"))
            elif ioc.type == "domain" and rec.get("address") and parse_ip(rec["address"]):
                out.append(rel("ip", rec["address"], "Passive DNS (OTX)"))
        return dedupe(out, 25)


class GreyNoise(Source):
    id = "greynoise"
    name = "GreyNoise"
    category = "reputation"
    types = frozenset({"ip"})
    weight = 0.6
    key_env = "GREYNOISE_API_KEY"
    key_required = False
    homepage = "https://viz.greynoise.io"
    signup = "https://viz.greynoise.io/signup"
    description = "Separates internet background noise (mass scanners) and known-benign services from targeted activity."

    async def lookup(self, ioc, ctx):
        if ":" in ioc.value:
            raise Unsupported("GreyNoise Community covers IPv4 only")
        headers = {"key": self.key} if self.key else {}
        resp = await self.request(ctx, "GET", f"https://api.greynoise.io/v3/community/{ioc.value}",
                                  headers=headers, allow=(404,), parse="raw")
        try:
            j = resp.json()
        except ValueError as exc:
            raise SourceError("Invalid response from GreyNoise") from exc
        link = j.get("link") or f"https://viz.greynoise.io/ip/{ioc.value}"
        if resp.status_code == 404:
            return self.result(verdict="clean", score=0, summary=j.get("message") or "Not observed scanning the internet",
                               data={"Internet scanner": False, "Known benign service (RIOT)": False}, link=link)
        classification = (j.get("classification") or "unknown").lower()
        noise, riot = bool(j.get("noise")), bool(j.get("riot"))
        benign = riot or classification == "benign"
        if classification == "malicious":
            verdict, score = "malicious", 65
        elif benign:
            verdict, score = "clean", 0
        elif noise:
            verdict, score = "suspicious", 25
        else:
            verdict, score = "info", 0
        actor = j.get("name")
        summary = {
            "malicious": "Malicious internet scanner observed by GreyNoise sensors",
            "benign": f"Known benign actor{f' ({actor})' if actor and actor != 'unknown' else ''}",
        }.get(classification, "Unclassified internet scanner" if noise else "Known business service (RIOT)" if riot else "No classification")
        return self.result(
            verdict=verdict, score=score, benign=benign, summary=summary,
            data={"Classification": classification, "Internet scanner": noise, "Known benign service (RIOT)": riot,
                  "Actor / service": actor, "Last seen": j.get("last_seen")},
            tags=[t for t in (classification if classification != "unknown" else None, "scanner" if noise else None) if t],
            link=link,
        )


class Pulsedive(Source):
    id = "pulsedive"
    name = "Pulsedive"
    category = "reputation"
    types = frozenset({"ip", "domain", "url"})
    weight = 0.6
    key_env = "PULSEDIVE_API_KEY"
    key_required = False
    homepage = "https://pulsedive.com"
    signup = "https://pulsedive.com/register"
    description = "Community threat-intel platform aggregating feeds, risk factors and linked threats."

    RISK = {"none": 0, "low": 20, "medium": 50, "high": 75, "critical": 95}

    async def lookup(self, ioc, ctx):
        params = {"indicator": ioc.value, "pretty": "0"}
        if self.key:
            params["key"] = self.key
        resp = await self.request(ctx, "GET", "https://pulsedive.com/api/info.php", params=params,
                                  allow=(404,), parse="raw")
        try:
            j = resp.json()
        except ValueError as exc:
            raise SourceError("Invalid response from Pulsedive") from exc
        if resp.status_code == 404 or j.get("error"):
            raise NotFound(j.get("error") or "Indicator not in Pulsedive")
        risk = (j.get("risk") or "unknown").lower()
        score = self.RISK.get(risk, 0)
        verdict = {"none": "clean", "low": "suspicious", "medium": "suspicious", "high": "malicious",
                   "critical": "malicious"}.get(risk, "unknown")
        threats = [t.get("name") for t in j.get("threats") or [] if t.get("name")]
        feeds = [f.get("name") for f in j.get("feeds") or [] if f.get("name")]
        factors = [f"{f.get('description')} ({f.get('risk')})" for f in j.get("riskfactors") or [] if f.get("description")]
        iid = j.get("iid")
        return self.result(
            verdict=verdict, score=score,
            summary=f"Pulsedive risk: {risk}" + (f" - linked to {', '.join(threats[:3])}" if threats else ""),
            data={"Risk": risk, "Risk factors": factors[:10], "Threats": threats[:10], "Feeds": feeds[:10],
                  "First added": day(j.get("stamp_added")), "Last seen": day(j.get("stamp_seen")),
                  "Umbrella rank": j.get("umbrella_rank")},
            tags=threats[:5],
            link=f"https://pulsedive.com/indicator/?iid={iid}" if iid else "https://pulsedive.com",
        )


class URLScan(Source):
    id = "urlscan"
    name = "urlscan.io"
    category = "reputation"
    category = "infrastructure"
    types = frozenset({"ip", "domain", "url"})
    weight = 0.0
    key_env = "URLSCAN_API_KEY"
    key_required = False
    homepage = "https://urlscan.io"
    signup = "https://urlscan.io/user/signup"
    description = "Historical sandboxed page scans: hosting IPs, page titles, screenshots."

    @staticmethod
    def _query(ioc) -> str:
        if ioc.type == "ip":
            return f'page.ip:"{ioc.value}"'
        if ioc.type == "domain":
            return f"page.domain:{ioc.value}"
        escaped = ioc.value.replace("\\", "\\\\").replace('"', '\\"')
        return f'page.url:"{escaped}"'

    async def lookup(self, ioc, ctx):
        query = self._query(ioc)
        headers = {"API-Key": self.key} if self.key else {}
        j = await self.request(ctx, "GET", "https://urlscan.io/api/v1/search/", params={"q": query, "size": 25},
                               headers=headers)
        results = j.get("results") or []
        total = int(j.get("total") or len(results))
        rows, related, titles = [], [], []
        for r in results[:12]:
            page, task = r.get("page") or {}, r.get("task") or {}
            rows.append({"date": day(task.get("time")), "url": page.get("url") or task.get("url"),
                         "title": (page.get("title") or "")[:80], "ip": page.get("ip"),
                         "country": page.get("country"), "status": page.get("status"),
                         "report": (r.get("result") or "").replace("/api/v1/result/", "/result/")})
            titles.append(page.get("title"))
            if ioc.type != "ip" and page.get("ip"):
                related.append(rel("ip", page["ip"], "Hosting IP (urlscan.io)"))
            if ioc.type == "ip" and page.get("domain"):
                related.append(rel("domain", page["domain"].lower(), "Hosted domain (urlscan.io)"))
        first = results[0] if results else {}
        summary = (f"{total} historical scan(s), latest {rows[0]['date']}" if rows
                   else "Never scanned on urlscan.io")
        return self.result(
            verdict="info" if total else "unknown", score=0, summary=summary,
            data={"Scans": total, "Page titles": uniq(titles, 6),
                  "Latest screenshot": first.get("screenshot"), "Recent scans": rows},
            related=dedupe(related, 20),
            link=f"https://urlscan.io/search/#{quote(query)}",
        )

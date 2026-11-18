"""Infrastructure context: DNS, protective DNS, RDAP/WHOIS, certificate transparency, geolocation, open ports."""
from __future__ import annotations

import asyncio
import base64
import re
import struct
from collections import Counter
from datetime import datetime, timezone

from ..ioc import parse_ip, registered_domain
from .base import NotFound, Source, SourceError, Unsupported, day, dedupe, parse_dt, rel, uniq

DOH_CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
DOH_CLOUDFLARE_SECURITY = "https://security.cloudflare-dns.com/dns-query"
DOH_QUAD9 = "https://dns.quad9.net/dns-query"
RR = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}


async def doh(ctx, name: str, rtype: str, server: str = DOH_CLOUDFLARE) -> dict:
    resp = await ctx.client.get(server, params={"name": name, "type": rtype},
                                headers={"accept": "application/dns-json"}, timeout=10)
    if resp.status_code >= 400:
        raise SourceError(f"DNS-over-HTTPS HTTP {resp.status_code}")
    return resp.json()


async def doh_wire(ctx, name: str, server: str = DOH_QUAD9) -> dict:
    """RFC 8484 wire-format A query (for resolvers without a JSON API). Returns {Status, answers}."""
    labels = [p.encode("ascii") for p in name.rstrip(".").split(".") if p]
    if any(len(p) > 63 for p in labels):
        raise SourceError("Invalid DNS label")
    packet = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    packet += b"".join(bytes([len(p)]) + p for p in labels) + b"\x00" + struct.pack(">HH", 1, 1)
    query = base64.urlsafe_b64encode(packet).rstrip(b"=").decode()
    resp = await ctx.client.get(server, params={"dns": query}, headers={"accept": "application/dns-message"},
                                timeout=10)
    if resp.status_code >= 400 or len(resp.content) < 12:
        raise SourceError(f"DNS-over-HTTPS HTTP {resp.status_code}")
    flags, _qd, ancount = struct.unpack(">HHH", resp.content[2:8])
    return {"Status": flags & 0x000F, "answers": ancount}


def answers(reply: dict, rtype: str) -> list[str]:
    return [str(a.get("data", "")) for a in reply.get("Answer") or [] if a.get("type") == RR[rtype]]


def txt_value(data: str) -> str:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts) if parts else data


def dns_host(ioc) -> str:
    host = ioc.host
    if not host or parse_ip(host) is not None:
        raise Unsupported("No hostname to resolve (the URL uses a raw IP)")
    return host


class DNSRecords(Source):
    id = "dns"
    name = "DNS records"
    category = "infrastructure"
    types = frozenset({"domain", "url"})
    weight = 0.0
    homepage = "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/"
    description = "Live A/AAAA/CNAME/MX/NS/TXT, SPF and DMARC records over DNS-over-HTTPS."

    async def lookup(self, ioc, ctx):
        host = dns_host(ioc)
        apex = registered_domain(host)
        queries = [(host, "A"), (host, "AAAA"), (host, "CNAME"), (apex, "MX"), (apex, "NS"), (apex, "TXT"),
                   (f"_dmarc.{apex}", "TXT")]
        replies = await asyncio.gather(*(doh(ctx, n, t) for n, t in queries), return_exceptions=True)
        if all(isinstance(r, Exception) for r in replies):
            raise SourceError(f"DNS lookups failed: {replies[0]}")
        rep = {f"{n}|{t}": (r if isinstance(r, dict) else {}) for (n, t), r in zip(queries, replies)}
        a_reply = rep[f"{host}|A"]
        if a_reply.get("Status") == 3:
            return self.result(verdict="info", summary="Domain does not resolve (NXDOMAIN) - possibly taken down or never existed",
                               data={"Status": "NXDOMAIN"}, link=f"https://dns.google/query?name={host}")

        a = answers(a_reply, "A")
        aaaa = answers(rep[f"{host}|AAAA"], "AAAA")
        cname = [c.rstrip(".") for c in answers(rep[f"{host}|CNAME"], "CNAME") + answers(a_reply, "CNAME")]
        mx_raw = answers(rep[f"{apex}|MX"], "MX")
        mx = []
        for m in mx_raw:
            parts = m.split()
            if len(parts) == 2 and parts[1] not in (".", ""):
                mx.append((parts[1].rstrip("."), parts[0]))
        ns = [n.rstrip(".").lower() for n in answers(rep[f"{apex}|NS"], "NS")]
        txt = [txt_value(t) for t in answers(rep[f"{apex}|TXT"], "TXT")]
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
        dmarc = next((txt_value(t) for t in answers(rep[f"_dmarc.{apex}|TXT"], "TXT")
                      if txt_value(t).lower().startswith("v=dmarc1")), None)

        related = [rel("ip", ip, "DNS A record") for ip in a] + [rel("ip", ip, "DNS AAAA record") for ip in aaaa]
        related += [rel("domain", c.lower(), "CNAME target") for c in cname]
        related += [rel("domain", h.lower(), "Mail server (MX)") for h, _ in mx]
        related += [rel("domain", n, "Name server (NS)") for n in ns]
        return self.result(
            verdict="info",
            summary=f"{len(a)} A, {len(aaaa)} AAAA, {len(mx)} MX, {len(ns)} NS record(s)"
                    + ("" if spf else " - no SPF") + ("" if dmarc else ", no DMARC"),
            data={"A": a, "AAAA": aaaa, "CNAME": uniq(cname), "MX": [f"{h} (pref {p})" for h, p in mx],
                  "NS": ns, "SPF": spf or "missing", "DMARC": dmarc or "missing",
                  "TXT": [t[:200] for t in txt[:12]]},
            related=dedupe(related, 40), link=f"https://dns.google/query?name={host}",
        )


class ProtectiveDNS(Source):
    id = "protective_dns"
    name = "Protective DNS"
    category = "reputation"
    types = frozenset({"domain", "url"})
    weight = 0.8
    homepage = "https://quad9.net"
    description = "Asks Cloudflare 1.1.1.2 and Quad9 9.9.9.9 - resolvers that block malware/phishing domains."

    async def lookup(self, ioc, ctx):
        host = dns_host(ioc)
        plain, cf, q9 = await asyncio.gather(
            doh(ctx, host, "A"), doh(ctx, host, "A", DOH_CLOUDFLARE_SECURITY), doh_wire(ctx, host),
            return_exceptions=True,
        )
        if all(isinstance(r, Exception) for r in (plain, cf, q9)):
            raise SourceError("All protective resolvers failed")
        resolves = isinstance(plain, dict) and plain.get("Status") == 0 and bool(answers(plain, "A"))
        nxdomain = isinstance(plain, dict) and plain.get("Status") == 3
        cf_block = isinstance(cf, dict) and "0.0.0.0" in answers(cf, "A")
        q9_block = isinstance(q9, dict) and resolves and q9.get("Status") == 3

        def state(reply, blocked):
            return "error" if isinstance(reply, Exception) else "BLOCKED" if blocked else "allowed"

        data = {"Cloudflare 1.1.1.2": state(cf, cf_block), "Quad9 9.9.9.9": state(q9, q9_block),
                "Resolves publicly": resolves}
        blocked_by = [name for name, hit in (("Cloudflare", cf_block), ("Quad9", q9_block)) if hit]
        if blocked_by:
            return self.result(verdict="malicious", score=92 if len(blocked_by) == 2 else 80,
                               summary=f"Blocked as malicious by {' and '.join(blocked_by)} threat-blocking DNS",
                               data=data, tags=["dns-blocked"], link=f"https://www.quad9.net/result/?url={host}")
        if nxdomain:
            return self.result(verdict="info", summary="Domain does not resolve (NXDOMAIN)", data=data,
                               link=self.homepage)
        return self.result(verdict="clean", summary="Not blocked by Cloudflare or Quad9 threat-blocking DNS",
                           data=data, link=f"https://www.quad9.net/result/?url={host}")


def _vcard(entity: dict, field: str):
    card = entity.get("vcardArray")
    if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
        for item in card[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == field:
                return item[3]
    return None


def _entities(obj: dict, role: str) -> list[dict]:
    found = []
    for ent in obj.get("entities") or []:
        if role in (ent.get("roles") or []):
            found.append(ent)
        found.extend(_entities(ent, role))
    return found


def _events(obj: dict) -> dict:
    return {e.get("eventAction"): e.get("eventDate") for e in obj.get("events") or [] if e.get("eventAction")}


class RDAP(Source):
    id = "rdap"
    name = "WHOIS / RDAP"
    category = "infrastructure"
    types = frozenset({"domain", "ip"})
    weight = 0.6
    ttl = 24 * 3600
    homepage = "https://rdap.org"
    description = "Registration data: registrar, creation date (newly-registered domains are risky), network owner."

    async def lookup(self, ioc, ctx):
        if ioc.type == "ip":
            return await self._ip(ioc, ctx)
        apex = registered_domain(ioc.value)
        try:
            j = await self.request(ctx, "GET", f"https://rdap.org/domain/{apex}", timeout=25)
        except NotFound:
            raise NotFound("No RDAP record (unregistered domain, or the TLD has no RDAP service)") from None
        ev = _events(j)
        registrar = next((_vcard(e, "fn") for e in _entities(j, "registrar")), None)
        abuse = next((_vcard(e, "email") for e in _entities(j, "abuse") if _vcard(e, "email")), None)
        created = parse_dt(ev.get("registration"))
        age = (datetime.now(timezone.utc) - created).days if created else None
        if age is not None and age < 7:
            verdict, score, note = "suspicious", 60, f"Newly registered domain ({age} days old)"
        elif age is not None and age < 30:
            verdict, score, note = "suspicious", 45, f"Recently registered domain ({age} days old)"
        elif age is not None and age < 90:
            verdict, score, note = "info", 20, f"Young domain ({age} days old)"
        else:
            verdict, score = "info", 0
            note = f"Registered {age // 365} year(s) ago" if age is not None else "Registration date not published"
        return self.result(
            verdict=verdict, score=score, summary=f"{note} via {registrar or 'unknown registrar'}",
            data={"Domain": apex, "Registrar": registrar, "Created": day(ev.get("registration")),
                  "Expires": day(ev.get("expiration")), "Updated": day(ev.get("last changed")),
                  "Age (days)": age, "Status": j.get("status") or [],
                  "Name servers": [n.get("ldhName", "").lower() for n in j.get("nameservers") or []],
                  "DNSSEC": (j.get("secureDNS") or {}).get("delegationSigned"), "Abuse contact": abuse},
            tags=["newly-registered"] if age is not None and age < 30 else [],
            link=f"https://lookup.icann.org/en/lookup?name={apex}",
        )

    async def _ip(self, ioc, ctx):
        j = await self.request(ctx, "GET", f"https://rdap.org/ip/{ioc.value}", timeout=25)
        cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in j.get("cidr0_cidrs") or []]
        org = next((_vcard(e, "fn") for e in _entities(j, "registrant")), None)
        abuse = next((_vcard(e, "email") for e in _entities(j, "abuse") if _vcard(e, "email")), None)
        ev = _events(j)
        return self.result(
            verdict="info",
            summary=f"Network {j.get('name') or j.get('handle')} ({', '.join(cidrs) or 'n/a'}) - {org or 'owner unknown'}",
            data={"Network name": j.get("name"), "Handle": j.get("handle"), "CIDR": cidrs,
                  "Range": f"{j.get('startAddress')} - {j.get('endAddress')}", "Owner": org,
                  "Country": j.get("country"), "Abuse contact": abuse, "Registered": day(ev.get("registration")),
                  "Updated": day(ev.get("last changed"))},
            link=f"https://bgp.he.net/ip/{ioc.value}",
        )


class CrtSh(Source):
    id = "crtsh"
    name = "crt.sh (Certificate Transparency)"
    category = "infrastructure"
    types = frozenset({"domain"})
    weight = 0.0
    ttl = 24 * 3600
    timeout = 45
    slow = True
    homepage = "https://crt.sh"
    description = "TLS certificates from public CT logs - reveals subdomains and certificate history."

    async def lookup(self, ioc, ctx):
        apex = registered_domain(ioc.value)
        last_error: Exception | None = None
        for _ in range(2):  # crt.sh is often overloaded; one retry helps a lot
            try:
                rows = await self.request(ctx, "GET", "https://crt.sh/", params={"q": f"%.{apex}", "output": "json"})
                break
            except SourceError as exc:
                last_error = exc
                await asyncio.sleep(1.5)
        else:
            raise SourceError(f"crt.sh unavailable ({last_error})")
        if not isinstance(rows, list):
            rows = []
        names, issuers, dates = set(), Counter(), []
        for r in rows:
            for n in str(r.get("name_value", "")).splitlines() + [str(r.get("common_name", ""))]:
                n = n.strip().lower().lstrip("*.")
                if n and (n == apex or n.endswith("." + apex)):
                    names.add(n)
            issuer = re.search(r"O=([^,]+)", str(r.get("issuer_name", "")))
            if issuer:
                issuers[issuer.group(1).strip('"')] += 1
            if r.get("not_before"):
                dates.append(r["not_before"])
        subs = sorted(names - {apex})
        return self.result(
            verdict="info", summary=f"{len(rows)} certificate(s), {len(subs)} unique subdomain(s) in CT logs",
            data={"Certificates": len(rows), "Subdomains found": len(subs),
                  "First certificate": day(min(dates)) if dates else None,
                  "Latest certificate": day(max(dates)) if dates else None,
                  "Issuers": [i for i, _ in issuers.most_common(6)], "Subdomains": subs[:300]},
            related=[rel("domain", s, "Subdomain (CT logs)") for s in subs[:40]],
            link=f"https://crt.sh/?q=%25.{apex}",
        )


class IPInfo(Source):
    id = "ipinfo"
    name = "IPinfo"
    category = "infrastructure"
    types = frozenset({"ip"})
    weight = 0.0
    key_env = "IPINFO_TOKEN"
    key_required = False
    ttl = 24 * 3600
    homepage = "https://ipinfo.io"
    signup = "https://ipinfo.io/signup"
    description = "Geolocation, ASN/organisation and reverse DNS for IP addresses."

    async def lookup(self, ioc, ctx):
        params = {"token": self.key} if self.key else None
        j = await self.request(ctx, "GET", f"https://ipinfo.io/{ioc.value}/json", params=params)
        if j.get("bogon"):
            raise Unsupported("Bogon (non-routable) address")
        loc = ", ".join(x for x in (j.get("city"), j.get("region"), j.get("country")) if x)
        hostname = j.get("hostname")
        return self.result(
            verdict="info", summary=f"{j.get('org') or 'Unknown org'} - {loc or 'location unknown'}",
            data={"Organisation / ASN": j.get("org"), "Hostname (PTR)": hostname, "City": j.get("city"),
                  "Region": j.get("region"), "Country": j.get("country"), "Coordinates": j.get("loc"),
                  "Timezone": j.get("timezone"), "Anycast": j.get("anycast")},
            related=[rel("domain", hostname.lower(), "Reverse DNS (PTR)")] if hostname else [],
            link=f"https://ipinfo.io/{ioc.value}",
        )


class Shodan(Source):
    id = "shodan"
    name = "Shodan"
    category = "infrastructure"
    types = frozenset({"ip"})
    weight = 0.5
    key_env = "SHODAN_API_KEY"
    key_required = False
    ttl = 12 * 3600
    homepage = "https://www.shodan.io"
    signup = "https://account.shodan.io/register"
    description = "Open ports, services, CVEs and tags. Uses the free InternetDB without a key, the full API with one."

    BAD_TAGS = {"c2", "malware", "compromised", "doublepulsar"}
    GREY_TAGS = {"scanner", "tor", "proxy", "honeypot"}

    async def lookup(self, ioc, ctx):
        if self.key:
            j = await self.request(ctx, "GET", f"https://api.shodan.io/shodan/host/{ioc.value}",
                                   params={"key": self.key, "minify": "true"})
            ports, vulns = j.get("ports") or [], list(j.get("vulns") or [])
            hostnames, tags, cpes = j.get("hostnames") or [], j.get("tags") or [], []
            extra = {"Organisation": j.get("org"), "ISP": j.get("isp"), "OS": j.get("os"),
                     "Last update": day(j.get("last_update"))}
        else:
            try:
                j = await self.request(ctx, "GET", f"https://internetdb.shodan.io/{ioc.value}")
            except NotFound:
                raise NotFound("No open ports or services indexed by Shodan") from None
            ports, vulns, hostnames = j.get("ports") or [], j.get("vulns") or [], j.get("hostnames") or []
            tags, cpes, extra = j.get("tags") or [], j.get("cpes") or [], {}
        tagset = {t.lower() for t in tags}
        if tagset & self.BAD_TAGS:
            verdict, score = "malicious", 75
        elif tagset & self.GREY_TAGS:
            verdict, score = "suspicious", 25
        else:
            verdict, score = "info", 0
        summary = f"{len(ports)} open port(s)" + (f", {len(vulns)} known CVE(s)" if vulns else "")
        if tags:
            summary += f" - tags: {', '.join(tags[:4])}"
        return self.result(
            verdict=verdict, score=score, summary=summary,
            data={"Open ports": sorted(ports), "CVEs": sorted(vulns)[:40], "Hostnames": hostnames[:15],
                  "Tags": tags, "CPEs": cpes[:15], **extra},
            tags=tags[:6], related=[rel("domain", h.lower(), "Hostname (Shodan)") for h in hostnames[:10]],
            link=f"https://www.shodan.io/host/{ioc.value}",
        )


DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "trashmail.com", "getnada.com", "dispostable.com", "sharklasers.com",
    "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mintemail.com", "mohmal.com", "emailondeck.com",
    "tempinbox.com", "spamgourmet.com", "mailnesia.com", "moakt.com", "tempr.email", "discard.email",
    "burnermail.io", "mail.tm", "1secmail.com", "inboxkitten.com", "harakirimail.com", "33mail.com",
}
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.ru",
    "yandex.com", "yandex.ru", "zoho.com", "tutanota.com", "mail.com",
}


class MailSecurity(Source):
    id = "mail_security"
    name = "Email domain checks"
    category = "infrastructure"
    types = frozenset({"email"})
    weight = 0.5
    homepage = "https://dmarc.org"
    description = "MX, SPF and DMARC posture of the sender domain, plus disposable / free-mail detection."

    async def lookup(self, ioc, ctx):
        domain = ioc.value.rsplit("@", 1)[1]
        mx_r, txt_r, dmarc_r = await asyncio.gather(
            doh(ctx, domain, "MX"), doh(ctx, domain, "TXT"), doh(ctx, f"_dmarc.{domain}", "TXT"),
            return_exceptions=True,
        )
        mx_r, txt_r, dmarc_r = (r if isinstance(r, dict) else {} for r in (mx_r, txt_r, dmarc_r))
        mx = [m.split()[-1].rstrip(".") for m in answers(mx_r, "MX") if m.split()[-1] not in (".", "")]
        spf = next((txt_value(t) for t in answers(txt_r, "TXT") if txt_value(t).lower().startswith("v=spf1")), None)
        dmarc = next((txt_value(t) for t in answers(dmarc_r, "TXT") if txt_value(t).lower().startswith("v=dmarc1")), None)
        policy = (re.search(r"\bp=(\w+)", dmarc or "") or [None, None])[1]
        disposable = domain in DISPOSABLE
        notes, score = [], 0
        if disposable:
            notes.append("disposable mailbox provider")
            score = 35
        if not mx:
            notes.append("domain cannot receive mail (no MX)")
            score = max(score, 25)
        if not dmarc or policy == "none":
            notes.append("no enforced DMARC - domain is easy to spoof")
        verdict = "suspicious" if score else "info"
        summary = "; ".join(notes) if notes else "Mail domain has MX, SPF and enforced DMARC"
        return self.result(
            verdict=verdict, score=score, summary=summary[:1].upper() + summary[1:],
            data={"Domain": domain, "MX": mx, "SPF": spf or "missing", "DMARC": dmarc or "missing",
                  "DMARC policy": policy or "none", "Disposable provider": disposable,
                  "Free webmail": domain in FREE_PROVIDERS},
            tags=["disposable-email"] if disposable else [],
            related=[rel("domain", domain, "Email domain")],
            link=f"https://dns.google/query?name=_dmarc.{domain}&rr_type=TXT",
        )

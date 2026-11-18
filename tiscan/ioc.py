"""Indicator of Compromise (IOC) detection, normalisation, refanging and extraction."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HASH_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_TYPES = frozenset(HASH_BY_LEN.values())
IOC_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "email", "keyword")

# Multi-label public suffixes that matter most for this tool (MENA + common ccSLDs).
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "co.kr", "co.nz", "co.za", "co.in", "co.id", "co.il", "co.ke",
    "com.br", "com.cn", "com.tr", "com.mx", "com.ar", "com.co", "com.pk", "com.ng", "com.sg",
    "com.my", "com.hk", "com.tw", "com.ua", "com.ru", "com.pl", "com.vn", "com.ph",
    "com.jo", "net.jo", "org.jo", "gov.jo", "edu.jo", "mil.jo", "name.jo", "sch.jo",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "med.sa", "pub.sa", "sch.sa",
    "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae", "sch.ae", "mil.ae",
    "com.kw", "net.kw", "org.kw", "gov.kw", "edu.kw",
    "com.qa", "net.qa", "org.qa", "gov.qa", "edu.qa",
    "com.bh", "net.bh", "org.bh", "gov.bh", "edu.bh",
    "com.om", "net.om", "org.om", "gov.om", "edu.om", "co.om",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg", "sci.eg",
    "com.lb", "net.lb", "org.lb", "gov.lb", "edu.lb",
    "com.iq", "net.iq", "org.iq", "gov.iq", "edu.iq",
    "com.ps", "net.ps", "org.ps", "gov.ps", "edu.ps",
    "com.sy", "gov.sy", "edu.sy", "com.ye", "gov.ye", "com.ly", "gov.ly",
    "com.tn", "gov.tn", "co.ma", "gov.ma", "ac.ma", "com.dz", "gov.dz", "com.sd", "gov.sd",
}

# Shared hosting platforms (Public Suffix List "private" section): each customer subdomain is its own site.
# Without these, ramixa-site.onrender.com would be looked up as onrender.com - every Render customer at once.
_PLATFORM_SUFFIXES = {
    "onrender.com", "herokuapp.com", "vercel.app", "netlify.app", "github.io", "gitlab.io", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "azurewebsites.net", "azurestaticapps.net", "cloudfront.net",
    "appspot.com", "fly.dev", "railway.app", "up.railway.app", "koyeb.app", "deno.dev", "glitch.me", "repl.co",
    "replit.app", "replit.dev", "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "webflow.io",
    "framer.website", "carrd.co", "notion.site", "myshopify.com", "surge.sh", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "r2.dev", "supabase.co", "pythonanywhere.com", "000webhostapp.com", "hf.space",
}
_SUFFIXES = _MULTI_SUFFIXES | _PLATFORM_SUFFIXES

# File extensions that are also TLDs and cause false positives when extracting from text.
_EXTRACT_TLD_DENY = {"zip", "mov", "md", "py", "exe", "dll"}

_REFANG_RULES = [
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bh\[tt\]p(s?)", re.I), r"http\1"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)|\{\s*(?:@|at)\s*\}", re.I), "@"),
]

_LABEL = r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)"
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
DOMAIN_RE = re.compile(rf"(?:{_LABEL}\.)+{_TLD}")
EMAIL_RE = re.compile(rf"[a-z0-9!#$%&'*+/=?^_`{{|}}~.-]{{1,64}}@(?:{_LABEL}\.)+{_TLD}")
HASH_RE = re.compile(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}")
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]{1,15}://", re.I)

_FIND_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\]\[{}|\\^]+", re.I)
_FIND_EMAIL = re.compile(rf"\b{EMAIL_RE.pattern}\b", re.I)
_FIND_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)")
_FIND_IPV6 = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])", re.I)
_FIND_HASH = re.compile(r"(?<![a-f0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])", re.I)
_FIND_DOMAIN = re.compile(rf"(?<![\w.@-]){DOMAIN_RE.pattern}(?![\w-])", re.I)


@lru_cache(maxsize=1)
def known_tlds() -> frozenset[str]:
    path = Path(__file__).with_name("data") / "tlds.txt"
    try:
        return frozenset(line.strip().lower() for line in path.read_text("utf-8").splitlines() if line.strip())
    except OSError:
        return frozenset()


def refang(text: str) -> str:
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, ioc_type: str) -> str:
    if ioc_type in HASH_TYPES or ioc_type == "keyword":
        return value
    out = value.replace(".", "[.]")
    if ioc_type == "url":
        out = re.sub(r"^http", "hxxp", out, flags=re.I).replace("://", "[://]", 1)
    if ioc_type == "email":
        out = out.replace("@", "[@]")
    return out


def registered_domain(host: str) -> str:
    """The domain an organisation actually controls: example.co.uk, bank.com.jo, mysite.onrender.com."""
    labels = host.lower().rstrip(".").split(".")
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in _SUFFIXES:
            return ".".join(labels[-(n + 1):])
    return ".".join(labels[-2:])


def parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    s = text.strip()
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]
    elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", s):
        s = s.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return None


def is_non_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
        or ip.is_link_local or ip.is_unspecified
    )


@dataclass(frozen=True)
class IOC:
    value: str
    type: str
    raw: str = ""
    private: bool = False

    @property
    def is_hash(self) -> bool:
        return self.type in HASH_TYPES

    @property
    def host(self) -> str | None:
        if self.type == "domain":
            return self.value
        if self.type == "url":
            return urlsplit(self.value).hostname
        if self.type == "email":
            return self.value.rsplit("@", 1)[1]
        if self.type == "ip":
            return self.value
        return None

    @property
    def host_is_ip(self) -> bool:
        host = self.host
        return bool(host) and parse_ip(host) is not None

    @property
    def domain(self) -> str | None:
        """Registered (apex) domain behind this IOC, if any."""
        host = self.host
        if not host or parse_ip(host) is not None:
            return None
        return registered_domain(host)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "defanged": defang(self.value, self.type),
            "private": self.private,
            "domain": self.domain,
        }


def _url_ioc(url: str, raw: str) -> IOC:
    parts = urlsplit(url.strip())
    host = parts.hostname
    if not host:
        raise ValueError("URL has no host")
    netloc = parts.netloc.lower() if "@" not in parts.netloc else parts.netloc
    value = urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))
    ip = parse_ip(host)
    return IOC(value, "url", raw, private=bool(ip and is_non_public(ip)))


def _to_idna(host: str) -> str:
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def detect(raw: str, allow_keyword: bool = False) -> IOC:
    """Classify a single user-supplied indicator. Raises ValueError if it is not recognised."""
    s = refang((raw or "").strip()).strip().strip("'\"<>`").strip()
    if not s:
        raise ValueError("Empty indicator")
    if len(s) > 2048:
        raise ValueError("Indicator is too long")
    low = s.lower()

    if HASH_RE.fullmatch(low):
        return IOC(low, HASH_BY_LEN[len(low)], raw)

    ip = parse_ip(s)
    if ip is not None:
        return IOC(str(ip), "ip", raw, private=is_non_public(ip))

    if SCHEME_RE.match(s):
        return _url_ioc(s, raw)

    if EMAIL_RE.fullmatch(low):
        return IOC(low, "email", raw)

    host = _to_idna(low.rstrip("."))
    if DOMAIN_RE.fullmatch(host) and not host.replace(".", "").isdigit():
        return IOC(host, "domain", raw)

    m = re.match(r"^([^/\s?#]+)([/?#]\S*)$", s)
    if m:
        head = m.group(1).lower().split(":")[0]
        if DOMAIN_RE.fullmatch(_to_idna(head)) or parse_ip(head) is not None:
            return _url_ioc("http://" + s, raw)

    if allow_keyword and 2 <= len(s) <= 120 and "\n" not in s:
        return IOC(s, "keyword", raw)
    raise ValueError("Unrecognised indicator - expected an IP, domain, URL, hash (MD5/SHA1/SHA256) or email")


def extract(text: str, limit: int = 1000) -> list[dict]:
    """Pull every IOC out of free text (phishing emails, logs, reports). Handles defanged notation."""
    text = refang(text or "")
    found: dict[tuple[str, str], dict] = {}
    covered: list[tuple[int, int]] = []

    def add(value: str, ioc_type: str, private: bool = False) -> None:
        key = (ioc_type, value)
        if key not in found and len(found) < limit:
            found[key] = {"value": value, "type": ioc_type, "private": private}

    def inside(start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in covered)

    for m in _FIND_URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?)'\">")
        try:
            ioc = _url_ioc(url, url)
        except ValueError:
            continue
        add(ioc.value, "url", ioc.private)
        covered.append((m.start(), m.start() + len(url)))

    for m in _FIND_EMAIL.finditer(text):
        if inside(m.start(), m.end()):
            continue
        add(m.group(0).lower(), "email")
        covered.append(m.span())

    for m in _FIND_IPV4.finditer(text):
        ip = parse_ip(m.group(0))
        if ip is not None:
            add(str(ip), "ip", is_non_public(ip))

    for m in _FIND_IPV6.finditer(text):
        candidate = m.group(0)
        if candidate.count(":") < 2 or ("::" not in candidate and candidate.count(":") != 7):
            continue
        ip = parse_ip(candidate)
        if ip is not None and ip.version == 6:
            add(str(ip), "ip", is_non_public(ip))

    for m in _FIND_HASH.finditer(text):
        h = m.group(0).lower()
        add(h, HASH_BY_LEN[len(h)])

    tlds = known_tlds()
    for m in _FIND_DOMAIN.finditer(text):
        if inside(m.start(), m.end()):
            continue
        host = m.group(0).lower().rstrip(".")
        tld = host.rsplit(".", 1)[-1]
        if tld in _EXTRACT_TLD_DENY or (tlds and tld not in tlds):
            continue
        add(host, "domain")

    return list(found.values())

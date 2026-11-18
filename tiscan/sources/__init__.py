"""Registry of every intelligence source TIScan can query."""
from __future__ import annotations

from .abusech import FeodoTracker, MalwareBazaar, ThreatFox, URLhaus
from .base import Result, Source
from .darkweb import HIBP, Ahmia, HudsonRock, LeakCheck, RansomwareLive, XposedOrNot
from .feeds import HashLookup, OpenPhish, SpamhausDROP, TorExits
from .infra import RDAP, CrtSh, DNSRecords, IPInfo, MailSecurity, ProtectiveDNS, Shodan
from .reputation import OTX, AbuseIPDB, GreyNoise, Pulsedive, URLScan, VirusTotal

SOURCE_CLASSES: list[type[Source]] = [
    # reputation
    VirusTotal, AbuseIPDB, OTX, GreyNoise, Pulsedive, URLScan, ProtectiveDNS,
    # abuse.ch + blocklists
    URLhaus, ThreatFox, MalwareBazaar, FeodoTracker, SpamhausDROP, OpenPhish, TorExits, HashLookup,
    # infrastructure
    DNSRecords, RDAP, CrtSh, IPInfo, Shodan, MailSecurity,
    # dark web
    RansomwareLive, HudsonRock, LeakCheck, XposedOrNot, HIBP, Ahmia,
]

__all__ = ["SOURCE_CLASSES", "Result", "Source"]

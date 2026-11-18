"""Runtime configuration, read from environment variables and the project's .env file."""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
# TISCAN_ENV_FILE lets containers keep dashboard-saved settings on a persistent volume.
_CUSTOM_ENV = os.getenv("TISCAN_ENV_FILE", "").strip()
ENV_PATH = Path(_CUSTOM_ENV) if _CUSTOM_ENV else ROOT / ".env"
load_dotenv(ENV_PATH, override=bool(_CUSTOM_ENV))
_env_lock = threading.Lock()


def _str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _num(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


class Settings:
    def __init__(self) -> None:
        self.host = _str("TISCAN_HOST", "127.0.0.1")
        self.port = int(_num("TISCAN_PORT", 8787))
        # Host headers accepted by the dashboard (DNS-rebinding protection). Empty = any.
        hosts = [h.strip().lower() for h in _str("TISCAN_ALLOWED_HOSTS").split(",") if h.strip()]
        self.allowed_hosts = set(hosts) or ({"127.0.0.1", "::1", "localhost"} if self.loopback_only else set())
        self.api_token = _str("TISCAN_API_TOKEN")
        self.db_path = Path(_str("TISCAN_DB") or ROOT / "data" / "tiscan.db")
        self.cache_ttl = int(_num("CACHE_TTL_HOURS", 6) * 3600)
        self.http_timeout = _num("HTTP_TIMEOUT", 20)
        self.user_agent = _str("TISCAN_USER_AGENT", "TIScan/1.0 (threat-intelligence scanner)")
        self.vt_rate_per_min = _num("VT_RATE_PER_MIN", 4)

        self.ransomware_countries = [
            c.strip().upper()
            for c in _str("RANSOMWARE_COUNTRIES", "JO,SA,AE,KW,QA,BH,OM").split(",")
            if len(c.strip()) == 2
        ]
        self.ransomware_refresh = _bool("RANSOMWARE_BACKGROUND_REFRESH", True)

        self.misp_url = _str("MISP_URL").rstrip("/")
        self.misp_key = _str("MISP_KEY")
        self.misp_verify_ssl = _bool("MISP_VERIFY_SSL", True)
        self.misp_distribution = _str("MISP_DISTRIBUTION", "0")
        self.misp_tlp = _str("MISP_TLP", "tlp:amber")

        # Alert delivery by email (Telegram is blocked in some countries, e.g. Jordan).
        self.smtp_host = _str("SMTP_HOST")
        self.smtp_port = int(_num("SMTP_PORT", 587))
        self.smtp_security = _str("SMTP_SECURITY", "starttls").lower()   # starttls | ssl | none
        self.smtp_user = _str("SMTP_USER")
        self.smtp_password = _str("SMTP_PASSWORD")
        self.smtp_from = _str("SMTP_FROM") or self.smtp_user
        self.alert_email_to = [e.strip() for e in _str("ALERT_EMAIL_TO").split(",") if e.strip()]

        self.monitor_enabled = _bool("MONITOR_ENABLED", True)
        self.monitor_interval = int(max(1.0, _num("MONITOR_INTERVAL_HOURS", 24)) * 3600)
        self.monitor_notify_baseline = _bool("MONITOR_NOTIFY_BASELINE", True)
        # Email a status report after every scheduled check, even when nothing new was found.
        self.monitor_daily_report = _bool("MONITOR_DAILY_REPORT", False)
        self.public_url = _str("TISCAN_PUBLIC_URL").rstrip("/")
        # Report links in alerts; turned off for headless runs (e.g. GitHub Actions) whose database is temporary.
        self.alert_links = _bool("TISCAN_ALERT_LINKS", True)

    def reload(self) -> None:
        self.__init__()

    @property
    def misp_configured(self) -> bool:
        return bool(self.misp_url and self.misp_key)

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host and self.alert_email_to and self.smtp_from)

    @property
    def base_url(self) -> str:
        """Where report links in alerts point to."""
        if self.public_url:
            return self.public_url
        host = "127.0.0.1" if self.host in {"0.0.0.0", "::", "localhost"} else self.host
        return f"http://{host}:{self.port}"

    @property
    def loopback_only(self) -> bool:
        return self.host in {"127.0.0.1", "localhost", "::1"}


settings = Settings()

_SAFE_VALUE = re.compile(r"^[^\r\n]*$")


def update_env(updates: dict[str, str]) -> None:
    """Write KEY=value pairs into .env (creating it from .env.example if needed) and apply them live."""
    for key, value in updates.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not _SAFE_VALUE.match(value):
            raise ValueError(f"Refusing to write {key!r}")
    with _env_lock:
        if ENV_PATH.exists():
            lines = ENV_PATH.read_text("utf-8").splitlines()
        elif not _CUSTOM_ENV and (ROOT / ".env.example").exists():
            lines = (ROOT / ".env.example").read_text("utf-8").splitlines()
        else:
            lines = []
        pending = dict(updates)
        for i, line in enumerate(lines):
            if line.lstrip().startswith("#") or "=" not in line:
                continue
            key = line.split("=", 1)[0].strip()
            if key in pending:
                lines[i] = f"{key}={pending.pop(key)}"
        lines.extend(f"{k}={v}" for k, v in pending.items())
        ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.environ.update(updates)
    settings.reload()

"""Alert delivery by email (any SMTP server, e.g. Gmail with an App Password).

Telegram is deliberately not used: it is blocked in some countries (e.g. Jordan).
"""
from __future__ import annotations

import asyncio
import html
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from .config import settings

SEVERITY_HEX = {"critical": "#ff4d6d", "high": "#ff7a45", "medium": "#e0a800", "low": "#3fb4cf", "info": "#4f8cff"}


class NotifyError(Exception):
    pass


def plain_text(alert: dict) -> str:
    lines = [alert["title"], ""]
    if alert.get("summary"):
        lines += [alert["summary"], ""]
    for f in alert.get("findings", []):
        lines.append(f"- [{f['severity'].upper()}] {f['text']}")
    if alert.get("more"):
        lines.append(f"... and {alert['more']} more")
    if alert.get("link"):
        lines += ["", f"Full report: {alert['link']}"]
    return "\n".join(lines)


def email_html(alert: dict) -> str:
    color = SEVERITY_HEX.get(alert.get("level", "info"), "#4f8cff")
    items = "".join(
        f'<li style="margin:4px 0"><b style="color:{SEVERITY_HEX.get(f["severity"], "#666")}">'
        f'{html.escape(f["severity"].upper())}</b> &nbsp;{html.escape(f["text"])}</li>'
        for f in alert.get("findings", [])
    )
    more = f"<p>… and {alert['more']} more</p>" if alert.get("more") else ""
    link = (f'<p><a href="{html.escape(alert["link"])}" style="color:#2563eb">Open the full report in TIScan</a></p>'
            if alert.get("link") else "")
    return f"""<div style="font-family:Segoe UI,Arial,sans-serif;max-width:640px">
<div style="border-left:5px solid {color};padding:10px 16px;background:#f6f8fc">
<h2 style="margin:0 0 6px;font-size:18px">{html.escape(alert["title"])}</h2>
<div style="color:#444">{html.escape(alert.get("summary", ""))}</div></div>
<ul style="padding-left:20px">{items}</ul>{more}{link}
<p style="color:#888;font-size:12px">Sent by TIScan threat-intelligence monitoring.</p></div>"""


def _smtp_send(msg: EmailMessage) -> None:
    context = ssl.create_default_context()
    try:
        if settings.smtp_security == "ssl":
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=25, context=context)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=25)
        with server:
            if settings.smtp_security == "starttls":
                server.starttls(context=context)
            if settings.smtp_user and settings.smtp_password:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise NotifyError("SMTP login failed - for Gmail/Outlook use an App Password, not your normal password") from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise NotifyError(f"SMTP error ({type(exc).__name__}): {str(exc)[:160]}") from exc


async def send_email(alert: dict) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[TIScan] {alert['title']}"
    msg["From"] = formataddr((settings.smtp_from_name, settings.smtp_from)) if settings.smtp_from_name else settings.smtp_from
    msg["To"] = ", ".join(settings.alert_email_to)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid("tiscan")
    msg.set_content(plain_text(alert))
    msg.add_alternative(email_html(alert), subtype="html")
    await asyncio.to_thread(_smtp_send, msg)


class Notifier:
    async def send(self, alert: dict) -> dict[str, str]:
        """Email the alert. Returns {channel label: "ok" | error message}, or {} when email is not set up."""
        if not settings.email_configured:
            return {}
        label = "email: " + ", ".join(settings.alert_email_to)
        try:
            await send_email(alert)
            return {label: "ok"}
        except NotifyError as exc:
            return {label: str(exc)}

    def status(self) -> dict:
        return {
            "configured": settings.email_configured,
            "host": settings.smtp_host, "port": settings.smtp_port, "security": settings.smtp_security,
            "user": settings.smtp_user, "from": settings.smtp_from, "to": settings.alert_email_to,
            "has_password": bool(settings.smtp_password),
            "daily_report": settings.monitor_daily_report,
        }

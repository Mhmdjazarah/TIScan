import asyncio

from tiscan.monitor import build_alert, diff, extract_findings
from tiscan.notify import email_html, plain_text


def report(results, risk=None, exposure=None, scan_id=1):
    return {"id": scan_id, "results": results, "risk": risk, "exposure": exposure}


def rw(listings):
    return {"source": "ransomware_live", "name": "Ransomware leak sites", "category": "darkweb", "status": "ok",
            "verdict": "malicious" if listings else "clean", "data": {"Listings": listings}}


def hudson(employees, users):
    return {"source": "hudsonrock", "name": "Infostealer logs", "category": "darkweb", "status": "ok",
            "verdict": "malicious", "data": {"Compromised employees": employees, "Compromised users / customers": users}}


LISTING = {"date": "2026-11-17", "victim": "Acme", "group": "lockbit3", "match": "domain"}


def test_baseline_then_only_new_findings_alert():
    first = report([rw([LISTING]), hudson(2, 10)])
    findings, metrics = extract_findings(first)
    new, state = diff({}, findings, metrics, first)
    assert state["baseline"] and len(state["seen"]) == 1

    # identical second run -> nothing new
    new, state = diff(state, *extract_findings(first), first)
    assert new == []

    # a second ransomware post + more compromised employees -> exactly those two alerts
    second = report([rw([LISTING, {**LISTING, "victim": "Acme Ltd", "group": "akira"}]), hudson(5, 10)])
    new, state = diff(state, *extract_findings(second), second)
    texts = [f["text"] for f in new]
    assert any("akira" in t for t in texts)
    assert any("2 → 5" in t for t in texts)
    assert all(f["severity"] == "critical" for f in new)


def test_failed_source_does_not_cause_realert():
    ok = report([rw([LISTING])])
    _, state = diff({}, *extract_findings(ok), ok)
    failed = report([{**rw([]), "status": "rate_limited"}])
    new, state = diff(state, *extract_findings(failed), failed)
    assert new == []
    new, _ = diff(state, *extract_findings(ok), ok)
    assert new == []  # the old listing is remembered, not re-alerted


def test_risk_level_rise_alerts():
    clean = report([], risk={"score": 0, "level": "clean"})
    _, state = diff({}, *extract_findings(clean), clean)
    bad = report([{"source": "protective_dns", "name": "Protective DNS", "category": "reputation", "status": "ok",
                   "verdict": "malicious", "summary": "Blocked by Quad9"}], risk={"score": 80, "level": "high"})
    new, _ = diff(state, *extract_findings(bad), bad)
    texts = " | ".join(f["text"] for f in new)
    assert "rose from clean to high" in texts and "Protective DNS" in texts


def test_alert_rendering_is_escaped():
    item = {"id": 1, "value": "acme.com", "label": "<b>HQ</b>"}
    alert = build_alert(item, report([], exposure={"score": 95, "level": "critical"}),
                        [{"text": "<script>x</script>", "severity": "critical"}], "change")
    assert alert["level"] == "critical" and "1 new finding" in alert["title"]
    assert "<script>" not in email_html(alert) and "&lt;script&gt;" in email_html(alert)
    assert "[CRITICAL]" in plain_text(alert)


def test_daily_report_alert():
    item = {"id": 1, "value": "acme.com", "label": None}
    quiet = build_alert(item, report([], risk={"score": 0, "level": "clean"}), [], "report")
    assert quiet["kind"] == "report" and quiet["level"] == "info" and "all clear" in quiet["title"]
    known = build_alert(item, report([]), [{"text": "Data breach: X", "severity": "medium"}], "report")
    assert "no new findings (1 known)" in known["title"] and known["level"] == "info"


def test_scheduled_check_sends_daily_report(monkeypatch, tmp_path):
    from tiscan.config import settings
    from tiscan.db import Database
    from tiscan.monitor import Monitor

    class FakeEngine:
        async def scan(self, ioc, mode, nocache):
            return {"id": 7, "results": [], "risk": {"score": 0, "level": "clean"}, "exposure": None}

    class FakeNotifier:
        async def send(self, alert):
            return {"email: soc@example.com": "ok"}

    db = Database(tmp_path / "t.db")
    mon = Monitor(FakeEngine(), db, FakeNotifier())
    wid = db.add_watch("acme.com", "domain", None)
    monkeypatch.setattr(settings, "monitor_daily_report", True)
    assert asyncio.run(mon.check(wid))["kind"] == "baseline"
    assert asyncio.run(mon.check(wid)) is None                      # manual re-check, nothing new: quiet
    assert asyncio.run(mon.check(wid, scheduled=True))["kind"] == "report"
    monkeypatch.setattr(settings, "monitor_daily_report", False)
    assert asyncio.run(mon.check(wid, scheduled=True)) is None
    db.close()


def test_notifier_without_email_returns_empty(monkeypatch):
    from tiscan.config import settings
    from tiscan.notify import Notifier

    monkeypatch.setattr(settings, "smtp_host", "")
    assert asyncio.run(Notifier().send({"title": "x"})) == {}

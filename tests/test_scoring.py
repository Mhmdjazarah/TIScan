from tiscan.scoring import exposure, level_for, risk
from tiscan.sources.base import Result


def r(name, verdict, score=0, weight=0.5, benign=False, status="ok", category="reputation", exp=0):
    return Result(source=name, name=name, category=category, status=status, verdict=verdict, score=score,
                  weight=weight, benign=benign, exposure=exp)


def test_single_trusted_hit_is_enough():
    out = risk([r("abusech", "malicious", 95, 0.95), r("dns", "info")])
    assert out["score"] >= 85 and out["level"] == "critical"


def test_moderate_signals_compound():
    one = risk([r("otx", "suspicious", 50, 0.5)])["score"]
    two = risk([r("otx", "suspicious", 50, 0.5), r("greynoise", "suspicious", 50, 0.5)])["score"]
    assert two > one


def test_benign_damps_weak_signals_only():
    weak = risk([r("otx", "suspicious", 50, 0.5), r("greynoise", "clean", benign=True)])
    assert weak["score"] < 25
    strong = risk([r("vt", "malicious", 100, 1.0), r("greynoise", "clean", benign=True)])
    assert strong["score"] == 100


def test_errors_and_missing_keys_do_not_count():
    out = risk([r("vt", "unknown", status="no_key"), r("abuse", "unknown", status="error")])
    assert out["level"] == "unknown" and out["answered"] == 0


def test_darkweb_kept_separate():
    results = [r("vt", "clean", 0, 1.0), r("hudson", "malicious", category="darkweb", exp=90)]
    assert risk(results)["score"] == 0
    assert exposure(results)["score"] == 90


def test_levels():
    assert [level_for(s) for s in (0, 10, 30, 60, 85)] == ["clean", "low", "medium", "high", "critical"]

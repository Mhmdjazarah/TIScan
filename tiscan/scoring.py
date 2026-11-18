"""Turn many per-source opinions into two explainable numbers: threat risk and dark-web exposure.

Both scores use a weighted "noisy-OR": each source contributes p = (score/100) * weight, and the
combined score is 1 - prod(1 - p). Independent moderate signals therefore compound, a single
trusted hit is enough on its own, and low-reliability sources can never dominate.
"""
from __future__ import annotations

from typing import Iterable

from .sources.base import Result

LEVELS = ((85, "critical"), (60, "high"), (30, "medium"), (10, "low"), (0, "clean"))
ANSWERED = {"ok", "not_found"}
# A benign signal (allow-list, known-good file) cannot cancel a hit this strong.
STRONG_HIT = 0.5
BENIGN_DAMPING = 0.4


def level_for(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "clean"


def _combine(contributions: Iterable[float]) -> float:
    remaining = 1.0
    for p in contributions:
        remaining *= 1.0 - max(0.0, min(1.0, p))
    return 1.0 - remaining


def risk(results: list[Result]) -> dict:
    intel = [r for r in results if r.category != "darkweb"]
    answered = [r for r in intel if r.status in ANSWERED]
    queried = [r for r in intel if r.status not in {"no_key", "unsupported", "skipped"}]

    reasons = []
    contributions = []
    for r in answered:
        if r.score <= 0:
            continue
        p = r.score / 100 * r.weight
        contributions.append(p)
        reasons.append({"source": r.name, "verdict": r.verdict, "impact": round(p * 100), "text": r.summary})

    combined = _combine(contributions)
    strongest = max(contributions, default=0.0)
    benign = [r for r in answered if r.benign]
    if benign and combined > 0 and strongest < STRONG_HIT:
        combined *= BENIGN_DAMPING
        names = ", ".join(r.name for r in benign)
        reasons.append({"source": names, "verdict": "clean", "impact": 0,
                        "text": f"Known-good / allow-listed by {names}; score reduced"})
    elif benign and combined == 0:
        reasons.append({"source": ", ".join(r.name for r in benign), "verdict": "clean", "impact": 0,
                        "text": "Listed as known-good / benign infrastructure"})

    score = round(combined * 100)
    reasons.sort(key=lambda x: -x["impact"])
    return {
        "score": score,
        "level": level_for(score) if answered else "unknown",
        "reasons": reasons[:12],
        "answered": len(answered),
        "queried": len(queried),
        "total": len(intel),
        "flagged": sum(1 for r in answered if r.verdict in {"malicious", "suspicious"}),
    }


def exposure(results: list[Result]) -> dict | None:
    dark = [r for r in results if r.category == "darkweb"]
    if not dark:
        return None
    answered = [r for r in dark if r.status in ANSWERED]
    reasons = [
        {"source": r.name, "verdict": r.verdict, "impact": r.exposure, "text": r.summary}
        for r in answered if r.exposure > 0
    ]
    score = round(_combine(r.exposure / 100 for r in answered) * 100)
    reasons.sort(key=lambda x: -x["impact"])
    return {
        "score": score,
        "level": level_for(score) if answered else "unknown",
        "reasons": reasons,
        "answered": len(answered),
        "queried": len([r for r in dark if r.status not in {"no_key", "unsupported", "skipped"}]),
        "total": len(dark),
        "flagged": sum(1 for r in answered if r.exposure > 0),
    }

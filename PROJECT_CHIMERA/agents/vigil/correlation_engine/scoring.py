from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


SEVERITY_LABEL_TO_SCORE = {
    "low": 3,
    "medium": 5,
    "high": 7,
    "critical": 9,
}


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def harmonic_mean(vals: List[float]) -> float:
    vals = [v for v in vals if v > 0]
    if not vals:
        return 0.0
    return len(vals) / sum(1.0 / v for v in vals)


@dataclass(frozen=True)
class AlertScore:
    confidence: float
    severity_label: str
    severity_score: int
    notes: List[str]


def compute_alert_score(
    *,
    rule_confidence: float,
    rule_severity_label: str,
    events: List[Dict[str, Any]],
    entity_match_strength: float,  # 0..1
) -> AlertScore:
    """
    Confidence strategy (simple but robust):
      base = rule_confidence
      evidence = harmonic mean of event confidences (penalizes one weak event)
      combine = 0.60*base + 0.40*evidence
      then multiply by entity_match_strength (penalty if weak/None matches)

    Severity:
      base severity from rule label -> score 3/5/7/9
      bump severity score slightly if evidence severity is high (avg severity)
    """
    notes: List[str] = []

    base = clamp(float(rule_confidence), 0.0, 1.0)

    ev_confs = []
    ev_sevs = []
    for e in events:
        try:
            ev_confs.append(clamp(float(e.get("confidence", 0.0)), 0.0, 1.0))
        except Exception:
            ev_confs.append(0.0)
        try:
            ev_sevs.append(int(e.get("severity", 1)))
        except Exception:
            ev_sevs.append(1)

    evidence_conf = harmonic_mean(ev_confs)
    combined = 0.60 * base + 0.40 * evidence_conf

    # Entity match penalty (0.5..1.0 typically)
    em = clamp(float(entity_match_strength), 0.0, 1.0)
    combined *= em

    combined = clamp(combined, 0.0, 1.0)

    if evidence_conf < 0.5:
        notes.append("Evidence confidence is low (harmonic mean < 0.5).")
    if em < 0.75:
        notes.append("Entity match is weak; confidence penalized.")

    # Severity
    sev_label = rule_severity_label
    sev_score = SEVERITY_LABEL_TO_SCORE.get(sev_label, 5)

    # Optional bump based on average event severity
    avg_sev = sum(ev_sevs) / max(1, len(ev_sevs))
    if avg_sev >= 8 and sev_score < 9:
        sev_score += 1
        notes.append("Severity bumped due to high average event severity.")
    sev_score = int(clamp(float(sev_score), 1.0, 10.0))

    return AlertScore(
        confidence=combined,
        severity_label=sev_label,
        severity_score=sev_score,
        notes=notes
    )

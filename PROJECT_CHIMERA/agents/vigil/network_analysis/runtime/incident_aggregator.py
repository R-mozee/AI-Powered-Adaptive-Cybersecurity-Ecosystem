from __future__ import annotations

from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any
import time


SEVERITY_ORDER = ["LOW", "MED", "HIGH", "CRITICAL"]


def bump_severity(cur: str, steps: int = 1) -> str:
    i = SEVERITY_ORDER.index(cur)
    return SEVERITY_ORDER[min(i + steps, len(SEVERITY_ORDER) - 1)]


@dataclass
class FlowAlert:
    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int
    label: str              # multiclass label
    alert_level: str        # NONE/SUSPECT/CONFIRMED
    p_attack: float
    margin: float


@dataclass
class Incident:
    key: str
    start_ts: float
    end_ts: float
    severity: str
    top_labels: List[Tuple[str, int]]
    counts: Dict[str, int]
    confirmed: int
    suspect: int
    unique_ports: int
    confidence: float
    recommendation: str


class IncidentAggregator:
    def __init__(self, window_sec: int = 30):
        self.window_sec = window_sec
        self.buffer: Dict[str, List[FlowAlert]] = defaultdict(list)

    def _key(self, a: FlowAlert) -> str:
        # tune keys as you like; this is a good default
        return f"{a.src_ip}->{a.dst_ip}"

    def add(self, alert: FlowAlert) -> List[Incident]:
        key = self._key(alert)
        self.buffer[key].append(alert)
        return self._flush_key(key)

    def _flush_key(self, key: str) -> List[Incident]:
        now = time.time()
        buf = self.buffer[key]

        # keep only recent
        cutoff = now - self.window_sec
        buf = [a for a in buf if a.ts >= cutoff]
        self.buffer[key] = buf

        if not buf:
            return []

        # ignore NONE flows for triggering (but keep them if you want context)
        trig = [a for a in buf if a.alert_level in ("SUSPECT", "CONFIRMED")]
        if not trig:
            return []

        confirmed = sum(1 for a in trig if a.alert_level == "CONFIRMED")
        suspect = sum(1 for a in trig if a.alert_level == "SUSPECT")

        labels = [a.label for a in trig]
        counts = Counter(labels)
        top_labels = counts.most_common(3)

        unique_ports = len({a.dst_port for a in trig})

        # base severity
        severity = "LOW"
        if confirmed >= 20:
            severity = "CRITICAL"
        elif confirmed >= 5:
            severity = "HIGH"
        elif suspect >= 40:
            severity = "HIGH"
        elif suspect >= 15:
            severity = "MED"

        # rare-class boost
        rare = {"Infiltration", "Botnet", "WebAttack"}
        if any(lbl in rare for lbl in counts.keys()):
            if severity == "LOW":
                severity = "MED"
            else:
                severity = bump_severity(severity, 1)

        # PortScan rule override
        if "PortScan" in counts:
            if unique_ports >= 50:
                severity = max(severity, "HIGH", key=lambda s: SEVERITY_ORDER.index(s))
            elif unique_ports >= 20:
                severity = max(severity, "MED", key=lambda s: SEVERITY_ORDER.index(s))
            else:
                # don't raise incidents for weak PortScan evidence
                if severity in ("LOW", "MED") and confirmed < 5:
                    return []

        # confidence = average of p_attack, boosted by margins
        avg_p = sum(a.p_attack for a in trig) / len(trig)
        avg_m = sum(a.margin for a in trig) / len(trig)
        confidence = float(min(1.0, avg_p + 0.15 * (avg_m > 1.0)))

        recommendation = {
            "LOW": "Log only; wait for correlation.",
            "MED": "Flag for review; correlate with DNS/HTTP logs.",
            "HIGH": "Block or rate-limit source; isolate target if needed.",
            "CRITICAL": "Immediate response: block source, isolate hosts, start incident workflow.",
        }[severity]

        inc = Incident(
            key=key,
            start_ts=min(a.ts for a in trig),
            end_ts=max(a.ts for a in trig),
            severity=severity,
            top_labels=top_labels,
            counts=dict(counts),
            confirmed=confirmed,
            suspect=suspect,
            unique_ports=unique_ports,
            confidence=confidence,
            recommendation=recommendation,
        )

        # Optional: once an incident is emitted at HIGH/CRITICAL, clear buffer to avoid spam
        if severity in ("HIGH", "CRITICAL"):
            self.buffer[key] = []

        return [inc]

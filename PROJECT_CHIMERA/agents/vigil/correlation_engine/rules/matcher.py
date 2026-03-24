from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class RuleStep:
    event_type: str
    within: Optional[str]
    same: Tuple[str, ...]
    where: Dict[str, Any]


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    name: str
    description: str
    enabled: bool
    severity: str
    confidence: float
    max_span: Optional[str]
    steps: Tuple[RuleStep, ...]


def compile_rules(ruleset: Dict[str, Any]) -> List[CompiledRule]:
    compiled: List[CompiledRule] = []
    for r in ruleset.get("rules", []):
        steps: List[RuleStep] = []
        for s in r["sequence"]:
            steps.append(
                RuleStep(
                    event_type=str(s["event_type"]).strip(),
                    within=s.get("within"),
                    same=tuple(s.get("same", []) or []),
                    where=dict(s.get("where", {}) or {}),
                )
            )

        compiled.append(
            CompiledRule(
                rule_id=r["id"],
                name=r["name"],
                description=r.get("description", ""),
                enabled=bool(r.get("enabled", True)),
                severity=r["severity"],
                confidence=float(r["confidence"]),
                max_span=r.get("max_span"),
                steps=tuple(steps),
            )
        )
    return compiled


def _get_field(event: Dict[str, Any], path: str) -> Any:
    # supports paths like "entities.dst_ip"
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def event_matches_step(event: Dict[str, Any], step: RuleStep) -> bool:
    if event.get("event_type") != step.event_type:
        return False

    where = step.where or {}

    min_conf = where.get("min_confidence")
    if min_conf is not None:
        try:
            if float(event.get("confidence", 0.0)) < float(min_conf):
                return False
        except Exception:
            return False

    min_sev = where.get("min_severity")
    if min_sev is not None:
        try:
            if int(event.get("severity", 0)) < int(min_sev):
                return False
        except Exception:
            return False

    tag_any = where.get("tag_any")
    if tag_any:
        tags = set(event.get("tags", []) or [])
        if not any(t in tags for t in tag_any):
            return False

    return True


def same_entity_satisfied(
    prev_event: Dict[str, Any],
    next_event: Dict[str, Any],
    same_paths: Tuple[str, ...]
) -> bool:
    """
    Returns True if ANY of the 'same' paths match (OR logic),
    ignoring None/empty values.
    """
    if not same_paths:
        return True

    for p in same_paths:
        a = _get_field(prev_event, p)
        b = _get_field(next_event, p)
        if a is None or b is None:
            continue
        if isinstance(a, str) and not a.strip():
            continue
        if isinstance(b, str) and not b.strip():
            continue
        if a == b:
            return True

    return False

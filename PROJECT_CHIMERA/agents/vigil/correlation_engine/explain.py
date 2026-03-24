from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from agents.vigil.correlation_engine.timeutils import parse_iso8601
from agents.vigil.correlation_engine.rules.matcher import RuleStep


def _get_field(event: Dict[str, Any], path: str) -> Any:
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


@dataclass(frozen=True)
class EntityMatch:
    path: str
    value: Any


@dataclass(frozen=True)
class StepExplanation:
    step_index: int
    expected_event_type: str
    matched_event_id: str
    matched_timestamp: str
    time_delta_seconds_from_prev: Optional[int]
    where_checks_passed: bool


def find_best_entity_match(
    prev_event: Dict[str, Any],
    next_event: Dict[str, Any],
    same_paths: Tuple[str, ...],
) -> Optional[EntityMatch]:
    """
    Returns the first satisfied 'same' match (in rule order).
    """
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
            return EntityMatch(path=p, value=a)
    return None


def build_explanation(
    *,
    rule_steps: Tuple[RuleStep, ...],
    matched_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Explainability payload, designed for UI + debugging.
    """
    steps: List[StepExplanation] = []
    entity_matches: List[Dict[str, Any]] = []

    for i, (step, ev) in enumerate(zip(rule_steps, matched_events)):
        delta = None
        if i > 0:
            prev_dt = parse_iso8601(matched_events[i - 1]["timestamp"])
            cur_dt = parse_iso8601(ev["timestamp"])
            delta = int((cur_dt - prev_dt).total_seconds())

        steps.append(
            StepExplanation(
                step_index=i,
                expected_event_type=step.event_type,
                matched_event_id=ev["event_id"],
                matched_timestamp=ev["timestamp"],
                time_delta_seconds_from_prev=delta,
                where_checks_passed=True,  # step matching already enforced
            )
        )

        # record entity match used for this transition
        if i > 0 and step.same:
            em = find_best_entity_match(matched_events[i - 1], ev, step.same)
            if em is not None:
                entity_matches.append(
                    {
                        "transition": f"{i-1}->{i}",
                        "path": em.path,
                        "value": em.value,
                    }
                )

    return {
        "steps": [s.__dict__ for s in steps],
        "entity_matches": entity_matches,
    }

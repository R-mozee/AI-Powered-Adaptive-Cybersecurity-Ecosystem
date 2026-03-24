from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import uuid
import math

from agents.vigil.correlation_engine.timeutils import parse_iso8601, window_to_timedelta
from agents.vigil.correlation_engine.rules.matcher import (
    CompiledRule,
    RuleStep,
    event_matches_step,
    same_entity_satisfied,
)
from agents.vigil.correlation_engine.explain import build_explanation, find_best_entity_match
from agents.vigil.correlation_engine.scoring import compute_alert_score


@dataclass
class CorrelationEngineConfig:
    buffer_retention: timedelta = timedelta(hours=6)

    # Dedupe tuning
    dedupe: bool = True
    dedupe_bucket: timedelta = timedelta(minutes=10)  # time bucket to prevent spam
    dedupe_key_entity_preference: Tuple[str, ...] = (
        # prefer these keys for dedupe “same incident”
        "entities.dst_ip",
        "entities.src_ip",
        "entities.ip",
        "entities.domain",
        "entities.url",
        "entities.user",
        "entities.host",
    )


class CorrelationEngine:
    def __init__(self, rules: List[CompiledRule], config: Optional[CorrelationEngineConfig] = None):
        self.rules = [r for r in rules if r.enabled]
        self.config = config or CorrelationEngineConfig()
        self._events: List[Dict[str, Any]] = []

        # dedupe signature set
        self._emitted: set[str] = set()

    def add_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "timestamp" not in event or "event_id" not in event:
            raise ValueError("Event must be normalized (missing timestamp/event_id)")

        self._events.append(event)
        self._events.sort(key=lambda e: e["timestamp"])  # prototype simplicity
        self._prune_buffer()
        return self._evaluate_all_rules()

    def get_buffer(self) -> List[Dict[str, Any]]:
        return list(self._events)

    def _prune_buffer(self) -> None:
        if not self._events:
            return
        latest_dt = parse_iso8601(self._events[-1]["timestamp"])
        cutoff = latest_dt - self.config.buffer_retention

        kept: List[Dict[str, Any]] = []
        for e in self._events:
            try:
                dt = parse_iso8601(e["timestamp"])
            except Exception:
                continue
            if dt >= cutoff:
                kept.append(e)
        self._events = kept

    def _evaluate_all_rules(self) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            alerts.extend(self._evaluate_rule(rule))
        return alerts

    def _evaluate_rule(self, rule: CompiledRule) -> List[Dict[str, Any]]:
        if len(rule.steps) < 2:
            return []

        max_span_td = window_to_timedelta(rule.max_span) if rule.max_span else None

        step0 = rule.steps[0]
        step0_candidates = [e for e in self._events if event_matches_step(e, step0)]

        alerts: List[Dict[str, Any]] = []
        for start_event in step0_candidates:
            seq_events = [start_event]
            ok, completed = self._try_extend_sequence(rule, seq_events, max_span_td)
            if not ok or not completed:
                continue

            alert = self._build_alert(rule, completed)
            if self.config.dedupe:
                sig = self._dedupe_signature(rule, alert, completed)
                if sig in self._emitted:
                    continue
                self._emitted.add(sig)

            alerts.append(alert)

        return alerts

    def _try_extend_sequence(
        self,
        rule: CompiledRule,
        seq_events: List[Dict[str, Any]],
        max_span_td: Optional[timedelta],
    ) -> Tuple[bool, Optional[List[Dict[str, Any]]]]:
        start_dt = parse_iso8601(seq_events[0]["timestamp"])

        for i in range(1, len(rule.steps)):
            prev = seq_events[-1]
            prev_dt = parse_iso8601(prev["timestamp"])
            step = rule.steps[i]

            within_td = window_to_timedelta(step.within) if step.within else None
            earliest = prev_dt
            latest = prev_dt + within_td if within_td is not None else None

            if max_span_td is not None:
                overall_latest = start_dt + max_span_td
                latest = overall_latest if latest is None else min(latest, overall_latest)

            candidate = self._find_next_match(prev, step, earliest, latest)
            if candidate is None:
                return (False, None)

            seq_events.append(candidate)

        return (True, seq_events)

    def _find_next_match(
        self,
        prev_event: Dict[str, Any],
        step: RuleStep,
        earliest: datetime,
        latest: Optional[datetime],
    ) -> Optional[Dict[str, Any]]:
        for e in self._events:
            dt = parse_iso8601(e["timestamp"])
            if dt < earliest:
                continue
            if latest is not None and dt > latest:
                continue
            if not event_matches_step(e, step):
                continue
            if not same_entity_satisfied(prev_event, e, step.same):
                continue
            return e
        return None

    def _dedupe_signature(self, rule: CompiledRule, alert: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
        """
        Dedupe signature:
          rule_id + chosen key entity value + time bucket of first event
        This prevents repeating the same incident over and over.
        """
        first_dt = parse_iso8601(events[0]["timestamp"])
        bucket_seconds = int(self.config.dedupe_bucket.total_seconds())
        bucket = int(first_dt.timestamp()) // max(1, bucket_seconds)

        key_entity = self._pick_key_entity(events)
        return f"{rule.rule_id}|{key_entity}|{bucket}"

    def _pick_key_entity(self, events: List[Dict[str, Any]]) -> str:
        # choose best entity field present among events (for stable dedupe)
        def get_path(e: Dict[str, Any], path: str) -> Any:
            cur: Any = e
            for part in path.split("."):
                if not isinstance(cur, dict):
                    return None
                cur = cur.get(part)
            return cur

        for path in self.config.dedupe_key_entity_preference:
            for e in events:
                v = get_path(e, path)
                if v is None:
                    continue
                if isinstance(v, str) and not v.strip():
                    continue
                return f"{path}={v}"
        # fallback to rule-only dedupe (still bucketed)
        return "no_key_entity"

    def _entity_match_strength(self, rule: CompiledRule, events: List[Dict[str, Any]]) -> float:
        """
        Estimate strength based on whether 'same' constraints actually matched on each transition.
        - If no same constraints: 1.0
        - For each transition with same constraints:
            matched => 1.0
            not matched (should not happen) => 0.5
        """
        strengths: List[float] = []
        for i in range(1, len(rule.steps)):
            same_paths = rule.steps[i].same
            if not same_paths:
                continue
            em = find_best_entity_match(events[i - 1], events[i], same_paths)
            strengths.append(1.0 if em is not None else 0.5)
        if not strengths:
            return 1.0
        return sum(strengths) / len(strengths)

    def _build_alert(self, rule: CompiledRule, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        explanation = build_explanation(rule_steps=rule.steps, matched_events=events)
        entity_strength = self._entity_match_strength(rule, events)

        score = compute_alert_score(
            rule_confidence=rule.confidence,
            rule_severity_label=rule.severity,
            events=events,
            entity_match_strength=entity_strength,
        )

        # Compact matched_entities summary (first non-null by key)
        matched_entities: Dict[str, Any] = {}
        for e in events:
            ents = e.get("entities", {}) or {}
            for k, v in ents.items():
                if v is None:
                    continue
                matched_entities.setdefault(k, v)

        return {
            "alert_id": str(uuid.uuid4()),
            "created_at": created_at,
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "description": rule.description or rule.name,

            # Rule base metadata
            "rule_severity": rule.severity,
            "rule_confidence": float(rule.confidence),

            # Final scored values (what UI should show)
            "severity": score.severity_label,
            "severity_score": score.severity_score,
            "confidence": score.confidence,

            "event_ids": [e["event_id"] for e in events],
            "events": events,

            "matched_entities": matched_entities,
            "explanation": explanation,
            "scoring_notes": score.notes,
        }

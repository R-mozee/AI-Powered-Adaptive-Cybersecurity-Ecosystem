from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import json
import os

from jsonschema import Draft202012Validator


@dataclass
class RuleValidationIssue:
    rule_id: Optional[str]
    level: str  # "error" | "warning"
    message: str


class RuleValidationError(ValueError):
    def __init__(self, issues: List[RuleValidationIssue]):
        self.issues = issues
        super().__init__("\n".join([f"{i.level.upper()}: [{i.rule_id}] {i.message}" for i in issues]))


def _load_schema(schema_path: str) -> Dict[str, Any]:
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _parse_window_to_seconds(window: str) -> int:
    # window format already schema-validated: ^\d+(s|m|h|d)$
    n = int(window[:-1])
    unit = window[-1]
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return n * mult


def validate_ruleset(
    ruleset: Dict[str, Any],
    *,
    schema_path: str,
    strict: bool = True
) -> List[RuleValidationIssue]:
    issues: List[RuleValidationIssue] = []

    schema = _load_schema(schema_path)
    v = Draft202012Validator(schema)

    # JSON-schema validation
    for err in sorted(v.iter_errors(ruleset), key=str):
        issues.append(RuleValidationIssue(rule_id=None, level="error", message=err.message))

    if issues and strict:
        return issues  # no need to add more noise

    # Extra semantic checks
    rules = ruleset.get("rules", [])
    if not isinstance(rules, list):
        issues.append(RuleValidationIssue(rule_id=None, level="error", message="'rules' must be a list"))
        return issues

    seen_ids = set()
    for r in rules:
        rid = r.get("id") if isinstance(r, dict) else None
        if not isinstance(r, dict):
            issues.append(RuleValidationIssue(rule_id=None, level="error", message="Each rule must be an object"))
            continue

        # unique IDs
        if rid in seen_ids:
            issues.append(RuleValidationIssue(rule_id=rid, level="error", message="Duplicate rule id"))
        else:
            seen_ids.add(rid)

        seq = r.get("sequence", [])
        if isinstance(seq, list) and len(seq) >= 2:
            # within allowed only on steps after first (it can exist, but meaningless)
            first_within = seq[0].get("within")
            if first_within is not None:
                issues.append(
                    RuleValidationIssue(
                        rule_id=rid,
                        level="warning",
                        message="First step has 'within' which is ignored; 'within' should be on subsequent steps."
                    )
                )

            # validate increasing constraints are sensible
            max_span = r.get("max_span")
            if isinstance(max_span, str):
                max_span_s = _parse_window_to_seconds(max_span)

                # sum of within windows should not exceed max_span (soft check)
                within_total = 0
                for step in seq[1:]:
                    w = step.get("within")
                    if isinstance(w, str):
                        within_total += _parse_window_to_seconds(w)
                if within_total > max_span_s:
                    issues.append(
                        RuleValidationIssue(
                            rule_id=rid,
                            level="warning",
                            message=f"Sum of 'within' windows ({within_total}s) exceeds max_span ({max_span_s}s)."
                        )
                    )

        # confidence sanity
        conf = r.get("confidence")
        if isinstance(conf, (int, float)) and conf < 0.5:
            issues.append(
                RuleValidationIssue(rule_id=rid, level="warning", message="Rule confidence < 0.5; may create noise.")
            )

    return issues


def validate_ruleset_or_raise(
    ruleset: Dict[str, Any],
    *,
    schema_path: str,
    strict: bool = True
) -> None:
    issues = validate_ruleset(ruleset, schema_path=schema_path, strict=strict)
    errors = [i for i in issues if i.level == "error"]
    if errors:
        raise RuleValidationError(issues)

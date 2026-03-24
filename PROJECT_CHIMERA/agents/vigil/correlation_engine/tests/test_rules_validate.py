import pytest

from agents.vigil.correlation_engine.rules.validator import (
    validate_ruleset_or_raise,
    RuleValidationError,
)
from agents.vigil.correlation_engine.rules.loader import load_rule_file


def test_ruleset_validates_against_schema(tmp_path):
    # minimal valid ruleset
    ruleset = {
        "rules": [
            {
                "id": "R100",
                "name": "test_rule",
                "sequence": [{"event_type": "a"}, {"event_type": "b", "within": "10m"}],
                "severity": "high",
                "confidence": 0.9,
                "max_span": "1h",
            }
        ]
    }

    schema_path = "agents/vigil/correlation_engine/rules/schema/rule_schema.json"
    validate_ruleset_or_raise(ruleset, schema_path=schema_path, strict=True)


def test_ruleset_invalid_missing_fields_raises():
    ruleset = {"rules": [{"id": "R1"}]}  # invalid
    schema_path = "agents/vigil/correlation_engine/rules/schema/rule_schema.json"
    with pytest.raises(RuleValidationError):
        validate_ruleset_or_raise(ruleset, schema_path=schema_path, strict=True)

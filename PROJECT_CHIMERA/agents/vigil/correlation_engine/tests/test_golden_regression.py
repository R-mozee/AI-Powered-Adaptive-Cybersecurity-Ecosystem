from agents.vigil.correlation_engine.golden import run_golden, expected_alerts


def _alert_event_types(alert: dict) -> list[str]:
    events = alert.get("events", []) or []
    return [e.get("event_type") for e in events]


def test_golden_regression_produces_expected_alerts():
    rule_yaml_path = "agents/vigil/correlation_engine/rules/basic_rules.yaml"
    rule_schema_path = "agents/vigil/correlation_engine/rules/schema/rule_schema.json"

    alerts, errors = run_golden(rule_yaml_path=rule_yaml_path, rule_schema_path=rule_schema_path)
    assert errors == []

    exp = expected_alerts()

    # index by rule_id
    by_rule = {}
    for a in alerts:
        by_rule.setdefault(a.get("rule_id"), []).append(a)

    for e in exp:
        assert e.rule_id in by_rule, f"Missing expected alert for rule {e.rule_id}"
        # take first instance (dedupe may reduce multiples)
        a = by_rule[e.rule_id][0]

        types = _alert_event_types(a)
        for t in e.must_include_event_types:
            assert t in types, f"Alert {e.rule_id} missing event_type {t}"

        ents = a.get("matched_entities", {}) or {}
        assert any(k in ents and ents[k] is not None for k in e.must_have_any_entity), (
            f"Alert {e.rule_id} missing required entities among {e.must_have_any_entity}"
        )

        assert float(a.get("confidence", 0.0)) >= e.min_confidence, (
            f"Alert {e.rule_id} confidence too low"
        )
        assert int(a.get("severity_score", 0)) >= e.min_severity_score, (
            f"Alert {e.rule_id} severity_score too low"
        )

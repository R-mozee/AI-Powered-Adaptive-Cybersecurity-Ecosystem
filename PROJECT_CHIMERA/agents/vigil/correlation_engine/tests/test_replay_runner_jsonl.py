import os
import tempfile

from agents.vigil.correlation_engine.synthetic.generate_scenarios import generate_mixed_scenarios
from agents.vigil.correlation_engine.replay.replay_runner import build_engine_from_rulefile, replay_events


def test_replay_runner_emits_alerts_from_synthetic():
    # Use your actual rule files (these paths match what we created in Step 2)
    rule_yaml_path = "agents/vigil/correlation_engine/rules/basic_rules.yaml"
    rule_schema_path = "agents/vigil/correlation_engine/rules/schema/rule_schema.json"

    engine = build_engine_from_rulefile(
        rule_yaml_path=rule_yaml_path,
        rule_schema_path=rule_schema_path,
    )

    events = generate_mixed_scenarios(num_each=3)
    alerts, res = replay_events(engine=engine, events=events, strict_normalization=True)

    # Depending on which templates match your basic_rules.yaml,
    # you should get at least one alert.
    assert res.total_input > 0
    assert res.normalized_failed == 0
    assert len(alerts) >= 1

    # Basic alert fields
    a = alerts[0]
    assert "rule_id" in a
    assert "confidence" in a
    assert "severity_score" in a
    assert "explanation" in a

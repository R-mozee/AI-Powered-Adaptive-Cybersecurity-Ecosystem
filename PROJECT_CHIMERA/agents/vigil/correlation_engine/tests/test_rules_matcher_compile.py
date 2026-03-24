from agents.vigil.correlation_engine.rules.matcher import (
    compile_rules,
    event_matches_step,
    same_entity_satisfied,
)


def test_compile_and_match():
    ruleset = {
        "rules": [
            {
                "id": "R001",
                "name": "phish_then_download",
                "sequence": [
                    {"event_type": "phishing_detected", "where": {"min_confidence": 0.6}},
                    {"event_type": "malware_download", "within": "1h", "same": ["entities.user"]},
                ],
                "severity": "high",
                "confidence": 0.85,
                "max_span": "2h",
            }
        ]
    }

    compiled = compile_rules(ruleset)
    assert len(compiled) == 1
    rule = compiled[0]
    assert rule.steps[0].event_type == "phishing_detected"

    e1 = {
        "event_type": "phishing_detected",
        "confidence": 0.9,
        "severity": 6,
        "tags": [],
        "entities": {"user": "alice"}
    }
    e2 = {
        "event_type": "malware_download",
        "confidence": 0.8,
        "severity": 5,
        "tags": [],
        "entities": {"user": "alice"}
    }

    assert event_matches_step(e1, rule.steps[0]) is True
    assert event_matches_step(e2, rule.steps[1]) is True
    assert same_entity_satisfied(e1, e2, rule.steps[1].same) is True

from agents.vigil.correlation_engine.rules.matcher import compile_rules
from agents.vigil.correlation_engine.engine import CorrelationEngine


def test_step4_scoring_and_explanation_present():
    ruleset = {
        "rules": [
            {
                "id": "R010",
                "name": "phish_then_download",
                "description": "Phish -> download within 1h same user",
                "enabled": True,
                "severity": "high",
                "confidence": 0.80,
                "max_span": "2h",
                "sequence": [
                    {"event_type": "phishing_detected", "where": {"min_confidence": 0.6}},
                    {"event_type": "malware_download", "within": "1h", "same": ["entities.user"]},
                ],
            }
        ]
    }

    engine = CorrelationEngine(compile_rules(ruleset))

    e1 = {
        "event_id": "E1",
        "timestamp": "2026-02-08T10:00:00Z",
        "event_type": "phishing_detected",
        "source": "phishing_detector",
        "entities": {"user": "alice", "domain": "evil.com"},
        "severity": 6,
        "confidence": 0.9,
        "tags": [],
        "raw": {},
    }
    e2 = {
        "event_id": "E2",
        "timestamp": "2026-02-08T10:10:00Z",
        "event_type": "malware_download",
        "source": "network_analysis",
        "entities": {"user": "alice", "domain": "evil.com"},
        "severity": 8,
        "confidence": 0.7,
        "tags": [],
        "raw": {},
    }

    assert engine.add_event(e1) == []
    alerts = engine.add_event(e2)
    assert len(alerts) == 1
    a = alerts[0]

    # scored fields exist
    assert "confidence" in a and 0.0 <= a["confidence"] <= 1.0
    assert "severity_score" in a and 1 <= a["severity_score"] <= 10
    assert "explanation" in a and "steps" in a["explanation"]
    assert len(a["explanation"]["steps"]) == 2
    assert a["event_ids"] == ["E1", "E2"]


def test_step4_dedupe_blocks_repeat_same_incident_bucket():
    ruleset = {
        "rules": [
            {
                "id": "R011",
                "name": "scan_then_exploit",
                "enabled": True,
                "severity": "critical",
                "confidence": 0.9,
                "max_span": "1h",
                "sequence": [
                    {"event_type": "port_scan"},
                    {"event_type": "exploit_attempt", "within": "30m", "same": ["entities.dst_ip"]},
                ],
            }
        ]
    }
    engine = CorrelationEngine(compile_rules(ruleset))

    s1 = {
        "event_id": "S1",
        "timestamp": "2026-02-08T10:00:00Z",
        "event_type": "port_scan",
        "source": "network_analysis",
        "entities": {"dst_ip": "10.0.0.5"},
        "severity": 4,
        "confidence": 0.7,
        "tags": [],
        "raw": {},
    }
    s2 = {
        "event_id": "S2",
        "timestamp": "2026-02-08T10:05:00Z",
        "event_type": "exploit_attempt",
        "source": "network_analysis",
        "entities": {"dst_ip": "10.0.0.5"},
        "severity": 9,
        "confidence": 0.9,
        "tags": [],
        "raw": {},
    }
    s3 = {
        "event_id": "S3",
        "timestamp": "2026-02-08T10:06:00Z",
        "event_type": "exploit_attempt",
        "source": "network_analysis",
        "entities": {"dst_ip": "10.0.0.5"},
        "severity": 9,
        "confidence": 0.9,
        "tags": [],
        "raw": {},
    }

    assert engine.add_event(s1) == []
    a1 = engine.add_event(s2)
    assert len(a1) == 1

    # Adding another exploit event in same time bucket should not re-emit same incident
    a2 = engine.add_event(s3)
    assert a2 == []

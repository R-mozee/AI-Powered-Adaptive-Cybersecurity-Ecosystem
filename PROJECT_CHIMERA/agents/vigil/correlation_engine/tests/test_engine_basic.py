from agents.vigil.correlation_engine.rules.matcher import compile_rules
from agents.vigil.correlation_engine.engine import CorrelationEngine


def test_engine_phish_then_download_emits_alert():
    ruleset = {
        "rules": [
            {
                "id": "R001",
                "name": "phish_then_download",
                "description": "Phishing then malware download within 1 hour, same user.",
                "enabled": True,
                "severity": "high",
                "confidence": 0.85,
                "max_span": "2h",
                "sequence": [
                    {"event_type": "phishing_detected", "where": {"min_confidence": 0.6}},
                    {"event_type": "malware_download", "within": "1h", "same": ["entities.user"]},
                ],
            }
        ]
    }

    compiled = compile_rules(ruleset)
    engine = CorrelationEngine(compiled)

    e1 = {
        "event_id": "E1",
        "timestamp": "2026-02-08T10:00:00Z",
        "event_type": "phishing_detected",
        "source": "phishing_detector",
        "entities": {"user": "alice", "domain": "evil.com"},
        "severity": 6,
        "confidence": 0.9,
        "tags": [],
        "raw": {"x": 1},
    }

    e2 = {
        "event_id": "E2",
        "timestamp": "2026-02-08T10:30:00Z",
        "event_type": "malware_download",
        "source": "network_analysis",
        "entities": {"user": "alice", "domain": "evil.com"},
        "severity": 5,
        "confidence": 0.8,
        "tags": [],
        "raw": {"x": 2},
    }

    # Add first event - no alert yet
    a1 = engine.add_event(e1)
    assert a1 == []

    # Add second event - should correlate
    a2 = engine.add_event(e2)
    assert len(a2) == 1
    alert = a2[0]
    assert alert["rule_id"] == "R001"
    assert alert["event_ids"] == ["E1", "E2"]
    assert alert["severity"] == "high"


def test_engine_respects_within_window_no_alert():
    ruleset = {
        "rules": [
            {
                "id": "R002",
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
    compiled = compile_rules(ruleset)
    engine = CorrelationEngine(compiled)

    e1 = {
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

    # exploit comes too late (after 30m)
    e2 = {
        "event_id": "S2",
        "timestamp": "2026-02-08T10:45:00Z",
        "event_type": "exploit_attempt",
        "source": "network_analysis",
        "entities": {"dst_ip": "10.0.0.5"},
        "severity": 8,
        "confidence": 0.9,
        "tags": [],
        "raw": {},
    }

    assert engine.add_event(e1) == []
    assert engine.add_event(e2) == []

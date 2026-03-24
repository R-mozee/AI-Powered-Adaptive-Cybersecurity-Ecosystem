import pytest
from datetime import datetime, timezone

from agents.vigil.correlation_engine.normalizer import normalize_event, EventNormalizationError


def test_normalize_phishing_event_minimal():
    raw = {
        "event_type": "phishing_detected",
        "timestamp": "2026-02-08T10:15:30Z",
        "from": "attacker@evil.com",
        "to": "user@college.edu",
        "url": "https://evil.com/login",
        "confidence": 0.92,
        "severity": 6
    }
    e = normalize_event(raw, source="phishing_detector")
    assert e["event_type"] == "phishing_detected"
    assert e["source"] == "phishing_detector"
    assert e["entities"]["url"] == "https://evil.com/login"
    assert e["entities"]["domain"] == "evil.com"
    assert e["entities"]["email_from"] == "attacker@evil.com"
    assert e["entities"]["email_to"] == "user@college.edu"
    assert 0.0 <= e["confidence"] <= 1.0
    assert 1 <= e["severity"] <= 10
    assert e["raw"] is raw


def test_normalize_network_anomaly_src_dst_ip():
    raw = {
        "type": "port_scan",
        "time": 1760000000,  # unix seconds
        "source_ip": "192.168.1.10",
        "dest_ip": "10.0.0.5",
        "severity": 4,
        "score": 0.7
    }
    e = normalize_event(raw, source="network_analysis")
    assert e["event_type"] == "port_scan"
    assert e["entities"]["src_ip"] == "192.168.1.10"
    assert e["entities"]["dst_ip"] == "10.0.0.5"
    assert e["confidence"] == 0.7


def test_normalize_urlintel_indicator_ip():
    raw = {
        "name": "suspicious_ip",
        "ts": "2026-02-08T08:00:00+05:30",
        "indicator_ip": "8.8.8.8",
        "risk_score": 0.55,
        "priority": 3,
        "tags": "osint,blocklist"
    }
    e = normalize_event(raw, source="url_intel")
    assert e["entities"]["ip"] == "8.8.8.8"
    assert "osint" in e["tags"] and "blocklist" in e["tags"]
    assert e["event_type"] == "suspicious_ip"


def test_missing_timestamp_strict_rejected():
    raw = {"event_type": "phishing_detected", "confidence": 0.8}
    with pytest.raises(EventNormalizationError) as ex:
        normalize_event(raw, source="phishing_detector", strict=True)
    assert "Missing timestamp" in str(ex.value)


def test_malformed_ip_strict_rejected():
    raw = {
        "event_type": "ddos",
        "timestamp": "2026-02-08T10:00:00Z",
        "src_ip": "999.1.1.1",
        "dst_ip": "10.0.0.1"
    }
    with pytest.raises(EventNormalizationError) as ex:
        normalize_event(raw, source="network_analysis", strict=True)
    assert "Malformed IPv4" in str(ex.value)


def test_confidence_out_of_range_strict_rejected():
    raw = {
        "event_type": "url_flagged",
        "timestamp": "2026-02-08T10:00:00Z",
        "url": "https://example.com",
        "confidence": 1.5
    }
    with pytest.raises(EventNormalizationError) as ex:
        normalize_event(raw, source="url_intel", strict=True)
    assert "confidence out of range" in str(ex.value)


def test_non_strict_defaults_timestamp_and_clamps_confidence_and_drops_bad_ip():
    raw = {
        "event_type": "anomaly",
        "src_ip": "999.1.1.1",
        "dst_ip": "10.0.0.1",
        "confidence": 99,
        "severity": 99
    }
    e = normalize_event(raw, source="network_analysis", strict=False)
    assert isinstance(e["timestamp"], str) and len(e["timestamp"]) > 10
    assert e["confidence"] == 1.0
    assert e["severity"] == 10
    assert e["entities"]["src_ip"] is None
    assert e["entities"]["dst_ip"] is None or e["entities"]["dst_ip"] == "10.0.0.1"

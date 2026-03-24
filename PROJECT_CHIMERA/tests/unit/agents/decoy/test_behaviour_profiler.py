import pytest
from agents.decoy.attacker_analysis.behavior_profiler import BehaviorProfiler

def make_event(event_id, action, ip="10.0.0.5", timestamp="2024-01-01T10:00:00"):
    return {
        "event_id":  event_id,
        "action":    action,
        "source":    {"remote_ip": ip},
        "timestamp": timestamp,
        "severity":  "HIGH",
    }

def test_single_event_creates_one_session():
    profiler = BehaviorProfiler(window_seconds=300)
    events = [make_event("1", "file_read")]
    sessions = profiler.profile(events)
    assert len(sessions) == 1

def test_groups_close_events_into_one_session():
    profiler = BehaviorProfiler(window_seconds=300)
    events = [
        make_event("1", "file_read",  timestamp="2024-01-01T10:00:00"),
        make_event("2", "file_copy",  timestamp="2024-01-01T10:02:00"),
    ]
    sessions = profiler.profile(events)
    assert len(sessions) == 1
    assert sessions[0]["event_count"] == 2

def test_splits_events_outside_window():
    profiler = BehaviorProfiler(window_seconds=60)
    events = [
        make_event("1", "service_connect", timestamp="2024-01-01T10:00:00"),
        make_event("2", "service_connect", timestamp="2024-01-01T10:05:00"),
    ]
    sessions = profiler.profile(events)
    assert len(sessions) == 2

def test_detects_credential_harvesting_pattern():
    profiler = BehaviorProfiler(window_seconds=300)
    events = [
        make_event("1", "file_read"),
        make_event("2", "canary_triggered", timestamp="2024-01-01T10:01:00"),
    ]
    sessions = profiler.profile(events)
    assert "credential_harvesting" in sessions[0]["attack_patterns"]

def test_detects_lateral_movement_pattern():
    profiler = BehaviorProfiler(window_seconds=300)
    events = [
        make_event("1", "service_connect"),
        make_event("2", "file_copy",       timestamp="2024-01-01T10:01:00"),
    ]
    sessions = profiler.profile(events)
    assert "lateral_movement" in sessions[0]["attack_patterns"]

def test_groups_by_source_ip():
    profiler = BehaviorProfiler(window_seconds=300)
    events = [
        make_event("1", "file_read", ip="10.0.0.1", timestamp="2024-01-01T10:00:00"),
        make_event("2", "file_read", ip="10.0.0.2", timestamp="2024-01-01T10:00:05"),
    ]
    sessions = profiler.profile(events)
    assert len(sessions) == 2  # different IPs = different sessions

def test_session_confidence_is_always_high():
    profiler = BehaviorProfiler(window_seconds=300)
    sessions = profiler.profile([make_event("1", "file_read")])
    assert sessions[0]["confidence"] == "HIGH"
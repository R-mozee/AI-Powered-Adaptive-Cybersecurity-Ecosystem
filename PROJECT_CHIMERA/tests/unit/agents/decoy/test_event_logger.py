import pytest
import os
from agents.decoy.attacker_analysis.event_logger import EventLogger

TEST_DB = "tests/unit/agents/decoy/test_events.db"

@pytest.fixture(autouse=True)
def cleanup():
    yield
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

def make_event(event_id="evt-001", action="file_read"):
    return {
        "event_id":  event_id,
        "trap_id":   "trap-001",
        "trap_type": "FileShareTrap",
        "action":    action,
        "source":    {"file_path": "/tmp/trap/passwords.txt"},
        "severity":  "HIGH",
        "timestamp": "2024-01-01T10:00:00",
    }

def test_log_stores_event():
    logger = EventLogger(TEST_DB)
    logger.log(make_event())
    events = logger.get_unexported()
    assert len(events) == 1
    assert events[0]["event_id"] == "evt-001"

def test_duplicate_event_ignored():
    logger = EventLogger(TEST_DB)
    logger.log(make_event())
    logger.log(make_event())  # same event_id
    events = logger.get_unexported()
    assert len(events) == 1

def test_mark_exported():
    logger = EventLogger(TEST_DB)
    logger.log(make_event("evt-001"))
    logger.log(make_event("evt-002", action="file_copy"))
    logger.mark_exported(["evt-001"])
    unexported = logger.get_unexported()
    assert len(unexported) == 1
    assert unexported[0]["event_id"] == "evt-002"

def test_source_is_deserialized():
    logger = EventLogger(TEST_DB)
    logger.log(make_event())
    event = logger.get_unexported()[0]
    assert isinstance(event["source"], dict)
    assert "file_path" in event["source"]
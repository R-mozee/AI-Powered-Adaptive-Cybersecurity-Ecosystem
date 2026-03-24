import pytest
from unittest.mock import patch, MagicMock
from agents.decoy.trap_manager.trap_manager import TrapManager

MOCK_CONFIG = {
    "honeypots": {
        "file_share":   {"enabled": False},
        "fake_service": {"enabled": False, "services": []},
        "canary_token": {"enabled": False},
    },
    "attacker_analysis": {
        "evolve_endpoint":        "http://localhost:5000/api/evolve/ingest",
        "behavior_window_seconds": 300,
        "export_to_evolve":        True,
        "high_threat_actions":    ["file_read"],
    },
    "database": {"path": ":memory:"},
    "logging":  {"level": "INFO", "file": "logs/decoy.log"},
}

@patch("agents.decoy.trap_manager.trap_manager.yaml.safe_load", return_value=MOCK_CONFIG)
@patch("builtins.open", MagicMock())
def test_deploy_all_with_no_traps_enabled(mock_yaml):
    manager = TrapManager("fake/path/config.yaml")
    manager.deploy_all()
    assert len(manager._active_traps) == 0

@patch("agents.decoy.trap_manager.trap_manager.yaml.safe_load", return_value=MOCK_CONFIG)
@patch("builtins.open", MagicMock())
def test_status_returns_correct_structure(mock_yaml):
    manager = TrapManager("fake/path/config.yaml")
    status = manager.status()
    assert "total_traps" in status
    assert "active" in status

@patch("agents.decoy.trap_manager.trap_manager.yaml.safe_load", return_value=MOCK_CONFIG)
@patch("builtins.open", MagicMock())
def test_teardown_clears_active_traps(mock_yaml):
    manager = TrapManager("fake/path/config.yaml")
    manager.teardown_all()
    assert manager._active_traps == []
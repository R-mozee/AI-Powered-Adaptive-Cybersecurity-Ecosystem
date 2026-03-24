import pytest
import os
import tempfile
from agents.decoy.honeypots.file_share_trap import FileShareTrap

@pytest.fixture
def trap_dir(tmp_path):
    return str(tmp_path / "decoy_files")

def test_deploy_creates_directory(trap_dir):
    received = []
    config = {
        "decoy_directory": trap_dir,
        "lure_files": [
            {"name": "passwords.txt", "content_template": "fake_credentials"}
        ]
    }
    trap = FileShareTrap(config, event_callback=received.append)
    result = trap.deploy()
    assert result is True
    assert os.path.isdir(trap_dir)
    trap.teardown()

def test_deploy_writes_lure_files(trap_dir):
    received = []
    config = {
        "decoy_directory": trap_dir,
        "lure_files": [
            {"name": "secrets.txt", "content_template": "fake_credentials"}
        ]
    }
    trap = FileShareTrap(config, event_callback=received.append)
    trap.deploy()
    assert os.path.exists(os.path.join(trap_dir, "secrets.txt"))
    trap.teardown()

def test_teardown_stops_watcher(trap_dir):
    config = {"decoy_directory": trap_dir, "lure_files": []}
    trap = FileShareTrap(config, event_callback=lambda e: None)
    trap.deploy()
    result = trap.teardown()
    assert result is True
    assert trap.is_active is False
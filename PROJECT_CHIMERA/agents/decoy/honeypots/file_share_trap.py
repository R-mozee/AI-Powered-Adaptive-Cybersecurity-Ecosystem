import os
import yaml
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .base_honeypot import BaseHoneypot

LURE_TEMPLATES = {
    "fake_credentials": "admin:password123\nroot:toor\nftp_user:ftp_pass\n",
    "fake_spreadsheet": b"",   # empty bytes — real xlsx not needed for a trap
    "empty_office_doc": b"",
}

class _TrapFileHandler(FileSystemEventHandler):
    """Watchdog handler — fires on any access to the decoy directory."""

    def __init__(self, honeypot_instance):
        self.honeypot = honeypot_instance

    def on_opened(self, event):
        if not event.is_directory:
            self._report(event.src_path, "file_read")

    def on_moved(self, event):
        self._report(event.src_path, "file_copy")

    def on_deleted(self, event):
        self._report(event.src_path, "file_delete")

    def _report(self, path, action):
        event_data = self.honeypot.build_event(
            action=action,
            source_info={"file_path": path, "pid": None}
            # pid enrichment happens in attacker_analysis layer
        )
        self.honeypot.event_callback(event_data)


class FileShareTrap(BaseHoneypot):
    """
    Creates convincingly-named decoy files in a hidden directory.
    Any filesystem access triggers a HIGH-severity event.
    """

    def __init__(self, config: dict, event_callback):
        super().__init__(config)
        self.trap_dir = Path(config["decoy_directory"]).expanduser()
        self.lure_files = config.get("lure_files", [])
        self.event_callback = event_callback   # injected by TrapManager
        self._observer = None

    def deploy(self) -> bool:
        try:
            self.trap_dir.mkdir(parents=True, exist_ok=True)
            self._write_lure_files()
            self._start_watcher()
            self.is_active = True
            return True
        except Exception as e:
            print(f"[DECOY][FileShareTrap] Deploy failed: {e}")
            return False

    def teardown(self) -> bool:
        try:
            if self._observer:
                self._observer.stop()
                self._observer.join()
            self.is_active = False
            return True
        except Exception as e:
            print(f"[DECOY][FileShareTrap] Teardown failed: {e}")
            return False

    def _write_lure_files(self):
        for lure in self.lure_files:
            content = LURE_TEMPLATES.get(lure["content_template"], b"")
            filepath = self.trap_dir / lure["name"]
            if not filepath.exists():
                mode = "w" if isinstance(content, str) else "wb"
                with open(filepath, mode) as f:
                    f.write(content)

    def _start_watcher(self):
        handler = _TrapFileHandler(self)
        self._observer = Observer()
        self._observer.schedule(handler, str(self.trap_dir), recursive=False)
        self._observer.start()
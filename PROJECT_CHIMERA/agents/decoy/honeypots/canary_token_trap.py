import os
import threading
import socket
from pathlib import Path
from .base_honeypot import BaseHoneypot

CANARY_CONTENT_TEMPLATE = """
# CONFIDENTIAL — Internal use only
# Server credentials for production environment
DB_HOST=prod-db-01.internal
DB_USER=admin
DB_PASS=Sup3rS3cr3t!
API_KEY=sk-prod-xxxxxxxxxxxxxxxxxxxxxxxx
"""

class CanaryTokenTrap(BaseHoneypot):
    """
    Drops a .env / config-looking lure file that contains a 
    fake URL or callback address. If an attacker reads the file
    and tries to use the credentials, the callback listener fires.
    
    This is a two-stage trap:
    Stage 1 — FileShareTrap detects file read
    Stage 2 — CanaryToken detects actual exploitation attempt
    """

    def __init__(self, config: dict, event_callback):
        super().__init__(config)
        self.token_dir  = Path(config["token_dir"]).expanduser()
        self.cb_host    = config.get("callback_host", "127.0.0.1")
        self.cb_port    = config.get("callback_port", 9999)
        self.event_callback = event_callback
        self._server    = None
        self._thread    = None
        self._running   = False

    def deploy(self) -> bool:
        try:
            self.token_dir.mkdir(parents=True, exist_ok=True)
            self._write_canary_file()
            self._start_callback_listener()
            self.is_active = True
            return True
        except Exception as e:
            print(f"[DECOY][CanaryTokenTrap] Deploy failed: {e}")
            return False

    def teardown(self) -> bool:
        self._running = False
        if self._server:
            self._server.close()
        self.is_active = False
        return True

    def _write_canary_file(self):
        # The callback host:port embedded in the file IS the trap
        canary_content = CANARY_CONTENT_TEMPLATE.replace(
            "prod-db-01.internal",
            f"{self.cb_host}:{self.cb_port}"
        )
        filepath = self.token_dir / ".env.production"
        filepath.write_text(canary_content)

    def _start_callback_listener(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.cb_host, self.cb_port))
        self._server.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    def _listen_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                data = conn.recv(512).decode(errors="replace")
                conn.close()
                event = self.build_event(
                    action="canary_triggered",
                    source_info={
                        "remote_ip":       addr[0],
                        "connection_data": data[:256],
                        "stage":           "exploitation_attempt",
                    }
                )
                self.event_callback(event)
            except OSError:
                break
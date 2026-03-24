import socket
import threading
from .base_honeypot import BaseHoneypot

class FakeServiceTrap(BaseHoneypot):
    """
    Spins up a lightweight TCP listener on a bait port.
    Any incoming connection is logged as a HIGH-severity intrusion attempt.
    The banner mimics an old, vulnerable service to look convincing.
    """

    def __init__(self, config: dict, event_callback):
        super().__init__(config)
        self.port = config["port"]
        self.banner = config.get("banner", "Service ready\r\n").encode()
        self.event_callback = event_callback
        self._server_socket = None
        self._thread = None
        self._running = False

    def deploy(self) -> bool:
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(("0.0.0.0", self.port))
            self._server_socket.listen(5)
            self._running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
            self.is_active = True
            return True
        except Exception as e:
            print(f"[DECOY][FakeServiceTrap] Deploy failed on port {self.port}: {e}")
            return False

    def teardown(self) -> bool:
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        self.is_active = False
        return True

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
                conn.sendall(self.banner)

                # Capture first 1024 bytes of attacker's probe
                try:
                    probe_data = conn.recv(1024).decode(errors="replace")
                except Exception:
                    probe_data = ""
                conn.close()

                event = self.build_event(
                    action="service_connect",
                    source_info={
                        "remote_ip":   addr[0],
                        "remote_port": addr[1],
                        "local_port":  self.port,
                        "probe_data":  probe_data[:256],  # truncate for safety
                    }
                )
                self.event_callback(event)
            except OSError:
                break  # socket closed during teardown
import yaml
import logging
from pathlib import Path
from ..honeypots.file_share_trap   import FileShareTrap
from ..honeypots.fake_service_trap import FakeServiceTrap
from ..honeypots.canary_token_trap import CanaryTokenTrap
from ..attacker_analysis.event_logger import EventLogger

logger = logging.getLogger("DECOY.TrapManager")

class TrapManager:
    """
    Central controller for the DECOY agent.
    Reads config.yaml, instantiates all enabled traps,
    and wires their event callbacks to the EventLogger.
    
    Called by core/orchestration/agent_manager.py via BaseAgent.run()
    """

    def __init__(self, config_path: str = None):
        config_path = config_path or Path(__file__).parents[1] / "config.yaml"
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.event_logger = EventLogger(self.config["database"]["path"])
        self._active_traps: list = []

    # ── Lifecycle ────────────────────────────────────────────────

    def deploy_all(self):
        """Deploy every enabled honeypot type defined in config."""
        hp_config = self.config["honeypots"]

        if hp_config["file_share"]["enabled"]:
            trap = FileShareTrap(hp_config["file_share"], self._on_event)
            self._deploy(trap, "FileShareTrap")

        if hp_config["fake_service"]["enabled"]:
            for svc in hp_config["fake_service"]["services"]:
                trap = FakeServiceTrap(svc, self._on_event)
                self._deploy(trap, f"FakeServiceTrap:{svc['port']}")

        if hp_config["canary_token"]["enabled"]:
            trap = CanaryTokenTrap(hp_config["canary_token"], self._on_event)
            self._deploy(trap, "CanaryTokenTrap")

        logger.info(f"[TrapManager] {len(self._active_traps)} traps deployed.")

    def teardown_all(self):
        for trap in self._active_traps:
            trap.teardown()
            logger.info(f"[TrapManager] Torn down: {trap.__class__.__name__}")
        self._active_traps.clear()

    def status(self) -> dict:
        return {
            "total_traps": len(self._active_traps),
            "active": [
                {"type": t.__class__.__name__, "id": t.trap_id}
                for t in self._active_traps if t.is_active
            ]
        }

    # ── Internal ─────────────────────────────────────────────────

    def _deploy(self, trap, label: str):
        if trap.deploy():
            self._active_traps.append(trap)
            logger.info(f"[TrapManager] Deployed: {label}")
        else:
            logger.error(f"[TrapManager] Failed to deploy: {label}")

    def _on_event(self, event: dict):
        """
        Callback injected into every honeypot.
        All trap interactions flow through here → DB → EVOLVE.
        """
        logger.warning(
            f"[DECOY] TRAP TRIGGERED | type={event['trap_type']} "
            f"action={event['action']} source={event['source']}"
        )
        self.event_logger.log(event)
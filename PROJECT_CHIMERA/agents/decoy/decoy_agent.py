import logging
from core.abstractions.agent import BaseAgent
from .trap_manager.trap_manager import TrapManager
from .attacker_analysis.threat_exporter import ThreatExporter

logger = logging.getLogger("DECOY")

class DecoyAgent(BaseAgent):
    """
    DECOY — Advanced Threat Intelligence Agent.
    
    Lifecycle managed by core/orchestration/agent_manager.py.
    Desktop-only. Deploys honeypots on startup, exports
    confirmed threat intelligence to EVOLVE on each cycle.
    """

    def __init__(self, config_path: str = None):
        super().__init__(name="DECOY")
        self.trap_manager = TrapManager(config_path)
        cfg = self.trap_manager.config
        self.exporter = ThreatExporter(
            event_logger     = self.trap_manager.event_logger,
            evolve_endpoint  = cfg["attacker_analysis"]["evolve_endpoint"],
            window_seconds   = cfg["attacker_analysis"]["behavior_window_seconds"],
        )

    def run(self):
        """Called once at agent startup — deploys all traps."""
        logger.info("[DECOY] Deploying honeypots...")
        self.trap_manager.deploy_all()
        logger.info(f"[DECOY] Status: {self.trap_manager.status()}")

    def cycle(self):
        """
        Called periodically by workflow_orchestrator.
        Exports accumulated threat data to EVOLVE.
        """
        result = self.exporter.export()
        logger.info(f"[DECOY] Export cycle complete: {result}")

    def shutdown(self):
        """Called on graceful shutdown — tears down all traps."""
        logger.info("[DECOY] Tearing down all honeypots...")
        self.trap_manager.teardown_all()

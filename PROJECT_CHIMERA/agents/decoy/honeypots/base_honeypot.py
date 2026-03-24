from abc import ABC, abstractmethod
from datetime import datetime
import uuid

class BaseHoneypot(ABC):
    """
    Abstract base for all DECOY trap types.
    Every honeypot must implement deploy(), teardown(), and
    return structured TrapEvent dicts on interaction.
    """

    def __init__(self, config: dict):
        self.config = config
        self.trap_id = str(uuid.uuid4())
        self.deployed_at = None
        self.is_active = False

    @abstractmethod
    def deploy(self) -> bool:
        """Activate the trap. Returns True on success."""
        pass

    @abstractmethod
    def teardown(self) -> bool:
        """Safely remove the trap. Returns True on success."""
        pass

    def build_event(self, action: str, source_info: dict) -> dict:
        """
        Builds a standardized TrapEvent for any interaction.
        All events go to EventLogger → SQLite → EVOLVE pipeline.
        """
        return {
            "event_id":   str(uuid.uuid4()),
            "trap_id":    self.trap_id,
            "trap_type":  self.__class__.__name__,
            "action":     action,           # e.g. "file_read", "service_connect"
            "source":     source_info,      # ip, pid, process_name, etc.
            "timestamp":  datetime.utcnow().isoformat(),
            "severity":   "HIGH",           # any honeypot interaction = HIGH by design
        }
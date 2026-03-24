import json
import logging
import requests
from .event_logger      import EventLogger
from .behavior_profiler import BehaviorProfiler

logger = logging.getLogger("DECOY.ThreatExporter")

class ThreatExporter:
    """
    Pulls unexported events from SQLite, runs them through
    BehaviorProfiler, and POSTs attack sessions to EVOLVE's
    ingest endpoint for model retraining.
    
    Called periodically by core/orchestration/workflow_orchestrator.py
    """

    def __init__(self, event_logger: EventLogger, evolve_endpoint: str, window_seconds: int = 300):
        self.logger   = event_logger
        self.profiler = BehaviorProfiler(window_seconds)
        self.endpoint = evolve_endpoint

    def export(self) -> dict:
        events = self.logger.get_unexported()
        if not events:
            logger.info("[ThreatExporter] No new events to export.")
            return {"exported": 0, "sessions": 0}

        sessions = self.profiler.profile(events)
        exported_ids = []

        for session in sessions:
            try:
                resp = requests.post(
                    self.endpoint,
                    json={"agent": "DECOY", "session": session},
                    timeout=5,
                )
                if resp.status_code == 200:
                    ids = [e["event_id"] for e in session["raw_events"]]
                    exported_ids.extend(ids)
                    logger.info(
                        f"[ThreatExporter] Exported session {session['session_id']} "
                        f"({len(ids)} events)"
                    )
                else:
                    logger.warning(f"[ThreatExporter] EVOLVE returned {resp.status_code}")
            except requests.RequestException as e:
                logger.error(f"[ThreatExporter] Failed to reach EVOLVE: {e}")

        self.logger.mark_exported(exported_ids)
        return {"exported": len(exported_ids), "sessions": len(sessions)}
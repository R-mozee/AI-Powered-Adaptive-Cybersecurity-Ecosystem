import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("DECOY.BehaviorProfiler")

# Based on MITRE ATT&CK framework mappings
ATTACK_PATTERNS = {
    "credential_harvesting": {"file_read", "canary_triggered"},
    "lateral_movement":      {"service_connect", "file_copy"},
    "data_exfiltration":     {"file_copy", "canary_triggered"},
    "reconnaissance":        {"service_connect"},
}

class BehaviorProfiler:
    """
    Groups raw TrapEvents into attack sessions and
    maps them to known ATT&CK patterns.
    
    Output is consumed by ThreatExporter → EVOLVE agent.
    """

    def __init__(self, window_seconds: int = 300):
        self.window = timedelta(seconds=window_seconds)

    def profile(self, events: list) -> list:
        """
        Takes a flat list of TrapEvents, groups by source IP / process,
        and returns a list of AttackSession dicts.
        """
        sessions = self._group_into_sessions(events)
        return [self._analyze_session(s) for s in sessions]

    def _group_into_sessions(self, events: list) -> list:
        """
        Two events belong to the same session if they share a
        source identifier and fall within the time window.
        """
        by_source = defaultdict(list)
        for ev in events:
            key = ev["source"].get("remote_ip") or ev["source"].get("file_path", "local")
            by_source[key].append(ev)

        sessions = []
        for source_key, evs in by_source.items():
            evs.sort(key=lambda e: e["timestamp"])
            current_session = [evs[0]]
            for ev in evs[1:]:
                t_prev = datetime.fromisoformat(current_session[-1]["timestamp"])
                t_curr = datetime.fromisoformat(ev["timestamp"])
                if t_curr - t_prev <= self.window:
                    current_session.append(ev)
                else:
                    sessions.append(current_session)
                    current_session = [ev]
            sessions.append(current_session)

        return sessions

    def _analyze_session(self, events: list) -> dict:
        actions   = {e["action"] for e in events}
        source_id = (events[0]["source"].get("remote_ip")
                     or events[0]["source"].get("file_path", "local"))
        patterns  = [
            pattern for pattern, required_actions in ATTACK_PATTERNS.items()
            if required_actions & actions  # intersection — partial match counts
        ]

        return {
            "session_id":   events[0]["event_id"],
            "source":       source_id,
            "event_count":  len(events),
            "actions":      list(actions),
            "attack_patterns": patterns,
            "confidence":   "HIGH",     # honeypot interaction = guaranteed threat
            "start_time":   events[0]["timestamp"],
            "end_time":     events[-1]["timestamp"],
            "raw_events":   events,
        }
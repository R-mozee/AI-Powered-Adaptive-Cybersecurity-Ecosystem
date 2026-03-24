import sqlite3
import json
import logging
from pathlib import Path

logger = logging.getLogger("DECOY.EventLogger")

class EventLogger:

    CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS trap_events (
        event_id    TEXT PRIMARY KEY,
        trap_id     TEXT NOT NULL,
        trap_type   TEXT NOT NULL,
        action      TEXT NOT NULL,
        source_json TEXT NOT NULL,
        severity    TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        exported    INTEGER DEFAULT 0
    );
    """

    def __init__(self, db_path: str):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute(self.CREATE_TABLE)

    def _conn(self):
        return sqlite3.connect(str(self.db_path))

    def log(self, event: dict):
        sql = """
        INSERT OR IGNORE INTO trap_events
        (event_id, trap_id, trap_type, action, source_json, severity, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(sql, (
                    event["event_id"],
                    event["trap_id"],
                    event["trap_type"],
                    event["action"],
                    json.dumps(event["source"]),
                    event["severity"],
                    event["timestamp"],
                ))
        except Exception as e:
            logger.error(f"[EventLogger] Failed to store event: {e}")

    def get_unexported(self) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM trap_events WHERE exported = 0 ORDER BY timestamp ASC"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def mark_exported(self, event_ids: list):
        with self._conn() as conn:
            conn.executemany(
                "UPDATE trap_events SET exported = 1 WHERE event_id = ?",
                [(eid,) for eid in event_ids]
            )

    def _row_to_dict(self, row) -> dict:
        cols = ["event_id", "trap_id", "trap_type", "action",
                "source_json", "severity", "timestamp", "exported"]
        d = dict(zip(cols, row))
        d["source"] = json.loads(d.pop("source_json"))
        return d
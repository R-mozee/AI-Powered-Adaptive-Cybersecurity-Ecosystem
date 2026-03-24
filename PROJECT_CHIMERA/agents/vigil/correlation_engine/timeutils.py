from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional


def parse_iso8601(ts: str) -> datetime:
    """
    Accepts ISO timestamps like:
      - 2026-02-08T10:00:00Z
      - 2026-02-08T10:00:00+05:30
      - 2026-02-08T10:00:00
    Returns timezone-aware UTC datetime.
    """
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def window_to_timedelta(window: Optional[str]) -> Optional[timedelta]:
    """
    window format: <int><unit> where unit in {s,m,h,d}
    Examples: 30m, 1h, 10s, 2d
    """
    if window is None:
        return None
    w = window.strip()
    if len(w) < 2:
        raise ValueError(f"Invalid window: {window!r}")
    n = int(w[:-1])
    unit = w[-1]
    if unit == "s":
        return timedelta(seconds=n)
    if unit == "m":
        return timedelta(minutes=n)
    if unit == "h":
        return timedelta(hours=n)
    if unit == "d":
        return timedelta(days=n)
    raise ValueError(f"Invalid window unit: {window!r}")

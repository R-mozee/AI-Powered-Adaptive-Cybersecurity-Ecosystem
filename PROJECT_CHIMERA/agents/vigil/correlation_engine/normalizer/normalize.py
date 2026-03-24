from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
import re
import uuid


@dataclass
class EventNormalizationError(ValueError):
    """Raised when a raw event cannot be normalized to the correlation contract."""
    message: str

    def __str__(self) -> str:
        return self.message


_IPv4_RE = re.compile(
    r"^("
    r"(25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"(25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"(25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"(25[0-5]|2[0-4]\d|1?\d?\d)"
    r")$"
)

# Very conservative domain pattern (not perfect, but safe enough for normalization)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

_URL_RE = re.compile(r"^(https?://)", re.IGNORECASE)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> str:
    """
    Returns ISO-8601 timestamp string.
    Accepts:
      - ISO strings with/without Z
      - Unix seconds (int/float) (assumed UTC)
      - datetime
    """
    if value is None:
        raise EventNormalizationError("Missing timestamp")

    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")

    if isinstance(value, str):
        s = value.strip()
        # support trailing Z
        if s.endswith("Z"):
            s2 = s[:-1] + "+00:00"
        else:
            s2 = s
        try:
            dt = datetime.fromisoformat(s2)
        except Exception:
            raise EventNormalizationError(f"Invalid timestamp format: {value!r}")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    raise EventNormalizationError(f"Unsupported timestamp type: {type(value).__name__}")


def _as_float(value: Any, *, field: str) -> float:
    try:
        return float(value)
    except Exception:
        raise EventNormalizationError(f"Invalid {field}: expected number, got {value!r}")


def _as_int(value: Any, *, field: str) -> int:
    try:
        return int(value)
    except Exception:
        raise EventNormalizationError(f"Invalid {field}: expected int, got {value!r}")


def _is_ipv4(s: Optional[str]) -> bool:
    if not s:
        return False
    return bool(_IPv4_RE.match(s.strip()))


def _clean_ip(s: Any) -> Optional[str]:
    if s is None:
        return None
    if not isinstance(s, str):
        s = str(s)
    s = s.strip()
    if not s:
        return None
    if _is_ipv4(s):
        return s
    # Reject malformed IPs (quality-first)
    raise EventNormalizationError(f"Malformed IPv4 address: {s!r}")


def _clean_domain(s: Any) -> Optional[str]:
    if s is None:
        return None
    if not isinstance(s, str):
        s = str(s)
    s = s.strip().lower()
    if not s:
        return None

    # If a URL is passed accidentally, try extracting host-ish part
    if _URL_RE.search(s):
        # naive extraction: split scheme:// then take until / or :
        try:
            host = s.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
            s = host.strip().lower()
        except Exception:
            return None

    if _DOMAIN_RE.match(s):
        return s

    # Not throwing here because domains can be weird; we keep it soft.
    return None


def _clean_url(s: Any) -> Optional[str]:
    if s is None:
        return None
    if not isinstance(s, str):
        s = str(s)
    s = s.strip()
    if not s:
        return None
    if _URL_RE.search(s):
        return s
    return None


def _pick_first(d: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
    for k in keys:
        if k in d and d[k] is not None and d[k] != "":
            return d[k]
    return None


def _normalize_entities(raw: Dict[str, Any]) -> Dict[str, Any]:
    src_ip = _pick_first(raw, ("src_ip", "source_ip", "src", "ip_src", "client_ip"))
    dst_ip = _pick_first(raw, ("dst_ip", "dest_ip", "destination_ip", "dst", "ip_dst", "server_ip"))
    single_ip = _pick_first(raw, ("ip", "suspicious_ip", "indicator_ip"))

    url = _pick_first(raw, ("url", "suspicious_url", "link", "clicked_url"))
    domain = _pick_first(raw, ("domain", "hostname", "host", "suspicious_domain"))

    user = _pick_first(raw, ("user", "username", "account", "victim_user"))
    host = _pick_first(raw, ("host", "hostname", "device", "machine"))

    email_from = _pick_first(raw, ("from", "email_from", "sender", "sender_email"))
    email_to = _pick_first(raw, ("to", "email_to", "recipient", "recipient_email"))

    entities: Dict[str, Any] = {}

    # IPs: strict validation
    try:
        entities["src_ip"] = _clean_ip(src_ip)
    except EventNormalizationError:
        # If source gives non-IP identifiers in src fields, keep null instead of crashing the entire pipeline
        entities["src_ip"] = None
        raise
    try:
        entities["dst_ip"] = _clean_ip(dst_ip)
    except EventNormalizationError:
        entities["dst_ip"] = None
        raise

    # indicator single IP
    if single_ip is not None:
        entities["ip"] = _clean_ip(single_ip)
    else:
        entities["ip"] = None

    # URL/domain: soft cleaning
    entities["url"] = _clean_url(url)
    entities["domain"] = _clean_domain(domain) or _clean_domain(url)

    entities["user"] = str(user).strip() if user is not None and str(user).strip() else None
    entities["host"] = str(host).strip() if host is not None and str(host).strip() else None

    entities["email_from"] = str(email_from).strip() if email_from is not None and str(email_from).strip() else None
    entities["email_to"] = str(email_to).strip() if email_to is not None and str(email_to).strip() else None

    return entities


def _validate_contract(event: Dict[str, Any]) -> None:
    # Required fields
    required = ("event_id", "timestamp", "event_type", "source", "entities", "severity", "confidence", "raw")
    missing = [k for k in required if k not in event or event[k] is None]
    if missing:
        raise EventNormalizationError(f"Normalized event missing required fields: {missing}")

    # Types/ranges
    if not isinstance(event["event_id"], str) or len(event["event_id"]) < 8:
        raise EventNormalizationError("event_id must be a non-empty string")

    if not isinstance(event["timestamp"], str) or len(event["timestamp"]) < 10:
        raise EventNormalizationError("timestamp must be an ISO-8601 string")

    if not isinstance(event["event_type"], str) or not event["event_type"].strip():
        raise EventNormalizationError("event_type must be a non-empty string")

    if not isinstance(event["source"], str) or not event["source"].strip():
        raise EventNormalizationError("source must be a non-empty string")

    sev = event["severity"]
    if not isinstance(sev, int) or not (1 <= sev <= 10):
        raise EventNormalizationError("severity must be int in range 1..10")

    conf = event["confidence"]
    if not isinstance(conf, (float, int)) or not (0.0 <= float(conf) <= 1.0):
        raise EventNormalizationError("confidence must be float in range 0..1")

    if not isinstance(event["entities"], dict):
        raise EventNormalizationError("entities must be an object/dict")

    if not isinstance(event["raw"], dict):
        raise EventNormalizationError("raw must be an object/dict")


def normalize_event(
    raw_event: Dict[str, Any],
    *,
    source: str,
    default_severity: int = 3,
    default_confidence: float = 0.6,
    strict: bool = True
) -> Dict[str, Any]:
    """
    Normalize arbitrary VIGIL events into a single correlation-friendly contract.

    strict=True:
      - Missing timestamp => error
      - Malformed IPs => error
      - confidence out of bounds => error
    strict=False:
      - Missing timestamp => current UTC time
      - Malformed IPs => set to None (does not error)
      - confidence => clamped into 0..1
    """
    if not isinstance(raw_event, dict):
        raise EventNormalizationError("raw_event must be a dict/object")

    if not source or not isinstance(source, str):
        raise EventNormalizationError("source must be a non-empty string")

    # event_type inference
    event_type = _pick_first(raw_event, ("event_type", "type", "alert_type", "name", "category"))
    if event_type is None:
        # allow "phishing_detected" if detector outputs boolean-like flags
        if raw_event.get("is_phishing") is True:
            event_type = "phishing_detected"
        else:
            raise EventNormalizationError("Missing event_type (expected one of: event_type/type/alert_type/name/category)")

    # timestamp inference
    ts_raw = _pick_first(raw_event, ("timestamp", "time", "ts", "event_time", "datetime"))
    if ts_raw is None:
        if strict:
            raise EventNormalizationError("Missing timestamp (expected one of: timestamp/time/ts/event_time/datetime)")
        timestamp = _now_utc_iso()
    else:
        timestamp = _parse_timestamp(ts_raw)

    # severity/confidence
    sev_raw = _pick_first(raw_event, ("severity", "sev", "level", "priority"))
    if sev_raw is None:
        severity = int(default_severity)
    else:
        severity = _as_int(sev_raw, field="severity")

    conf_raw = _pick_first(raw_event, ("confidence", "score", "probability", "risk_score"))
    if conf_raw is None:
        confidence = float(default_confidence)
    else:
        confidence = _as_float(conf_raw, field="confidence")

    if strict:
        if not (0.0 <= confidence <= 1.0):
            raise EventNormalizationError(f"confidence out of range 0..1: {confidence!r}")
    else:
        confidence = max(0.0, min(1.0, confidence))

    if not (1 <= severity <= 10):
        if strict:
            raise EventNormalizationError(f"severity out of range 1..10: {severity!r}")
        severity = max(1, min(10, severity))

    # entities extraction (IP validation is strict by default)
    try:
        entities = _normalize_entities(raw_event)
    except EventNormalizationError:
        if strict:
            raise
        # non-strict: drop IPs if malformed
        entities = {
            "src_ip": None,
            "dst_ip": None,
            "ip": None,
            "url": _clean_url(_pick_first(raw_event, ("url", "suspicious_url", "link", "clicked_url"))),
            "domain": _clean_domain(_pick_first(raw_event, ("domain", "hostname", "host", "suspicious_domain"))),
            "user": str(_pick_first(raw_event, ("user", "username", "account", "victim_user")) or "").strip() or None,
            "host": str(_pick_first(raw_event, ("host", "hostname", "device", "machine")) or "").strip() or None,
            "email_from": str(_pick_first(raw_event, ("from", "email_from", "sender", "sender_email")) or "").strip() or None,
            "email_to": str(_pick_first(raw_event, ("to", "email_to", "recipient", "recipient_email")) or "").strip() or None
        }

    # optional fields
    stage = _pick_first(raw_event, ("stage", "kill_chain_stage", "phase"))
    attack_technique = _pick_first(raw_event, ("attack_technique", "mitre_technique", "technique"))

    tags_raw = raw_event.get("tags", [])
    if tags_raw is None:
        tags = []
    elif isinstance(tags_raw, list):
        tags = [str(t).strip() for t in tags_raw if str(t).strip()]
    else:
        # allow comma-separated
        tags = [t.strip() for t in str(tags_raw).split(",") if t.strip()]

    normalized: Dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "event_type": str(event_type).strip(),
        "source": source.strip(),
        "entities": entities,
        "severity": int(severity),
        "confidence": float(confidence),
        "stage": str(stage).strip() if stage is not None and str(stage).strip() else None,
        "attack_technique": str(attack_technique).strip() if attack_technique is not None and str(attack_technique).strip() else None,
        "tags": tags,
        "raw": raw_event  # keep untouched for debugging
    }

    _validate_contract(normalized)
    return normalized

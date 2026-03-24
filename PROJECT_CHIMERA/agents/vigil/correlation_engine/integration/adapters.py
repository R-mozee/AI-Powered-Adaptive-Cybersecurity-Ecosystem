from __future__ import annotations

from typing import Any, Dict, Optional


def adapt_network_anomaly(anomaly: Dict[str, Any]) -> Dict[str, Any]:
    """
    Expected incoming shapes (examples):
      - {"alert_type":"port_scan","timestamp": "...", "src_ip": "...", "dst_ip":"...", "score":0.7, "severity":4}
      - {"type":"ddos","time": 1760..., "source_ip":"...", "dest_ip":"...", "confidence":0.8}
    Output: raw event dict including a 'source' key.
    """
    e: Dict[str, Any] = dict(anomaly)
    e.setdefault("source", "network_analysis")

    # common mappings
    if "event_type" not in e:
        e["event_type"] = e.get("alert_type") or e.get("type") or e.get("name") or "network_anomaly"

    # timestamp fallbacks
    if "timestamp" not in e:
        e["timestamp"] = e.get("time") or e.get("ts") or e.get("event_time")

    # confidence/score fallbacks
    if "confidence" not in e and "score" in e:
        e["confidence"] = e.get("score")

    return e


def adapt_phishing_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Expected shapes:
      - {"is_phishing": True, "timestamp": "...", "url": "...", "from": "...", "to":"...", "confidence":0.92}
      - {"event_type":"phishing_detected", "time":"...", "sender":"...", "recipient":"...", "link":"..."}
    """
    e: Dict[str, Any] = dict(alert)
    e.setdefault("source", "phishing_detector")

    # ensure event_type
    if "event_type" not in e:
        if e.get("is_phishing") is True:
            e["event_type"] = "phishing_detected"
        else:
            e["event_type"] = e.get("type") or "phishing_alert"

    if "timestamp" not in e:
        e["timestamp"] = e.get("time") or e.get("ts") or e.get("event_time")

    # unify common email fields
    if "from" not in e and "sender" in e:
        e["from"] = e.get("sender")
    if "to" not in e and "recipient" in e:
        e["to"] = e.get("recipient")

    if "url" not in e and "link" in e:
        e["url"] = e.get("link")

    return e


def adapt_url_intel(indicator: Dict[str, Any]) -> Dict[str, Any]:
    """
    Expected shapes:
      - {"indicator":"evil.com","type":"domain_flagged","timestamp":"...", "risk_score":0.7}
      - {"domain":"evil.com","timestamp":"...","event_type":"domain_flagged"}
    """
    e: Dict[str, Any] = dict(indicator)
    e.setdefault("source", "url_intel")

    if "event_type" not in e:
        e["event_type"] = e.get("type") or e.get("name") or "intel_indicator"

    if "timestamp" not in e:
        e["timestamp"] = e.get("time") or e.get("ts") or e.get("event_time")

    if "confidence" not in e and "risk_score" in e:
        e["confidence"] = e.get("risk_score")

    # if indicator is a domain/url/ip, place it in likely keys
    ind = e.get("indicator")
    if ind and not any(k in e for k in ("domain", "url", "ip")):
        s = str(ind)
        if s.startswith("http://") or s.startswith("https://"):
            e["url"] = s
        elif "." in s and not s.replace(".", "").isdigit():
            e["domain"] = s
        else:
            e["ip"] = s

    return e

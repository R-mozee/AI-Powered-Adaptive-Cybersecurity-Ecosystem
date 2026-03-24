from __future__ import annotations

from typing import Any, Dict, List


def golden_event_stream() -> List[Dict[str, Any]]:
    """
    RAW events (not normalized contract). Replay runner will normalize.
    Deterministic timestamps so results are stable.
    """
    return [
        # --- Rule R001: phishing_detected -> malware_download within 1h, same user/domain ---
        {
            "event_type": "phishing_detected",
            "timestamp": "2026-02-08T09:00:00Z",
            "source": "phishing_detector",
            "user": "alice",
            "domain": "evil.com",
            "url": "https://evil.com/login",
            "severity": 6,
            "confidence": 0.90,
            "tags": ["phishing"],
        },
        {
            "event_type": "malware_download",
            "timestamp": "2026-02-08T09:20:00Z",
            "source": "network_analysis",
            "user": "alice",
            "domain": "evil.com",
            "url": "https://evil.com/payload.exe",
            "severity": 7,
            "confidence": 0.80,
            "tags": ["download"],
        },

        # --- Rule R002: port_scan -> exploit_attempt within 30m, same dst_ip ---
        {
            "event_type": "port_scan",
            "timestamp": "2026-02-08T10:00:00Z",
            "source": "network_analysis",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.5",
            "severity": 4,
            "confidence": 0.75,
            "tags": ["recon"],
        },
        {
            "event_type": "exploit_attempt",
            "timestamp": "2026-02-08T10:10:00Z",
            "source": "network_analysis",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.5",
            "severity": 9,
            "confidence": 0.90,
            "tags": ["exploit"],
        },

        # --- Noise: should NOT trigger anything ---
        {
            "event_type": "phishing_detected",
            "timestamp": "2026-02-08T11:00:00Z",
            "source": "phishing_detector",
            "user": "bob",
            "domain": "maybe-benign.com",
            "url": "https://maybe-benign.com",
            "severity": 2,
            "confidence": 0.40,
            "tags": ["phishing"],
        },
        {
            "event_type": "malware_download",
            "timestamp": "2026-02-08T13:30:00Z",
            "source": "network_analysis",
            "user": "bob",
            "domain": "maybe-benign.com",
            "url": "https://maybe-benign.com/file",
            "severity": 3,
            "confidence": 0.60,
            "tags": ["download"],
        },
    ]

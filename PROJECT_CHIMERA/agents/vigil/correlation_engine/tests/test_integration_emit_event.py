from agents.vigil.correlation_engine.integration import (
    VigilCorrelationBus,
    CorrelationIntegrationConfig,
    InMemoryAlertSink,
)


def test_emit_network_and_phishing_produces_alerts():
    # Use your real rules
    cfg = CorrelationIntegrationConfig(
        rule_yaml_path="agents/vigil/correlation_engine/rules/basic_rules.yaml",
        rule_schema_path="agents/vigil/correlation_engine/rules/schema/rule_schema.json",
        strict_normalization=True,
    )

    mem = []
    sink = InMemoryAlertSink(mem)

    bus = VigilCorrelationBus.from_config(cfg, sink=sink)

    # 1) phishing event
    r1 = bus.emit(
        {
            "is_phishing": True,
            "timestamp": "2026-02-08T09:00:00Z",
            "user": "alice",
            "url": "https://evil.com/login",
            "domain": "evil.com",
            "confidence": 0.9,
            "severity": 6,
        },
        kind="phishing",
    )
    assert r1.error is None
    assert r1.alerts == []

    # 2) network event that completes sequence (matches R001)
    r2 = bus.emit(
        {
            "alert_type": "malware_download",
            "timestamp": "2026-02-08T09:20:00Z",
            "user": "alice",
            "url": "https://evil.com/payload.exe",
            "domain": "evil.com",
            "score": 0.8,
            "severity": 7,
        },
        kind="network",
    )
    assert r2.error is None
    assert len(r2.alerts) >= 1
    assert len(mem) >= 1  # sink captured alert(s)

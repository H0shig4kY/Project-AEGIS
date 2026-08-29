from pathlib import Path

from aegis.assessment import AssessmentContext
from aegis.context import CampaignContext
from aegis.plugins.builtin.service.plugin import (
    ServiceDiscoveryPlugin,
)

from aegis.models import CoverageType


def create_context(
    tmp_path: Path,
) -> AssessmentContext:
    campaign = tmp_path / "campaign"
    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    return AssessmentContext(
        CampaignContext(campaign)
    )


def test_service_plugin_metadata():
    plugin = ServiceDiscoveryPlugin()

    assert plugin.name == "service"
    assert plugin.version == "0.1.0"
    assert plugin.description


def test_service_plugin_detects_open_port(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("example.com")

    def fake_check_port(
        host,
        port,
        timeout=1.0,
    ):
        return port == 443

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.check_tcp_port",
        fake_check_port,
    )

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.grab_banner",
        lambda host, port: None,
    )

    plugin = ServiceDiscoveryPlugin(
        ports=[22, 80, 443]
    )

    result = plugin.execute(context)

    assert len(result.coverage) == 1

    coverage = result.coverage[0]

    assert coverage.plugin == "service"
    assert coverage.target == "example.com"
    assert (
        coverage.coverage_type
        == CoverageType.SERVICE
    )
    assert coverage.ports == [22, 80, 443]

    assert result.plugin == "service"
    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.target == "example.com"
    assert observation.type == "service_open"

    assert observation.data["port"] == 443
    assert observation.data["transport"] == "tcp"
    assert observation.data["service_name"] == "https"
    assert observation.data["tls"] is True
    assert observation.data["banner"] is None

    assert observation.data["confidence"] == "medium"
    assert (
        observation.data["fingerprint_source"]
        == "port"
    )


def test_service_plugin_can_detect_multiple_ports(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("example.com")

    def fake_check_port(
        host,
        port,
        timeout=1.0,
    ):
        return port in {80, 443}

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.check_tcp_port",
        fake_check_port,
    )

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.grab_banner",
        lambda host, port: None,
    )

    plugin = ServiceDiscoveryPlugin(
        ports=[22, 80, 443]
    )

    result = plugin.execute(context)

    ports = [
        observation.data["port"]
        for observation in result.observations
    ]

    assert ports == [80, 443]

    services = [
        observation.data["service_name"]
        for observation in result.observations
    ]

    assert services == [
        "http",
        "https",
    ]

    banners = [
        observation.data["banner"]
        for observation in result.observations
    ]

    assert banners == [
        None,
        None,
    ]

    confidences = [
        observation.data["confidence"]
        for observation in result.observations
    ]

    assert confidences == [
        "medium",
        "medium",
    ]

    sources = [
        observation.data["fingerprint_source"]
        for observation in result.observations
    ]

    assert sources == [
        "port",
        "port",
    ]


def test_service_plugin_ignores_wildcard(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("*.example.com")

    called = False

    def fake_check_port(
        host,
        port,
        timeout=1.0,
    ):
        nonlocal called
        called = True
        return False

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.check_tcp_port",
        fake_check_port,
    )

    result = ServiceDiscoveryPlugin().execute(
        context
    )

    assert result.observations == []
    assert called is False


def test_service_plugin_processes_ip(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("192.168.1.10")

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.check_tcp_port",
        lambda host, port, timeout=1.0: port == 22,
    )

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.grab_banner",
        lambda host, port: (
            "SSH-2.0-TestSSH"
            if port == 22
            else None
        ),
    )

    plugin = ServiceDiscoveryPlugin(
        ports=[22]
    )

    result = plugin.execute(context)

    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.target == "192.168.1.10"
    assert observation.type == "service_open"

    assert observation.data["port"] == 22
    assert observation.data["transport"] == "tcp"
    assert observation.data["service_name"] == "ssh"
    assert observation.data["tls"] is False

    assert (
        observation.data["banner"]
        == "SSH-2.0-TestSSH"
    )

    assert observation.data["confidence"] == "high"
    assert (
        observation.data["fingerprint_source"]
        == "banner"
    )

def test_service_plugin_records_coverage_even_when_no_ports_open(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("example.com")

    monkeypatch.setattr(
        "aegis.plugins.builtin.service.plugin.check_tcp_port",
        lambda host, port, timeout=1.0: False,
    )

    plugin = ServiceDiscoveryPlugin(
        ports=[22, 80, 443]
    )

    result = plugin.execute(context)

    assert result.observations == []
    assert len(result.coverage) == 1

    coverage = result.coverage[0]

    assert coverage.target == "example.com"
    assert coverage.ports == [22, 80, 443]
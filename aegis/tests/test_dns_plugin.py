from pathlib import Path

from aegis.assessment import AssessmentContext
from aegis.context import CampaignContext
from aegis.models import (
    CoverageType,
)
from aegis.plugins.builtin.dns.plugin import DNSPlugin

def create_context(tmp_path: Path) -> AssessmentContext:
    campaign = tmp_path / "campaign"

    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    return AssessmentContext(
        CampaignContext(campaign)
    )

def test_dns_plugin_metadata():
    plugin = DNSPlugin()

    assert plugin.name == "dns"
    assert plugin.version == "0.1.0"
    assert plugin.description

def test_dns_plugin_ignores_non_domains(tmp_path):
    context = create_context(tmp_path)

    context.scope.add("192.168.1.10")

    plugin = DNSPlugin()

    result = plugin.execute(context)

    assert result.plugin == "dns"
    assert result.version == "0.1.0"
    assert result.observations == []

def test_dns_plugin_processes_domain(tmp_path, monkeypatch):
    context = create_context(tmp_path)

    context.scope.add("example.com")

    def fake_resolve(name):
        return ["93.184.216.34"]

    monkeypatch.setattr(
        "aegis.plugins.builtin.dns.plugin.resolve_domain",
        fake_resolve,
    )

    plugin = DNSPlugin()

    result = plugin.execute(context)

    assert result.plugin == "dns"
    assert result.version == "0.1.0"
    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.target == "example.com"
    assert observation.type == "dns_resolution"
    assert observation.data["addresses"] == [
    "93.184.216.34"
]

def test_dns_plugin_records_coverage_without_addresses(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.scope.add(
        "example.com"
    )

    monkeypatch.setattr(
        "aegis.plugins.builtin.dns.plugin.resolve_domain",
        lambda domain: [],
    )

    plugin = DNSPlugin()

    result = plugin.execute(
        context
    )

    assert len(result.coverage) == 1

    coverage = result.coverage[0]

    assert coverage.plugin == "dns"
    assert coverage.target == "example.com"

    assert (
        coverage.coverage_type
        == CoverageType.DNS
    )

    assert coverage.ports == []
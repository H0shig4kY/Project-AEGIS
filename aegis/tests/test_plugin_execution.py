from pathlib import Path

from aegis.assessment import AssessmentContext
from aegis.context import CampaignContext
from aegis.plugins.registry import create_plugin_manager

def test_execute_dns_plugin(tmp_path: Path, monkeypatch):
    campaign = tmp_path / "campaign"
    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    context = AssessmentContext(
        CampaignContext(campaign)
    )

    context.scope.add("example.com")

    monkeypatch.setattr(
        "aegis.plugins.builtin.dns.plugin.resolve_domain",
        lambda domain: ["192.0.2.10"],
    )

    manager = create_plugin_manager()

    result = manager.execute(
        "dns",
        context,
    )

    assert result.plugin == "dns"
    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.target == "example.com"
    assert observation.type == "dns_resolution"
    assert observation.data["addresses"] == [
    "192.0.2.10"
]
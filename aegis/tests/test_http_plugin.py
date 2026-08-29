from pathlib import Path

from aegis.assessment import AssessmentContext
from aegis.context import CampaignContext
from aegis.plugins.builtin.http.plugin import HTTPPlugin

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

def test_http_plugin_metadata():
    plugin = HTTPPlugin()

    assert plugin.name == "http"
    assert plugin.version == "0.1.0"
    assert plugin.description

def test_http_plugin_processes_domain(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("example.com")

    def fake_probe(domain):
        return {
            "url": "https://example.com/",
            "scheme": "https",
            "status_code": 200,
            "server": "test-server",
            "content_type": "text/html",
        }

    monkeypatch.setattr(
        "aegis.plugins.builtin.http.plugin.probe_http",
        fake_probe,
    )

    plugin = HTTPPlugin()

    result = plugin.execute(context)

    assert result.plugin == "http"
    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.target == "example.com"
    assert observation.type == "http_probe"
    assert (
        observation.data["url"]
        == "https://example.com/"
    )
    assert observation.data["status_code"] == 200

def test_http_plugin_ignores_ip_target(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("192.168.1.10")

    called = False

    def fake_probe(domain):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(
        "aegis.plugins.builtin.http.plugin.probe_http",
        fake_probe,
    )

    result = HTTPPlugin().execute(context)

    assert result.observations == []
    assert called is False

def test_http_plugin_handles_no_response(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("example.com")

    monkeypatch.setattr(
        "aegis.plugins.builtin.http.plugin.probe_http",
        lambda domain: None,
    )

    result = HTTPPlugin().execute(context)

    assert result.plugin == "http"
    assert result.observations == []
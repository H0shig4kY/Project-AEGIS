from pathlib import Path

from aegis.assessment import AssessmentContext
from aegis.context import CampaignContext
from aegis.plugins.builtin.tls.plugin import (
    TLSPlugin,
)
from aegis.results import Observation
from aegis.models import (
    CoverageType,
)


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


def test_tls_plugin_metadata():
    plugin = TLSPlugin()

    assert plugin.name == "tls"
    assert plugin.version == "0.1.0"
    assert plugin.description


def test_tls_plugin_processes_domain(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("example.com")

    monkeypatch.setattr(
        "aegis.plugins.builtin.tls.plugin.inspect_tls",
        lambda host, port: Observation(
            target=host,
            type="tls_handshake",
            data={
                "host": host,
                "port": port,
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "subject": None,
                "issuer": None,
                "valid_from": None,
                "valid_to": None,
                "sans": [
                    "example.com",
                ],
                "certificate_sha256": (
                    "a" * 64
                ),
            },
        ),
    )

    result = TLSPlugin().execute(
        context
    )

    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.type == "tls_handshake"
    assert (
        observation.data["tls_version"]
        == "TLSv1.3"
    )
    assert (
        observation.data[
            "certificate_sha256"
        ]
        == "a" * 64
    )

    assert len(result.coverage) == 1

    coverage = result.coverage[0]

    assert coverage.plugin == "tls"

    assert (
        coverage.target
        == "example.com"
    )

    assert (
        coverage.coverage_type
        == CoverageType.TLS
    )

    assert coverage.ports == []


def test_tls_plugin_ignores_wildcard(
    tmp_path,
    monkeypatch,
):
    context = create_context(tmp_path)

    context.scope.add("*.example.com")

    called = False

    def fake_inspect_tls(host, port):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(
        "aegis.plugins.builtin.tls.plugin.inspect_tls",
        fake_inspect_tls,
    )

    result = TLSPlugin().execute(
        context
    )

    assert result.observations == []
    assert called is False

def test_tls_plugin_records_coverage_without_observation(
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
        "aegis.plugins.builtin.tls.plugin.inspect_tls",
        lambda host, port: None,
    )

    plugin = TLSPlugin()

    result = plugin.execute(
        context
    )

    assert result.observations == []

    assert len(result.coverage) == 1

    coverage = result.coverage[0]

    assert coverage.plugin == "tls"

    assert (
        coverage.target
        == "example.com"
    )

    assert (
        coverage.coverage_type
        == CoverageType.TLS
    )

    assert coverage.ports == []
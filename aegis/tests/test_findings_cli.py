import json
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from pathlib import Path

from typer.testing import CliRunner

from aegis.assessment import AssessmentContext
from aegis.cli import app
from aegis.context import CampaignContext
from aegis.models import (
    Asset,
    AssetType,
)

from aegis.exposure import (
    ExposureAnalyzer,
)


runner = CliRunner()

def get_http_finding_id(
    context,
):
    report = ExposureAnalyzer().analyze(
        assets=context.assets.find(),
        relations=context.relations.find(),
        changes=context.changes.find(),
    )

    return (
        report.findings[0]
        .finding_id
    )

def create_context(
    tmp_path: Path,
) -> AssessmentContext:
    campaign = (
        tmp_path
        / "campaign"
    )

    campaign.mkdir()

    (
        campaign
        / "aegis.yaml"
    ).write_text(
        "name: test\n",
        encoding="utf-8",
    )

    return AssessmentContext(
        CampaignContext(
            campaign
        )
    )


def add_http_finding_asset(
    context,
):
    context.assets.save(
        Asset(
            value="example.com:80",
            type=AssetType.SERVICE,
            source="service",
            metadata={
                "host": "example.com",
                "port": 80,
                "service_name": "http",
                "transport": "tcp",
                "tls": False,
            },
            active=True,
        )
    )


def test_findings_list_empty(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
        ],
    )

    assert result.exit_code == 0
    assert "No findings found." in result.output


def test_findings_list(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    report = ExposureAnalyzer().analyze(
        assets=context.assets.find(),
        relations=context.relations.find(),
        changes=context.changes.find(),
    )

    finding_id = (
        report.findings[0]
        .finding_id
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
        ],
    )

    assert result.exit_code == 0
    assert "HTTP_WITHOUT_TLS" in result.output
    assert "MEDIUM" in result.output
    assert finding_id[:12] in result.output


def test_findings_filter_by_severity(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--severity",
            "medium",
        ],
    )

    assert result.exit_code == 0
    assert "HTTP_WITHOUT_TLS" in result.output


def test_findings_filter_by_rule(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--rule",
            "HTTP_WITHOUT_TLS",
        ],
    )

    assert result.exit_code == 0
    assert "HTTP_WITHOUT_TLS" in result.output


def test_findings_filter_by_asset_type(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--asset-type",
            "service",
        ],
    )

    assert result.exit_code == 0
    assert "HTTP_WITHOUT_TLS" in result.output


def test_findings_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(
        payload
    ) == 1

    finding = payload[0]

    assert "id" in finding

    assert len(
        finding["id"]
    ) == 64

    assert (
        finding["rule_id"]
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        finding["severity"]
        == "medium"
    )

    assert (
        finding["asset_type"]
        == "service"
    )

    assert (
        finding["asset_value"]
        == "example.com:80"
    )

    assert (
        finding["affected_service"]
        is None
    )

    assert (
        finding["plugin"]
        is None
    )


def test_findings_rejects_invalid_severity(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--severity",
            "impossible",
        ],
    )

    assert result.exit_code == 1
    assert "invalid severity" in result.output

def test_findings_show(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    finding_id = get_http_finding_id(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding_id[:12],
        ],
    )

    assert result.exit_code == 0
    assert "FINDING DETAIL" in result.output
    assert "HTTP_WITHOUT_TLS" in result.output
    assert finding_id[:12] in result.output


def test_findings_show_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    finding_id = get_http_finding_id(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding_id[:12],
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert (
        payload["id"]
        == finding_id
    )

    assert (
        payload["rule_id"]
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        payload["asset_value"]
        == "example.com:80"
    )


def test_findings_show_not_found(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            "deadbeef",
        ],
    )

    assert result.exit_code == 1
    assert "finding not found" in result.output
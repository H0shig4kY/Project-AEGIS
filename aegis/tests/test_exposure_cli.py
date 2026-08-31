import json
from pathlib import Path

from typer.testing import CliRunner

from aegis.assessment import AssessmentContext
from aegis.cli import app
from aegis.context import CampaignContext
from aegis.models import (
    Asset,
    AssetRelation,
    AssetRelationType,
    AssetType,
    ChangeRecord,
    ChangeType,
)

from datetime import (
    datetime,
    timedelta,
    timezone,
)

import aegis.cli_ui as cli_ui
import os


runner = CliRunner()


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


def test_exposure_empty_campaign(
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
            "exposure",
        ],
    )

    assert result.exit_code == 0
    assert "EXPOSURE" in result.output


def test_exposure_shows_service(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.assets.save(
        Asset(
            value="example.com:443",
            type=AssetType.SERVICE,
            source="service",
            active=True,
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "exposure",
        ],
    )

    assert result.exit_code == 0
    assert "SERVICES" in result.output
    assert "example.com:443" in result.output


def test_exposure_shows_tls_relation(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.relations.save(
        AssetRelation(
            source_type=AssetType.SERVICE,
            source_value="example.com:443",
            relation=(
                AssetRelationType.PRESENTS
            ),
            target_type=(
                AssetType.CERTIFICATE
            ),
            target_value="a" * 64,
            source="tls",
            active=True,
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "exposure",
        ],
    )

    assert result.exit_code == 0
    assert "TLS EXPOSURE" in result.output
    assert "example.com:443" in result.output


def test_exposure_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.assets.save(
        Asset(
            value="example.com:443",
            type=AssetType.SERVICE,
            source="service",
            active=True,
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "exposure",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert (
        payload[
            "assets"
        ][
            "service"
        ][
            "active"
        ]
        == 1
    )

    assert len(
        payload[
            "services"
        ]
    ) == 1

def test_exposure_shows_http_without_tls_finding(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

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

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "exposure",
        ],
    )

    assert result.exit_code == 0

    assert "FINDINGS" in result.output
    assert "HTTP_WITHOUT_TLS" in result.output
    assert "MEDIUM" in result.output
    assert "example.com:80" in result.output

def test_exposure_json_contains_findings(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

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

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "exposure",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(
        payload["findings"]
    ) == 1

    finding = payload[
        "findings"
    ][0]

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

def test_exposure_json_includes_affected_service(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    certificate_value = (
        "a" * 64
    )

    context.assets.save(
        Asset(
            value=certificate_value,
            type=AssetType.CERTIFICATE,
            source="tls",
            metadata={
                "valid_to": (
                    datetime.now(
                        timezone.utc
                    )
                    - timedelta(
                        days=1
                    )
                ).isoformat(),
            },
            active=True,
        )
    )

    context.relations.save(
        AssetRelation(
            source_type=(
                AssetType.SERVICE
            ),
            source_value=(
                "example.com:443"
            ),
            relation=(
                AssetRelationType.PRESENTS
            ),
            target_type=(
                AssetType.CERTIFICATE
            ),
            target_value=(
                certificate_value
            ),
            source="tls",
            active=True,
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "exposure",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    finding = next(
        item
        for item in payload[
            "findings"
        ]
        if (
            item["rule_id"]
            == "TLS_CERTIFICATE_EXPIRED"
        )
    )

    assert (
        finding[
            "affected_service"
        ]
        == "example.com:443"
    )

def test_exposure_shows_affected_service(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    certificate_value = (
        "b" * 64
    )

    context.assets.save(
        Asset(
            value=certificate_value,
            type=AssetType.CERTIFICATE,
            source="tls",
            metadata={
                "valid_to": (
                    datetime.now(
                        timezone.utc
                    )
                    - timedelta(
                        days=1
                    )
                ).isoformat(),
            },
            active=True,
        )
    )

    context.relations.save(
        AssetRelation(
            source_type=(
                AssetType.SERVICE
            ),
            source_value=(
                "example.com:443"
            ),
            relation=(
                AssetRelationType.PRESENTS
            ),
            target_type=(
                AssetType.CERTIFICATE
            ),
            target_value=(
                certificate_value
            ),
            source="tls",
            active=True,
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "exposure",
        ],
    )

    assert result.exit_code == 0

    assert (
        "TLS_CERTIFICATE_EXPIRED"
        in result.output
    )

    assert (
        "example.com:443"
        in result.output
    )

def test_terminal_is_compact(
    monkeypatch,
):
    monkeypatch.setattr(
        cli_ui.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size(
            (80, 30)
        ),
    )

    assert (
        cli_ui.terminal_is_compact()
        is True
    )


def test_terminal_is_not_compact(
    monkeypatch,
):
    monkeypatch.setattr(
        cli_ui.shutil,
        "get_terminal_size",
        lambda fallback: os.terminal_size(
            (160, 40)
        ),
    )

    assert (
        cli_ui.terminal_is_compact()
        is False
    )

def test_exposure_compact_layout(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

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

    monkeypatch.chdir(
        context.root
    )

    monkeypatch.setattr(
        cli_ui,
        "terminal_is_compact",
        lambda: True,
    )

    result = runner.invoke(
        app,
        [
            "exposure",
        ],
    )

    assert result.exit_code == 0
    assert "FINDINGS" in result.output
    assert "HTTP_WITHOUT_TLS" in result.output
    assert "Asset:" in result.output
    assert "Service:" in result.output

def test_exposure_wide_layout(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

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

    monkeypatch.chdir(
        context.root
    )

    monkeypatch.setattr(
        cli_ui,
        "terminal_is_compact",
        lambda: False,
    )

    result = runner.invoke(
        app,
        [
            "exposure",
        ],
    )

    assert result.exit_code == 0

    assert "FINDINGS" in result.output
    assert "Severity" in result.output
    assert "Rule" in result.output
    assert "HTTP_WITHOUT_TLS" in result.output
    assert "MEDIUM" in result.output

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )

    assert (
        "MEDIUM"
        in result.output
    )
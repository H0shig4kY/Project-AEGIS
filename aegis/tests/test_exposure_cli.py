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
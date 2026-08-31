import json
from pathlib import Path

from typer.testing import CliRunner

from aegis.assessment import AssessmentContext
from aegis.cli import app
from aegis.context import CampaignContext
from aegis.models import (
    Asset,
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


def test_status_empty_campaign(
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
            "status",
        ],
    )

    assert result.exit_code == 0

    assert "CAMPAIGN" in result.output
    assert "SCOPE" in result.output
    assert "EXPOSURE" in result.output

    assert (
        "INTEGRITY / VERIFICATION"
        in result.output
    )

    assert (
        "INTEGRITY / BASELINES"
        in result.output
    )


def test_status_shows_assets(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.assets.save(
        Asset(
            value="example.com",
            type=AssetType.DOMAIN,
            source="scope",
            active=True,
        )
    )

    context.assets.save(
        Asset(
            value="example.com:80",
            type=AssetType.SERVICE,
            source="service",
            active=False,
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "status",
        ],
    )

    assert result.exit_code == 0

    assert "Assets" in result.output
    assert "1" in result.output


def test_status_shows_recent_change(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.INACTIVE
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:80"
            ),
            plugin="service",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "status",
        ],
    )

    assert result.exit_code == 0
    assert "RECENT CHANGES" in result.output
    assert "INACTIVE" in result.output
    assert "service" in result.output


def test_status_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.assets.save(
        Asset(
            value="example.com",
            type=AssetType.DOMAIN,
            source="scope",
            active=True,
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "status",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert (
        payload["assets"]["total"]
        == 1
    )

    assert (
        payload["assets"]["active"]
        == 1
    )

    assert (
        payload["assets"]["inactive"]
        == 0
    )

    assert (
        payload["relations"]["total"]
        == 0
    )

    assert (
        payload["changes"]["total"]
        == 0
    )

    assert (
        payload[
            "integrity"
        ][
            "verification"
        ][
            "OK"
        ]
        == 0
    )

    assert (
        payload[
            "integrity"
        ][
            "baselines"
        ][
            "ORIGINAL"
        ]
        == 0
    )

    assert (
        payload[
            "integrity"
        ][
            "baselines"
        ][
            "RETROSPECTIVE"
        ]
        == 0
    )

def test_status_integrity_structure(
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
            "status",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    integrity = payload[
        "integrity"
    ]

    assert set(
        integrity[
            "verification"
        ]
    ) == {
        "OK",
        "FAILED",
        "UNKNOWN",
        "CONFLICT",
    }

    assert set(
        integrity[
            "baselines"
        ]
    ) == {
        "ORIGINAL",
        "RETROSPECTIVE",
    }
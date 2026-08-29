from pathlib import Path
import json

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
    campaign = tmp_path / "campaign"
    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    return AssessmentContext(
        CampaignContext(
            campaign
        )
    )


def test_assets_history_asset_not_found(
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
            "assets",
            "history",
            "service",
            "example.com:80",
        ],
    )

    assert result.exit_code == 1

    assert (
        "Error: asset not found"
        in result.output
    )


def test_assets_history_shows_lifecycle(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    asset = Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
        active=True,
    )

    context.assets.save(
        asset
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "assets",
            "history",
            "service",
            "example.com:80",
        ],
    )

    assert result.exit_code == 0

    assert (
        "Asset history"
        in result.output
    )

    assert (
        "Type: service"
        in result.output
    )

    assert (
        "Value: example.com:80"
        in result.output
    )

    assert (
        "Active: yes"
        in result.output
    )


def test_assets_history_shows_changes(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    asset = Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
    )

    context.assets.save(
        asset
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:80"
            ),
            plugin="service",
            target="example.com",
            current_result=(
                "service-2.json"
            ),
        )
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
            current_result=(
                "service-3.json"
            ),
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "assets",
            "history",
            "service",
            "example.com:80",
        ],
    )

    assert result.exit_code == 0

    assert (
        "CANDIDATE_MISSING"
        in result.output
    )

    assert (
        "INACTIVE"
        in result.output
    )

def test_assets_history_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    asset = Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
        active=True,
    )

    context.assets.save(asset)

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "assets",
            "history",
            "service",
            "example.com:80",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert (
        payload["asset"]["type"]
        == "service"
    )

    assert (
        payload["asset"]["value"]
        == "example.com:80"
    )

    assert (
        payload["asset"]["active"]
        is True
    )
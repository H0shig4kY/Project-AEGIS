from pathlib import Path
import json

from typer.testing import CliRunner

from aegis.assessment import (
    AssessmentContext,
)
from aegis.cli import app
from aegis.context import (
    CampaignContext,
)
from aegis.models import (
    AssetType,
    AssetRelationType,
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


def test_changes_list_empty(
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
            "changes",
            "list",
        ],
    )

    assert result.exit_code == 0

    assert (
        "No changes found."
        in result.output
    )


def test_changes_list(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.REACTIVATED,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            plugin="service",
            target="example.com",
            previous_result="service-previous.json",
            current_result="service-current.json",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
        ],
    )

    assert result.exit_code == 0
    assert "Lifecycle Changes" in result.output
    assert "REACTIVATED" in result.output
    assert "SERVICE" in result.output
    assert "Plugin" in result.output
    assert "service" in result.output


def test_changes_show(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    change = ChangeRecord(
        change_type=(
            ChangeType.REACTIVATED
        ),
        asset_type=(
            AssetType.SERVICE
        ),
        asset_value=(
            "example.com:80"
        ),
        plugin="service",
        target="example.com",
        previous_result=(
            "service-previous.json"
        ),
        current_result=(
            "service-current.json"
        ),
    )

    path = context.changes.save(
        change
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "show",
            path.name,
        ],
    )

    assert result.exit_code == 0

    assert (
        "Change"
        in result.output
    )

    assert (
        "Type: reactivated"
        in result.output
    )

    assert (
        "Asset type: service"
        in result.output
    )

    assert (
        "Asset: example.com:80"
        in result.output
    )

    assert (
        "Plugin: service"
        in result.output
    )

    assert (
        "Target: example.com"
        in result.output
    )

    assert (
        "Previous result: "
        "service-previous.json"
        in result.output
    )

    assert (
        "Current result: "
        "service-current.json"
        in result.output
    )


def test_changes_show_rejects_invalid_path(
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
            "changes",
            "show",
            "../aegis.yaml",
        ],
    )

    assert result.exit_code == 1

    assert (
        "Error: invalid change path."
        in result.output
    )

def test_changes_list_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.REACTIVATED
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
            "changes",
            "list",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1

    assert (
        payload[0]["change_type"]
        == "reactivated"
    )

    assert (
        payload[0]["asset_value"]
        == "example.com:80"
    )

def test_changes_list_filter_by_type(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            plugin="service",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.REACTIVATED,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:443",
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
            "changes",
            "list",
            "--type",
            "inactive",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1
    assert payload[0]["change_type"] == "inactive"
    assert payload[0]["asset_value"] == "example.com:80"


def test_changes_list_filter_by_asset_type(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            plugin="service",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.CONFIRMED,
            asset_type=AssetType.DOMAIN,
            asset_value="example.com",
            plugin="dns",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
            "--asset-type",
            "service",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1
    assert payload[0]["asset_type"] == "service"
    assert payload[0]["asset_value"] == "example.com:80"


def test_changes_list_filter_by_asset_value(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            plugin="service",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:443",
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
            "changes",
            "list",
            "--asset",
            "example.com:443",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1
    assert payload[0]["asset_value"] == "example.com:443"


def test_changes_list_filter_by_plugin(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            plugin="service",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.CONFIRMED,
            asset_type=AssetType.DOMAIN,
            asset_value="example.com",
            plugin="dns",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
            "--plugin",
            "service",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1
    assert payload[0]["plugin"] == "service"
    assert payload[0]["asset_value"] == "example.com:80"


def test_changes_list_rejects_invalid_change_type(
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
            "changes",
            "list",
            "--type",
            "invalid",
        ],
    )

    assert result.exit_code == 1

    assert (
        "Error: invalid change type"
        in result.output
    )


def test_changes_list_rejects_invalid_asset_type(
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
            "changes",
            "list",
            "--asset-type",
            "invalid",
        ],
    )

    assert result.exit_code == 1

    assert (
        "Error: invalid asset type"
        in result.output
    )

def test_changes_list_filters_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.REACTIVATED
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

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.INACTIVE
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:443"
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
            "changes",
            "list",
            "--type",
            "reactivated",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1

    assert (
        payload[0]["change_type"]
        == "reactivated"
    )

    assert (
        payload[0]["asset_value"]
        == "example.com:80"
    )

def test_changes_list_combined_filters_json(
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

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.REACTIVATED
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:443"
            ),
            plugin="service",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.INACTIVE
            ),
            asset_type=(
                AssetType.DOMAIN
            ),
            asset_value=(
                "example.com"
            ),
            plugin="dns",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
            "--type",
            "inactive",
            "--asset-type",
            "service",
            "--plugin",
            "service",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1

    item = payload[0]

    assert (
        item["change_type"]
        == "inactive"
    )

    assert (
        item["asset_type"]
        == "service"
    )

    assert (
        item["asset_value"]
        == "example.com:80"
    )

    assert (
        item["plugin"]
        == "service"
    )

def test_changes_list_shows_relation_change(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            relation_type=AssetRelationType.RESOLVES_TO,
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
        ],
    )

    assert result.exit_code == 0
    assert "Lifecycle Changes" in result.output
    assert "INACTIVE" in result.output
    assert "DOMAIN" in result.output
    assert "dns" in result.output


def test_changes_show_relation_change(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    path = context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "show",
            path.name,
        ],
    )

    assert result.exit_code == 0

    assert (
        "Kind: relation"
        in result.output
    )

    assert (
        "Relation: resolves_to"
        in result.output
    )

    assert (
        "Source: example.com"
        in result.output
    )

    assert (
        "Target asset: 192.0.2.10"
        in result.output
    )


def test_changes_list_relation_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.REACTIVATED
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1

    item = payload[0]

    assert item["kind"] == "relation"

    assert (
        item["change_type"]
        == "reactivated"
    )

    assert (
        item["relation_type"]
        == "resolves_to"
    )

    assert (
        item["source_type"]
        == "domain"
    )

    assert (
        item["source_value"]
        == "example.com"
    )

    assert (
        item["target_type"]
        == "ip"
    )

    assert (
        item["target_value"]
        == "192.0.2.10"
    )

def test_changes_list_filter_by_relation_type(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            relation_type=AssetRelationType.RESOLVES_TO,
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
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
            "changes",
            "list",
            "--relation-type",
            "resolves_to",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1

    item = payload[0]

    assert item["kind"] == "relation"
    assert item["relation_type"] == "resolves_to"
    assert item["target_value"] == "192.0.2.10"

def test_changes_list_filter_relation_source(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            relation_type=AssetRelationType.RESOLVES_TO,
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            relation_type=AssetRelationType.RESOLVES_TO,
            source_type=AssetType.DOMAIN,
            source_value="other.example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.20",
            plugin="dns",
            target="other.example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
            "--source",
            "example.com",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1

    item = payload[0]

    assert item["source_value"] == "example.com"
    assert item["target_value"] == "192.0.2.10"

def test_changes_list_filter_relation_target(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            relation_type=AssetRelationType.RESOLVES_TO,
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=ChangeType.INACTIVE,
            relation_type=AssetRelationType.RESOLVES_TO,
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.20",
            plugin="dns",
            target="example.com",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "changes",
            "list",
            "--target-value",
            "192.0.2.10",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(payload) == 1

    item = payload[0]

    assert item["source_value"] == "example.com"
    assert item["target_value"] == "192.0.2.10"

def test_changes_list_rejects_invalid_relation_type(
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
            "changes",
            "list",
            "--relation-type",
            "invalid",
        ],
    )

    assert result.exit_code == 1

    assert (
        "Error: invalid relation type"
        in result.output
    )
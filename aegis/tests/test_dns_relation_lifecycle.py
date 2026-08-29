from pathlib import Path

from typer.testing import CliRunner

from aegis.assessment import AssessmentContext
from aegis.cli import app
from aegis.context import CampaignContext
from aegis.models import (
    AssetRelationType,
    AssetType,
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


def reopen_context(
    campaign_dir: Path,
) -> AssessmentContext:
    return AssessmentContext(
        CampaignContext(
            campaign_dir
        )
    )


def get_dns_relation(
    context: AssessmentContext,
):
    relations = context.relations.find()

    return next(
        relation
        for relation in relations
        if (
            relation.source_type
            == AssetType.DOMAIN
            and relation.source_value
            == "example.com"
            and relation.relation
            == AssetRelationType.RESOLVES_TO
            and relation.target_type
            == AssetType.IP
            and relation.target_value
            == "192.0.2.10"
        )
    )


def test_dns_relation_lifecycle(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    campaign_dir = context.root

    context.scope.add(
        "example.com"
    )

    context.scope.add(
        "192.0.2.10"
    )

    states = [
        ["192.0.2.10"],
        [],
        [],
        ["192.0.2.10"],
    ]

    call_index = {
        "value": 0,
    }

    def fake_resolve_domain(
        domain,
    ):
        return states[
            call_index["value"]
        ]

    monkeypatch.setattr(
        "aegis.plugins.builtin.dns.plugin.resolve_domain",
        fake_resolve_domain,
    )

    monkeypatch.chdir(
        campaign_dir
    )

    # -------------------------------------------------
    # RUN #1
    # Relação DNS existe.
    # -------------------------------------------------

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "dns",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation = get_dns_relation(
        context
    )

    assert relation.active is True

    # -------------------------------------------------
    # RUN #2
    # Primeira ausência.
    # -------------------------------------------------

    call_index["value"] = 1

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "dns",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation = get_dns_relation(
        context
    )

    assert relation.active is True

    candidate_missing = (
        context.changes.find(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.IP
            ),
            target_value=(
                "192.0.2.10"
            ),
        )
    )

    assert len(
        candidate_missing
    ) == 1

    # -------------------------------------------------
    # RUN #3
    # Segunda ausência consecutiva.
    # -------------------------------------------------

    call_index["value"] = 2

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "dns",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation = get_dns_relation(
        context
    )

    assert relation.active is False

    candidate_missing = (
        context.changes.find(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.IP
            ),
            target_value=(
                "192.0.2.10"
            ),
        )
    )

    assert len(
        candidate_missing
    ) == 2

    inactive_changes = (
        context.changes.find(
            change_type=(
                ChangeType.INACTIVE
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.IP
            ),
            target_value=(
                "192.0.2.10"
            ),
        )
    )

    assert len(
        inactive_changes
    ) == 1

    # O IP em si não deve ficar inativo.
    ip_assets = context.assets.find(
        asset_type=AssetType.IP,
    )

    ip_asset = next(
        asset
        for asset in ip_assets
        if asset.value == "192.0.2.10"
    )

    assert ip_asset.active is True

    # -------------------------------------------------
    # RUN #4
    # Relação DNS reaparece.
    # -------------------------------------------------

    call_index["value"] = 3

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "dns",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation = get_dns_relation(
        context
    )

    assert relation.active is True

    reactivated_changes = (
        context.changes.find(
            change_type=(
                ChangeType.REACTIVATED
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.IP
            ),
            target_value=(
                "192.0.2.10"
            ),
        )
    )

    assert len(
        reactivated_changes
    ) == 1

    reactivated = (
        reactivated_changes[0]
    )

    assert (
        reactivated.plugin
        == "dns"
    )

    assert (
        reactivated.target
        == "example.com"
    )

    assert (
        reactivated.current_result
        is not None
    )

    # O histórico INACTIVE deve continuar
    # presente depois da reativação.
    inactive_changes = (
        context.changes.find(
            change_type=(
                ChangeType.INACTIVE
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.IP
            ),
            target_value=(
                "192.0.2.10"
            ),
        )
    )

    assert len(
        inactive_changes
    ) == 1
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


def get_exposes_relation(
    context: AssessmentContext,
):
    return next(
        relation
        for relation
        in context.relations.find()
        if (
            relation.source_type
            == AssetType.DOMAIN
            and relation.source_value
            == "example.com"
            and relation.relation
            == AssetRelationType.EXPOSES
            and relation.target_type
            == AssetType.SERVICE
            and relation.target_value
            == "example.com:80"
        )
    )


def get_service_asset(
    context: AssessmentContext,
):
    return next(
        asset
        for asset
        in context.assets.find(
            asset_type=AssetType.SERVICE,
        )
        if asset.value == "example.com:80"
    )


def test_exposes_relation_lifecycle(
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

    states = [
        {80},
        set(),
        set(),
        {80},
    ]

    call_index = {
        "value": 0,
    }

    def fake_check_tcp_port(
        host,
        port,
        timeout=1.0,
    ):
        return (
            port
            in states[
                call_index["value"]
            ]
        )

    monkeypatch.setattr(
        (
            "aegis.plugins.builtin."
            "service.plugin.check_tcp_port"
        ),
        fake_check_tcp_port,
    )

    monkeypatch.setattr(
        (
            "aegis.plugins.builtin."
            "service.plugin.grab_banner"
        ),
        lambda host, port: None,
    )

    monkeypatch.chdir(
        campaign_dir
    )

    # ---------------------------------------------
    # RUN #1
    # Porta 80 aberta.
    # SERVICE e EXPOSES devem nascer ativos.
    # ---------------------------------------------

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "service",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    service = get_service_asset(
        context
    )

    relation = get_exposes_relation(
        context
    )

    assert service.active is True
    assert relation.active is True

    # ---------------------------------------------
    # RUN #2
    # Primeira ausência.
    # ---------------------------------------------

    call_index["value"] = 1

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "service",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    service = get_service_asset(
        context
    )

    relation = get_exposes_relation(
        context
    )

    # Ambos continuam ativos após
    # apenas uma ausência.
    assert service.active is True
    assert relation.active is True

    asset_missing = (
        context.changes.find(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        asset_missing
    ) == 1

    relation_missing = (
        context.changes.find(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            relation_type=(
                AssetRelationType.EXPOSES
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.SERVICE
            ),
            target_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        relation_missing
    ) == 1

    # ---------------------------------------------
    # RUN #3
    # Segunda ausência.
    # SERVICE e EXPOSES devem ficar inactive.
    # ---------------------------------------------

    call_index["value"] = 2

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "service",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    service = get_service_asset(
        context
    )

    relation = get_exposes_relation(
        context
    )

    assert service.active is False
    assert relation.active is False

    asset_missing = (
        context.changes.find(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        asset_missing
    ) == 2

    relation_missing = (
        context.changes.find(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            relation_type=(
                AssetRelationType.EXPOSES
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.SERVICE
            ),
            target_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        relation_missing
    ) == 2

    asset_inactive = (
        context.changes.find(
            change_type=(
                ChangeType.INACTIVE
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        asset_inactive
    ) == 1

    relation_inactive = (
        context.changes.find(
            change_type=(
                ChangeType.INACTIVE
            ),
            relation_type=(
                AssetRelationType.EXPOSES
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.SERVICE
            ),
            target_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        relation_inactive
    ) == 1

    # ---------------------------------------------
    # RUN #4
    # Porta 80 reaparece.
    # SERVICE e EXPOSES devem reativar.
    # ---------------------------------------------

    call_index["value"] = 3

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "service",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    service = get_service_asset(
        context
    )

    relation = get_exposes_relation(
        context
    )

    assert service.active is True
    assert relation.active is True

    asset_reactivated = (
        context.changes.find(
            change_type=(
                ChangeType.REACTIVATED
            ),
            asset_type=(
                AssetType.SERVICE
            ),
            asset_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        asset_reactivated
    ) == 1

    relation_reactivated = (
        context.changes.find(
            change_type=(
                ChangeType.REACTIVATED
            ),
            relation_type=(
                AssetRelationType.EXPOSES
            ),
            source_type=(
                AssetType.DOMAIN
            ),
            source_value=(
                "example.com"
            ),
            target_type=(
                AssetType.SERVICE
            ),
            target_value=(
                "example.com:80"
            ),
        )
    )

    assert len(
        relation_reactivated
    ) == 1

    reactivated = (
        relation_reactivated[0]
    )

    assert (
        reactivated.plugin
        == "service"
    )

    assert (
        reactivated.target
        == "example.com"
    )

    assert (
        reactivated.current_result
        is not None
    )
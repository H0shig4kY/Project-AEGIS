from pathlib import Path

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


def get_service(
    context: AssessmentContext,
    value: str,
):
    services = context.assets.find(
        asset_type=AssetType.SERVICE,
    )

    return next(
        asset
        for asset in services
        if asset.value == value
    )


def reopen_context(
    campaign_dir: Path,
) -> AssessmentContext:
    return AssessmentContext(
        CampaignContext(
            campaign_dir
        )
    )


def test_plugin_run_service_lifecycle(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    campaign_dir = (
        context.root
    )

    context.scope.add(
        "example.com"
    )

    # Four executions:
    #
    # #1 service exists
    # #2 first absence
    # #3 second absence -> inactive
    # #4 service returns -> reactivated
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
        current = states[
            call_index["value"]
        ]

        return (
            port in current
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

    # -------------------------------------------------
    # RUN #1
    # Service exists.
    # -------------------------------------------------

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

    service_80 = get_service(
        context,
        "example.com:80",
    )

    assert service_80.active is True

    candidate_missing = (
        context.changes.find(
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
        )
    )

    assert (
        candidate_missing
        == []
    )

    # -------------------------------------------------
    # RUN #2
    # First absence.
    # -------------------------------------------------

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

    service_80 = get_service(
        context,
        "example.com:80",
    )

    # One absence is not enough.
    assert service_80.active is True

    candidate_missing = (
        context.changes.find(
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
        )
    )

    assert len(
        candidate_missing
    ) == 1

    inactive_changes = (
        context.changes.find(
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            change_type=(
                ChangeType.INACTIVE
            ),
        )
    )

    assert (
        inactive_changes
        == []
    )

    # -------------------------------------------------
    # RUN #3
    # Second consecutive absence.
    # -------------------------------------------------

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

    service_80 = get_service(
        context,
        "example.com:80",
    )

    # Threshold reached.
    assert service_80.active is False

    candidate_missing = (
        context.changes.find(
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
        )
    )

    assert len(
        candidate_missing
    ) == 2

    inactive_changes = (
        context.changes.find(
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            change_type=(
                ChangeType.INACTIVE
            ),
        )
    )

    assert len(
        inactive_changes
    ) == 1

    inactive_change = (
        inactive_changes[0]
    )

    assert (
        inactive_change.asset_value
        == "example.com:80"
    )

    assert (
        inactive_change.current_result
        is not None
    )

    # Remember the last positive confirmation
    # before reactivation.
    old_last_confirmed = (
        service_80.last_confirmed
    )

    assert (
        old_last_confirmed
        is not None
    )

    # -------------------------------------------------
    # RUN #4
    # Service returns.
    # -------------------------------------------------

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

    service_80 = get_service(
        context,
        "example.com:80",
    )

    # AssetStore.save() positively confirms
    # and reactivates the asset.
    assert service_80.active is True

    assert (
        service_80.last_confirmed
        is not None
    )

    assert (
        service_80.last_confirmed
        > old_last_confirmed
    )

    # Historical REACTIVATED event must also
    # have been persisted.
    reactivated_changes = (
        context.changes.find(
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            change_type=(
                ChangeType.REACTIVATED
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
        reactivated.change_type
        == ChangeType.REACTIVATED
    )

    assert (
        reactivated.asset_type
        == AssetType.SERVICE
    )

    assert (
        reactivated.asset_value
        == "example.com:80"
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

    # The historical inactive record must
    # remain present after reactivation.
    inactive_changes = (
        context.changes.find(
            asset_type=AssetType.SERVICE,
            asset_value="example.com:80",
            change_type=(
                ChangeType.INACTIVE
            ),
        )
    )

    assert len(
        inactive_changes
    ) == 1
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
    FindingEventType,
    FindingState,
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

def test_plugin_run_service_persists_finding_lifecycle_history(
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

    # Four real CLI executions:
    #
    # #1 HTTP service exists
    # #2 first absence
    # #3 second absence -> resolved
    # #4 HTTP service returns
    states = [
        {80},  # #1 present
        set(), # #2 first asset absence
        set(), # #3 asset inactive / first finding absence
        set(), # #4 second finding absence -> resolved
        {80},  # #5 reappears -> active
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
    # Finding is created.
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

    findings = [
        finding
        for finding
        in context.findings.find()
        if (
            finding.rule_id
            == "HTTP_WITHOUT_TLS"
            and finding.asset_type
            == AssetType.SERVICE
            and finding.asset_value
            == "example.com:80"
        )
    ]

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding.state
        == FindingState.ACTIVE
    )

    assert finding.active is True

    events = (
        context.finding_history
        .find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 1

    assert (
        events[0].event_type
        == FindingEventType.CREATED
    )

    assert (
        events[0].from_state
        is None
    )

    assert (
        events[0].to_state
        == FindingState.ACTIVE
    )

    assert (
        events[0].plugin
        == "service"
    )

    # -------------------------------------------------
    # RUN #2
    # ACTIVE -> CANDIDATE_MISSING
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

    finding = (
        context.findings.get(
            finding.finding_id
        )
    )

    assert finding is not None

    # The first missing service observation does not
    # immediately remove the asset from the exposure
    # surface. The asset lifecycle is itself debounced.
    #
    # Therefore the finding is still confirmed as ACTIVE
    # during this execution.
    assert (
        finding.state
        == FindingState.ACTIVE
    )

    assert finding.active is True

    events = (
        context.finding_history
        .find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 1

    assert (
        events[0].event_type
        == FindingEventType.CREATED
    )

    assert (
        events[0].from_state
        is None
    )

    assert (
        events[0].to_state
        == FindingState.ACTIVE
    )

    assert (
        events[0].plugin
        == "service"
    )

    # -------------------------------------------------
    # RUN #3
    # CANDIDATE_MISSING -> RESOLVED
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

    finding = (
        context.findings.get(
            finding.finding_id
        )
    )

    assert finding is not None

    assert (
        finding.state
        == FindingState.CANDIDATE_MISSING
    )

    assert finding.active is True

    events = (
        context.finding_history
        .find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 2

    assert (
        events[1].event_type
        == FindingEventType.STATE_CHANGED
    )

    assert (
        events[1].from_state
        == FindingState.ACTIVE
    )

    assert (
        events[1].to_state
        == FindingState.CANDIDATE_MISSING
    )

    assert (
        events[1].plugin
        == "service"
    )

    # -------------------------------------------------
    # RUN #4
    # Second finding-level absence.
    # CANDIDATE_MISSING -> RESOLVED
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

    finding = (
        context.findings.get(
            finding.finding_id
        )
    )

    assert finding is not None

    assert (
        finding.state
        == FindingState.RESOLVED
    )

    assert finding.active is False

    events = (
        context.finding_history
        .find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 3

    assert (
        events[2].event_type
        == FindingEventType.STATE_CHANGED
    )

    assert (
        events[2].from_state
        == FindingState.CANDIDATE_MISSING
    )

    assert (
        events[2].to_state
        == FindingState.RESOLVED
    )

    # -------------------------------------------------
    # RUN #5
    # Service returns.
    # RESOLVED -> ACTIVE
    # -------------------------------------------------

    call_index["value"] = 4

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

    finding = (
        context.findings.get(
            finding.finding_id
        )
    )

    assert finding is not None

    assert (
        finding.state
        == FindingState.ACTIVE
    )

    assert finding.active is True

    events = (
        context.finding_history
        .find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 4

    # -------------------------------------------------
    # COMPLETE PERSISTED HISTORY
    # -------------------------------------------------

    transitions = [
        (
            event.event_type,
            event.from_state,
            event.to_state,
        )
        for event in events
    ]

    assert transitions == [
        (
            FindingEventType.CREATED,
            None,
            FindingState.ACTIVE,
        ),
        (
            FindingEventType.STATE_CHANGED,
            FindingState.ACTIVE,
            FindingState.CANDIDATE_MISSING,
        ),
        (
            FindingEventType.STATE_CHANGED,
            FindingState.CANDIDATE_MISSING,
            FindingState.RESOLVED,
        ),
        (
            FindingEventType.STATE_CHANGED,
            FindingState.RESOLVED,
            FindingState.ACTIVE,
        ),
    ]

    assert all(
        event.plugin == "service"
        for event in events
    )

    assert all(
        event.rule_id
        == "HTTP_WITHOUT_TLS"
        for event in events
    )

    assert all(
        event.asset_type
        == AssetType.SERVICE
        for event in events
    )

    assert all(
        event.asset_value
        == "example.com:80"
        for event in events
    )

    # Finding history must be chronological.
    timestamps = [
        event.detected_at
        for event in events
    ]

    assert timestamps == sorted(
        timestamps
    )
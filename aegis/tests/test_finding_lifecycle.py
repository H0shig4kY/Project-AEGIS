from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.exposure import (
    ExposureFinding,
    ExposureSeverity,
)
from aegis.finding_history_store import (
    FindingHistoryStore,
)
from aegis.finding_lifecycle import (
    FindingLifecycleManager,
)
from aegis.finding_store import (
    FindingStore,
)
from aegis.models import (
    AssetType,
    FindingEventType,
    FindingState,
)

def create_finding():
    return ExposureFinding(
        rule_id="HTTP_WITHOUT_TLS",
        severity=ExposureSeverity.MEDIUM,
        title=(
            "HTTP service exposed "
            "without TLS"
        ),
        description=(
            "Test finding."
        ),
        asset_type=(
            AssetType.SERVICE
        ),
        asset_value=(
            "example.com:80"
        ),
        coverage_plugins=(
            "service",
            "http",
        ),
    )


def test_new_finding_becomes_active(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    now = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    manager.process(
        [finding],
        observed_at=now,
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.ACTIVE
    )

    assert record.active is True
    assert record.seen_count == 1
    assert record.missing_count == 0
    assert record.first_seen == now
    assert record.last_seen == now
    assert record.last_confirmed == now


def test_existing_finding_stays_active(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    manager.process(
        [finding],
        observed_at=first,
    )

    manager.process(
        [finding],
        observed_at=second,
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.ACTIVE
    )

    assert record.active is True
    assert record.seen_count == 2
    assert record.missing_count == 0
    assert record.first_seen == first
    assert record.last_seen == second
    assert record.last_confirmed == second


def test_first_missing_marks_candidate_missing(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    manager.process(
        [finding],
        observed_at=first,
    )

    manager.process(
        [],
        observed_at=second,
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.CANDIDATE_MISSING
    )

    assert record.active is True
    assert record.missing_count == 1
    assert record.last_confirmed == first


def test_second_missing_resolves_finding(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    third = (
        first
        + timedelta(
            hours=2
        )
    )

    manager.process(
        [finding],
        observed_at=first,
    )

    manager.process(
        [],
        observed_at=second,
    )

    manager.process(
        [],
        observed_at=third,
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.RESOLVED
    )

    assert record.active is False
    assert record.missing_count == 2


def test_candidate_missing_reappears_active(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    third = (
        first
        + timedelta(
            hours=2
        )
    )

    manager.process(
        [finding],
        observed_at=first,
    )

    manager.process(
        [],
        observed_at=second,
    )

    manager.process(
        [finding],
        observed_at=third,
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.ACTIVE
    )

    assert record.active is True
    assert record.missing_count == 0
    assert record.seen_count == 2
    assert record.last_seen == third
    assert record.last_confirmed == third


def test_resolved_finding_reactivates(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    third = (
        first
        + timedelta(
            hours=2
        )
    )

    fourth = (
        first
        + timedelta(
            hours=3
        )
    )

    manager.process(
        [finding],
        observed_at=first,
    )

    manager.process(
        [],
        observed_at=second,
    )

    manager.process(
        [],
        observed_at=third,
    )

    manager.process(
        [finding],
        observed_at=fourth,
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.ACTIVE
    )

    assert record.active is True
    assert record.missing_count == 0
    assert record.seen_count == 2
    assert record.first_seen == first
    assert record.last_seen == fourth
    assert record.last_confirmed == fourth

def test_unrelated_plugin_does_not_mark_missing(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    manager.process(
        [],
        observed_at=second,
        observed_plugin="dns",
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.ACTIVE
    )

    assert record.active is True
    assert record.missing_count == 0
    assert record.last_confirmed == first

def test_related_plugin_marks_missing(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    manager.process(
        [],
        observed_at=second,
        observed_plugin="service",
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.CANDIDATE_MISSING
    )

    assert record.active is True
    assert record.missing_count == 1

def test_unrelated_plugin_does_not_confirm_present_finding(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert record.seen_count == 1
    assert record.last_seen == first
    assert record.last_confirmed == first

    # Analyzer still sees the global HTTP finding,
    # but DNS is not authoritative for this rule.
    manager.process(
        [finding],
        observed_at=second,
        observed_plugin="dns",
    )

    record = store.get(
        finding.finding_id
    )

    assert record is not None

    assert record.seen_count == 1
    assert record.last_seen == first
    assert record.last_confirmed == first
    assert record.missing_count == 0

    assert (
        record.state
        == FindingState.ACTIVE
    )

def test_unrelated_plugin_does_not_create_finding(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    manager = FindingLifecycleManager(
        store
    )

    finding = create_finding()

    now = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    manager.process(
        [finding],
        observed_at=now,
        observed_plugin="dns",
    )

    assert (
        store.get(
            finding.finding_id
        )
        is None
    )

    assert (
        store.find()
        == []
    )

def test_new_finding_emits_created_event(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    history_store = (
        FindingHistoryStore(
            tmp_path
            / "finding_history"
        )
    )

    manager = FindingLifecycleManager(
        store,
        history_store,
    )

    finding = create_finding()

    now = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    manager.process(
        [finding],
        observed_at=now,
        observed_plugin="service",
    )

    events = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 1

    event = events[0]

    assert (
        event.finding_id
        == finding.finding_id
    )

    assert (
        event.event_type
        == FindingEventType.CREATED
    )

    assert (
        event.from_state
        is None
    )

    assert (
        event.to_state
        == FindingState.ACTIVE
    )

    assert (
        event.detected_at
        == now
    )

    assert (
        event.plugin
        == "service"
    )

    assert (
        event.rule_id
        == finding.rule_id
    )

    assert (
        event.asset_type
        == finding.asset_type
    )

    assert (
        event.asset_value
        == finding.asset_value
    )

def test_active_to_candidate_missing_emits_state_changed_event(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    history_store = (
        FindingHistoryStore(
            tmp_path
            / "finding_history"
        )
    )

    manager = FindingLifecycleManager(
        store,
        history_store,
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    manager.process(
        [],
        observed_at=second,
        observed_plugin="service",
    )

    events = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 2

    assert (
        events[0].event_type
        == FindingEventType.CREATED
    )

    event = events[1]

    assert (
        event.event_type
        == FindingEventType.STATE_CHANGED
    )

    assert (
        event.from_state
        == FindingState.ACTIVE
    )

    assert (
        event.to_state
        == FindingState.CANDIDATE_MISSING
    )

    assert (
        event.detected_at
        == second
    )

    assert (
        event.plugin
        == "service"
    )

    assert (
        event.finding_id
        == finding.finding_id
    )

    assert (
        event.rule_id
        == finding.rule_id
    )

    assert (
        event.asset_type
        == finding.asset_type
    )

    assert (
        event.asset_value
        == finding.asset_value
    )

def test_candidate_missing_to_resolved_emits_state_changed_event(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    history_store = (
        FindingHistoryStore(
            tmp_path
            / "finding_history"
        )
    )

    manager = FindingLifecycleManager(
        store,
        history_store,
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    third = (
        first
        + timedelta(
            hours=2
        )
    )

    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    manager.process(
        [],
        observed_at=second,
        observed_plugin="service",
    )

    manager.process(
        [],
        observed_at=third,
        observed_plugin="service",
    )

    events = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 3

    assert (
        events[0].event_type
        == FindingEventType.CREATED
    )

    assert (
        events[1].event_type
        == FindingEventType.STATE_CHANGED
    )

    event = events[2]

    assert (
        event.event_type
        == FindingEventType.STATE_CHANGED
    )

    assert (
        event.from_state
        == FindingState.CANDIDATE_MISSING
    )

    assert (
        event.to_state
        == FindingState.RESOLVED
    )

    assert (
        event.detected_at
        == third
    )

    assert (
        event.plugin
        == "service"
    )

    assert (
        event.finding_id
        == finding.finding_id
    )

    assert (
        event.rule_id
        == finding.rule_id
    )

    assert (
        event.asset_type
        == finding.asset_type
    )

    assert (
        event.asset_value
        == finding.asset_value
    )

def test_candidate_missing_to_active_emits_state_changed_event(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    history_store = (
        FindingHistoryStore(
            tmp_path
            / "finding_history"
        )
    )

    manager = FindingLifecycleManager(
        store,
        history_store,
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    third = (
        first
        + timedelta(
            hours=2
        )
    )

    # None -> ACTIVE
    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    # ACTIVE -> CANDIDATE_MISSING
    manager.process(
        [],
        observed_at=second,
        observed_plugin="service",
    )

    # CANDIDATE_MISSING -> ACTIVE
    manager.process(
        [finding],
        observed_at=third,
        observed_plugin="service",
    )

    events = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 3

    assert (
        events[0].event_type
        == FindingEventType.CREATED
    )

    assert (
        events[1].from_state
        == FindingState.ACTIVE
    )

    assert (
        events[1].to_state
        == FindingState.CANDIDATE_MISSING
    )

    event = events[2]

    assert (
        event.event_type
        == FindingEventType.STATE_CHANGED
    )

    assert (
        event.from_state
        == FindingState.CANDIDATE_MISSING
    )

    assert (
        event.to_state
        == FindingState.ACTIVE
    )

    assert (
        event.detected_at
        == third
    )

    assert (
        event.plugin
        == "service"
    )

    assert (
        event.finding_id
        == finding.finding_id
    )

    assert (
        event.rule_id
        == finding.rule_id
    )

    assert (
        event.asset_type
        == finding.asset_type
    )

    assert (
        event.asset_value
        == finding.asset_value
    )

def test_resolved_to_active_emits_state_changed_event(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    history_store = (
        FindingHistoryStore(
            tmp_path
            / "finding_history"
        )
    )

    manager = FindingLifecycleManager(
        store,
        history_store,
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    third = (
        first
        + timedelta(
            hours=2
        )
    )

    fourth = (
        first
        + timedelta(
            hours=3
        )
    )

    # None -> ACTIVE
    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    # ACTIVE -> CANDIDATE_MISSING
    manager.process(
        [],
        observed_at=second,
        observed_plugin="service",
    )

    # CANDIDATE_MISSING -> RESOLVED
    manager.process(
        [],
        observed_at=third,
        observed_plugin="service",
    )

    # RESOLVED -> ACTIVE
    manager.process(
        [finding],
        observed_at=fourth,
        observed_plugin="service",
    )

    events = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 4

    assert (
        events[0].event_type
        == FindingEventType.CREATED
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
        events[2].from_state
        == FindingState.CANDIDATE_MISSING
    )

    assert (
        events[2].to_state
        == FindingState.RESOLVED
    )

    event = events[3]

    assert (
        event.event_type
        == FindingEventType.STATE_CHANGED
    )

    assert (
        event.from_state
        == FindingState.RESOLVED
    )

    assert (
        event.to_state
        == FindingState.ACTIVE
    )

    assert (
        event.detected_at
        == fourth
    )

    assert (
        event.plugin
        == "service"
    )

    assert (
        event.finding_id
        == finding.finding_id
    )

    assert (
        event.rule_id
        == finding.rule_id
    )

    assert (
        event.asset_type
        == finding.asset_type
    )

    assert (
        event.asset_value
        == finding.asset_value
    )

def test_active_to_active_does_not_emit_state_changed_event(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    history_store = (
        FindingHistoryStore(
            tmp_path
            / "finding_history"
        )
    )

    manager = FindingLifecycleManager(
        store,
        history_store,
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    # None -> ACTIVE
    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    # ACTIVE -> ACTIVE
    manager.process(
        [finding],
        observed_at=second,
        observed_plugin="service",
    )

    events = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        == FindingEventType.CREATED
    )

    assert event.from_state is None

    assert (
        event.to_state
        == FindingState.ACTIVE
    )

    assert (
        event.detected_at
        == first
    )

def test_unrelated_plugin_does_not_emit_history_event(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    history_store = (
        FindingHistoryStore(
            tmp_path
            / "finding_history"
        )
    )

    manager = FindingLifecycleManager(
        store,
        history_store,
    )

    finding = create_finding()

    first = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    second = (
        first
        + timedelta(
            hours=1
        )
    )

    # Relevant plugin creates the finding.
    manager.process(
        [finding],
        observed_at=first,
        observed_plugin="service",
    )

    events_before = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events_before) == 1

    # DNS is unrelated to this finding's
    # coverage_plugins.
    manager.process(
        [],
        observed_at=second,
        observed_plugin="dns",
    )

    events_after = (
        history_store.find_by_finding_id(
            finding.finding_id
        )
    )

    assert len(events_after) == 1

    event = events_after[0]

    assert (
        event.event_type
        == FindingEventType.CREATED
    )

    assert event.from_state is None

    assert (
        event.to_state
        == FindingState.ACTIVE
    )

    assert (
        event.detected_at
        == first
    )

    assert (
        event.plugin
        == "service"
    )
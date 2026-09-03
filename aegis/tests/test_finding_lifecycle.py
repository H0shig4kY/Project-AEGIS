from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.exposure import (
    ExposureFinding,
    ExposureSeverity,
)
from aegis.finding_lifecycle import (
    FindingLifecycleManager,
)
from aegis.finding_store import (
    FindingStore,
)
from aegis.models import (
    AssetType,
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
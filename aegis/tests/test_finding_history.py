from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.models import (
    AssetType,
    FindingEvent,
    FindingEventType,
    FindingState,
)

from aegis.finding_history_store import (
    FindingHistoryStore,
)


def test_finding_event_model():
    detected_at = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    event = FindingEvent(
        event_id="a" * 64,
        finding_id="b" * 64,
        event_type=(
            FindingEventType.CREATED
        ),
        from_state=None,
        to_state=(
            FindingState.ACTIVE
        ),
        detected_at=(
            detected_at
        ),
        plugin="service",
        rule_id="HTTP_WITHOUT_TLS",
        asset_type=(
            AssetType.SERVICE
        ),
        asset_value=(
            "example.com:80"
        ),
    )

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
        event.finding_id
        == "b" * 64
    )

    assert (
        event.detected_at
        == detected_at
    )

def test_finding_history_store_saves_event(
    tmp_path,
):
    store = FindingHistoryStore(
        tmp_path
    )

    detected_at = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    event = FindingEvent(
        event_id="a" * 64,
        finding_id="b" * 64,
        event_type=(
            FindingEventType.CREATED
        ),
        from_state=None,
        to_state=(
            FindingState.ACTIVE
        ),
        detected_at=detected_at,
        plugin="service",
        rule_id="HTTP_WITHOUT_TLS",
        asset_type=(
            AssetType.SERVICE
        ),
        asset_value="example.com:80",
    )

    path = store.save(
        event
    )

    assert path.exists()

    loaded = store.get(
        event.event_id
    )

    assert loaded is not None

    assert (
        loaded.event_id
        == event.event_id
    )

    assert (
        loaded.finding_id
        == event.finding_id
    )

    assert (
        loaded.event_type
        == FindingEventType.CREATED
    )

    assert (
        loaded.from_state
        is None
    )

    assert (
        loaded.to_state
        == FindingState.ACTIVE
    )

    assert (
        loaded.detected_at
        == detected_at
    )

    assert (
        loaded.plugin
        == "service"
    )

    assert (
        loaded.asset_type
        == AssetType.SERVICE
    )

    assert (
        loaded.asset_value
        == "example.com:80"
    )


def test_finding_history_store_filters_by_finding(
    tmp_path,
):
    store = FindingHistoryStore(
        tmp_path
    )

    now = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    first = FindingEvent(
        event_id="a" * 64,
        finding_id="1" * 64,
        event_type=(
            FindingEventType.CREATED
        ),
        from_state=None,
        to_state=(
            FindingState.ACTIVE
        ),
        detected_at=now,
    )

    second = FindingEvent(
        event_id="b" * 64,
        finding_id="2" * 64,
        event_type=(
            FindingEventType.CREATED
        ),
        from_state=None,
        to_state=(
            FindingState.ACTIVE
        ),
        detected_at=now,
    )

    store.save(
        first
    )

    store.save(
        second
    )

    events = (
        store.find_by_finding_id(
            "1" * 64
        )
    )

    assert len(events) == 1

    assert (
        events[0].event_id
        == "a" * 64
    )


def test_finding_history_is_chronological(
    tmp_path,
):
    store = FindingHistoryStore(
        tmp_path
    )

    first_time = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    second_time = (
        first_time
        + timedelta(
            hours=1
        )
    )

    later = FindingEvent(
        event_id="b" * 64,
        finding_id="1" * 64,
        event_type=(
            FindingEventType.STATE_CHANGED
        ),
        from_state=(
            FindingState.ACTIVE
        ),
        to_state=(
            FindingState.CANDIDATE_MISSING
        ),
        detected_at=second_time,
    )

    earlier = FindingEvent(
        event_id="a" * 64,
        finding_id="1" * 64,
        event_type=(
            FindingEventType.CREATED
        ),
        from_state=None,
        to_state=(
            FindingState.ACTIVE
        ),
        detected_at=first_time,
    )

    # Deliberately save out of order.
    store.save(
        later
    )

    store.save(
        earlier
    )

    events = (
        store.find_by_finding_id(
            "1" * 64
        )
    )

    assert len(events) == 2

    assert (
        events[0].event_type
        == FindingEventType.CREATED
    )

    assert (
        events[1].event_type
        == FindingEventType.STATE_CHANGED
    )

    assert (
        events[0].detected_at
        < events[1].detected_at
    )
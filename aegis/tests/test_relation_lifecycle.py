from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.change_store import ChangeStore
from aegis.models import (
    AssetRelation,
    AssetRelationType,
    AssetType,
    ChangeRecord,
    ChangeType,
)
from aegis.relation_lifecycle import (
    RelationLifecycleManager,
)
from aegis.relation_store import (
    RelationStore,
)


def make_relation(
    confirmed_at: datetime,
) -> AssetRelation:
    return AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=(
            AssetRelationType.RESOLVES_TO
        ),
        target_type=AssetType.IP,
        target_value="192.0.2.10",
        first_seen=confirmed_at,
        last_seen=confirmed_at,
        last_confirmed=confirmed_at,
        seen_count=1,
        active=True,
    )


def make_missing(
    detected_at: datetime,
    result_file: str,
) -> ChangeRecord:
    return ChangeRecord(
        change_type=(
            ChangeType.CANDIDATE_MISSING
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
        detected_at=detected_at,
        current_result=result_file,
    )


def test_relation_lifecycle_first_missing_keeps_active(
    tmp_path,
):
    relation_store = RelationStore(
        tmp_path / "relations"
    )

    change_store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    relation_store.save(
        make_relation(start)
    )

    manager = RelationLifecycleManager(
        relation_store,
        change_store,
    )

    change = make_missing(
        start + timedelta(minutes=5),
        "dns-2.json",
    )

    change_store.save(
        change
    )

    inactive = manager.process_missing(
        change
    )

    assert inactive is None

    relation = relation_store.find()[0]

    assert relation.active is True


def test_relation_lifecycle_second_missing_marks_inactive(
    tmp_path,
):
    relation_store = RelationStore(
        tmp_path / "relations"
    )

    change_store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    relation_store.save(
        make_relation(start)
    )

    manager = RelationLifecycleManager(
        relation_store,
        change_store,
    )

    first = make_missing(
        start + timedelta(minutes=5),
        "dns-2.json",
    )

    change_store.save(
        first
    )

    assert (
        manager.process_missing(first)
        is None
    )

    second = make_missing(
        start + timedelta(minutes=10),
        "dns-3.json",
    )

    change_store.save(
        second
    )

    inactive = manager.process_missing(
        second
    )

    assert inactive is not None

    assert (
        inactive.change_type
        == ChangeType.INACTIVE
    )

    relation = relation_store.find()[0]

    assert relation.active is False


def test_relation_lifecycle_builds_reactivated_change(
    tmp_path,
):
    relation_store = RelationStore(
        tmp_path / "relations"
    )

    change_store = ChangeStore(
        tmp_path / "changes"
    )

    start = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    relation_store.save(
        make_relation(start)
    )

    relation = relation_store.find()[0]

    manager = RelationLifecycleManager(
        relation_store,
        change_store,
    )

    change = manager.build_reactivated(
        relation=relation,
        plugin="dns",
        target="example.com",
        detected_at=(
            start + timedelta(minutes=20)
        ),
        previous_result="dns-3.json",
        current_result="dns-4.json",
    )

    assert (
        change.change_type
        == ChangeType.REACTIVATED
    )

    assert (
        change.relation_type
        == AssetRelationType.RESOLVES_TO
    )

    assert (
        change.source_value
        == "example.com"
    )

    assert (
        change.target_value
        == "192.0.2.10"
    )
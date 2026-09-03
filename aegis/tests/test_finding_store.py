from datetime import (
    datetime,
    timezone,
)

from aegis.finding_store import (
    FindingStore,
)

from aegis.models import (
    AssetType,
    FindingRecord,
    FindingState,
)


def create_finding():
    now = datetime.now(
        timezone.utc
    )

    return FindingRecord(
        finding_id="a" * 64,
        rule_id="HTTP_WITHOUT_TLS",
        severity="medium",
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
        affected_service=None,
        plugin=None,
        coverage_plugins=(
            "service",
            "http",
        ),
        state=(
            FindingState.ACTIVE
        ),
        first_seen=now,
        last_seen=now,
        last_confirmed=now,
        seen_count=1,
        missing_count=0,
        active=True,
    )


def test_finding_store_saves_and_loads(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    finding = create_finding()

    store.save(
        finding
    )

    loaded = store.get(
        finding.finding_id
    )

    assert loaded is not None

    assert (
        loaded.finding_id
        == finding.finding_id
    )

    assert (
        loaded.rule_id
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        loaded.asset_type
        == AssetType.SERVICE
    )

    assert (
        loaded.asset_value
        == "example.com:80"
    )

    assert (
        loaded.state
        == FindingState.ACTIVE
    )

    assert (
        loaded.coverage_plugins
        == (
            "service",
            "http",
        )
    )

    assert loaded.active is True
    assert loaded.seen_count == 1
    assert loaded.missing_count == 0


def test_finding_store_find_returns_records(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    finding = create_finding()

    store.save(
        finding
    )

    records = store.find()

    assert len(
        records
    ) == 1

    assert (
        records[0].finding_id
        == finding.finding_id
    )


def test_finding_store_updates_existing_record(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    finding = create_finding()

    store.save(
        finding
    )

    finding.missing_count = 1

    finding.state = (
        FindingState.CANDIDATE_MISSING
    )

    store.save(
        finding
    )

    loaded = store.get(
        finding.finding_id
    )

    assert loaded is not None

    assert (
        loaded.missing_count
        == 1
    )

    assert (
        loaded.state
        == FindingState.CANDIDATE_MISSING
    )


def test_finding_store_returns_none_for_unknown_id(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    assert (
        store.get(
            "b" * 64
        )
        is None
    )


def test_finding_store_resolves_unique_prefix(
    tmp_path,
):
    store = FindingStore(
        tmp_path
    )

    finding = create_finding()

    store.save(
        finding
    )

    loaded = store.find_by_id(
        finding.finding_id[:12]
    )

    assert loaded is not None

    assert (
        loaded.finding_id
        == finding.finding_id
    )

def test_finding_store_loads_record_without_coverage(
    tmp_path,
):
    store = FindingStore(
        tmp_path / "findings"
    )

    finding = create_finding()

    path = store.save(
        finding
    )

    import json

    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    data.pop(
        "coverage_plugins"
    )

    path.write_text(
        json.dumps(
            data,
            indent=2,
        ),
        encoding="utf-8",
    )

    loaded = store.get(
        finding.finding_id
    )

    assert loaded is not None

    assert (
        loaded.coverage_plugins
        == ()
    )
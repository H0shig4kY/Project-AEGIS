from aegis.models import (
    AssetRelation,
    AssetRelationType,
    AssetType,
    RelationProvenance,
)
from aegis.relation_store import RelationStore
from datetime import datetime, timezone


def test_relation_store_saves_relation(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
    )

    path = store.save(relation)

    assert path.exists()

    loaded = store.load(path)

    assert loaded == relation


def test_relation_store_deduplicates_relation(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
    )

    first = store.save(relation)
    second = store.save(relation)

    assert first == second
    assert len(store.list()) == 1


def test_relation_store_finds_by_source(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
    )

    store.save(relation)

    found = store.find(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
    )

    assert found == [relation]


def test_relation_store_finds_by_target(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
    )

    store.save(relation)

    found = store.find(
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
    )

    assert found == [relation]

def test_relation_store_walks_graph(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    service = AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=AssetRelationType.EXPOSES,
        target_type=AssetType.SERVICE,
        target_value="example.com:443",
    )

    certificate = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
    )

    store.save(service)
    store.save(certificate)

    walked = store.walk_from(
        AssetType.DOMAIN,
        "example.com",
    )

    assert len(walked) == 2

    assert walked[0] == (
        1,
        service,
    )

    assert walked[1] == (
        2,
        certificate,
    )

def test_relation_store_walk_handles_cycles(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    first = AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=AssetRelationType.EXPOSES,
        target_type=AssetType.SERVICE,
        target_value="example.com:443",
    )

    second = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.EXPOSES,
        target_type=AssetType.DOMAIN,
        target_value="example.com",
    )

    store.save(first)
    store.save(second)

    walked = store.walk_from(
        AssetType.DOMAIN,
        "example.com",
    )

    assert len(walked) == 2

def test_relation_store_tracks_lifecycle(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    first_seen = datetime(
        2026,
        8,
        24,
        10,
        0,
        tzinfo=timezone.utc,
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
        provenance=[
            RelationProvenance(
                plugin="tls",
                observation_type="tls_handshake",
                target="example.com",
                observed_at=first_seen,
                observation_id="obs-1",
                result_id="result-1",
            )
        ],
    )

    path = store.save(relation)
    stored = store.load(path)

    assert stored.first_seen == first_seen
    assert stored.last_seen == first_seen
    assert stored.seen_count == 1

def test_relation_store_merges_provenance(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    first_seen = datetime(
        2026,
        8,
        25,
        15,
        0,
        tzinfo=timezone.utc,
    )

    second_seen = datetime(
        2026,
        8,
        25,
        15,
        5,
        tzinfo=timezone.utc,
    )

    first = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
        provenance=[
            RelationProvenance(
                plugin="tls",
                observation_type="tls_handshake",
                target="example.com",
                observed_at=first_seen,
                observation_id="obs-1",
                result_id="result-1",
            )
        ],
    )

    second = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
        provenance=[
            RelationProvenance(
                plugin="tls",
                observation_type="tls_handshake",
                target="example.com",
                observed_at=second_seen,
                observation_id="obs-1",
                result_id="result-2",
            )
        ],
    )

    store.save(first)
    path = store.save(second)

    stored = store.load(path)

    assert len(stored.provenance) == 2
    assert stored.seen_count == 2

    assert stored.first_seen == first_seen
    assert stored.last_seen == second_seen
    assert stored.last_confirmed == second_seen
    assert stored.active is True

def test_relation_store_marks_relation_active(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    observed_at = datetime(
        2026,
        8,
        25,
        15,
        0,
        tzinfo=timezone.utc,
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
        provenance=[
            RelationProvenance(
                plugin="tls",
                observation_type="tls_handshake",
                target="example.com",
                observed_at=observed_at,
                observation_id="obs-1",
                result_id="result-1",
            )
        ],
    )

    path = store.save(relation)
    stored = store.load(path)

    assert stored.active is True
    assert stored.last_confirmed == observed_at

def test_relation_store_reactivates_relation(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    first_seen = datetime(
        2026,
        8,
        25,
        14,
        0,
        tzinfo=timezone.utc,
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
        active=False,
        provenance=[
            RelationProvenance(
                plugin="tls",
                observation_type="tls_handshake",
                target="example.com",
                observed_at=first_seen,
                observation_id="obs-old",
                result_id="result-old",
            )
        ],
    )

    path = store.save(relation)

    stored = store.load(path)

    # Simular uma relação que ficou inativa.
    stored.active = False

    path.write_text(
        stored.model_dump_json(indent=2),
        encoding="utf-8",
    )

    rediscovered_at = datetime(
        2026,
        8,
        25,
        15,
        0,
        tzinfo=timezone.utc,
    )

    rediscovered = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=AssetRelationType.PRESENTS,
        target_type=AssetType.CERTIFICATE,
        target_value="a" * 64,
        provenance=[
            RelationProvenance(
                plugin="tls",
                observation_type="tls_handshake",
                target="example.com",
                observed_at=rediscovered_at,
                observation_id="obs-new",
                result_id="result-new",
            )
        ],
    )

    path = store.save(
        rediscovered
    )

    stored = store.load(path)

    assert stored.active is True
    assert (
        stored.last_confirmed
        == rediscovered_at
    )
    assert stored.seen_count == 2

def test_relation_store_can_mark_relation_inactive(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    relation = AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=(
            AssetRelationType.RESOLVES_TO
        ),
        target_type=AssetType.IP,
        target_value="192.0.2.10",
    )

    path = store.save(
        relation
    )

    updated = store.set_active(
        AssetType.DOMAIN,
        "example.com",
        AssetRelationType.RESOLVES_TO,
        AssetType.IP,
        "192.0.2.10",
        False,
    )

    assert updated is not None
    assert updated.active is False

    stored = store.load(
        path
    )

    assert stored.active is False

def test_relation_store_can_reactivate_relation(
    tmp_path,
):
    store = RelationStore(
        tmp_path / "relations"
    )

    relation = AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=(
            AssetRelationType.RESOLVES_TO
        ),
        target_type=AssetType.IP,
        target_value="192.0.2.10",
    )

    store.save(
        relation
    )

    store.set_active(
        AssetType.DOMAIN,
        "example.com",
        AssetRelationType.RESOLVES_TO,
        AssetType.IP,
        "192.0.2.10",
        False,
    )

    updated = store.set_active(
        AssetType.DOMAIN,
        "example.com",
        AssetRelationType.RESOLVES_TO,
        AssetType.IP,
        "192.0.2.10",
        True,
    )

    assert updated is not None
    assert updated.active is True
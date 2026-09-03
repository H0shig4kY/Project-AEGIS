from datetime import (
    datetime,
    timezone,
)

from aegis.finding_processor import (
    FindingProcessor,
)
from aegis.finding_store import (
    FindingStore,
)
from aegis.asset_store import (
    AssetStore,
)
from aegis.relation_store import (
    RelationStore,
)
from aegis.change_store import (
    ChangeStore,
)
from aegis.models import (
    Asset,
    AssetType,
    FindingState,
)


def create_processor(
    tmp_path,
):
    assets = AssetStore(
        tmp_path / "assets"
    )

    relations = RelationStore(
        tmp_path / "relations"
    )

    changes = ChangeStore(
        tmp_path / "changes"
    )

    findings = FindingStore(
        tmp_path / "findings"
    )

    processor = FindingProcessor(
        asset_store=assets,
        relation_store=relations,
        change_store=changes,
        finding_store=findings,
    )

    return (
        processor,
        assets,
        findings,
    )


def test_processor_persists_exposure_finding(
    tmp_path,
):
    (
        processor,
        assets,
        findings,
    ) = create_processor(
        tmp_path
    )

    assets.save(
        Asset(
            type=AssetType.SERVICE,
            value="example.com:80",
            source="service",
            metadata={
                "service_name": "http",
                "port": 80,
                "transport": "tcp",
            },
        )
    )

    now = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    report = processor.process(
        observed_at=now
    )

    assert len(
        report.findings
    ) == 1

    records = findings.find()

    assert len(records) == 1

    record = records[0]

    assert (
        record.rule_id
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        record.state
        == FindingState.ACTIVE
    )

    assert record.active is True
    assert record.first_seen == now
    assert record.last_confirmed == now


def test_processor_updates_existing_finding(
    tmp_path,
):
    (
        processor,
        assets,
        findings,
    ) = create_processor(
        tmp_path
    )

    assets.save(
        Asset(
            type=AssetType.SERVICE,
            value="example.com:80",
            source="service",
            metadata={
                "service_name": "http",
                "port": 80,
                "transport": "tcp",
            },
        )
    )

    first = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    second = datetime(
        2026,
        9,
        3,
        13,
        0,
        tzinfo=timezone.utc,
    )

    processor.process(
        observed_at=first
    )

    processor.process(
        observed_at=second
    )

    records = findings.find()

    assert len(records) == 1

    record = records[0]

    assert record.seen_count == 2
    assert record.first_seen == first
    assert record.last_seen == second

    assert (
        record.state
        == FindingState.ACTIVE
    )


def test_processor_marks_missing_finding(
    tmp_path,
    monkeypatch,
):
    (
        processor,
        assets,
        findings,
    ) = create_processor(
        tmp_path
    )

    asset = Asset(
        type=AssetType.SERVICE,
        value="example.com:80",
        source="service",
        metadata={
            "service_name": "http",
            "port": 80,
            "transport": "tcp",
        },
        active=True,
    )

    assets.save(
        asset
    )

    first = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    processor.process(
        observed_at=first
    )

    records = findings.find()

    assert len(
        records
    ) == 1

    record = records[0]

    monkeypatch.setattr(
        processor.asset_store,
        "find",
        lambda *args, **kwargs: [],
    )

    second = datetime(
        2026,
        9,
        3,
        13,
        0,
        tzinfo=timezone.utc,
    )

    processor.process(
        observed_at=second
    )

    record = findings.get(
        record.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.CANDIDATE_MISSING
    )

    assert record.active is True
    assert record.missing_count == 1

def test_processor_ignores_missing_for_unrelated_plugin(
    tmp_path,
    monkeypatch,
):
    (
        processor,
        assets,
        findings,
    ) = create_processor(
        tmp_path
    )

    asset = Asset(
        type=AssetType.SERVICE,
        value="example.com:80",
        source="service",
        metadata={
            "service_name": "http",
            "port": 80,
            "transport": "tcp",
        },
        active=True,
    )

    assets.save(
        asset
    )

    first = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    processor.process(
        observed_at=first,
        observed_plugin="service",
    )

    record = findings.find()[0]

    monkeypatch.setattr(
        processor.asset_store,
        "find",
        lambda *args, **kwargs: [],
    )

    second = datetime(
        2026,
        9,
        3,
        13,
        0,
        tzinfo=timezone.utc,
    )

    processor.process(
        observed_at=second,
        observed_plugin="dns",
    )

    record = findings.get(
        record.finding_id
    )

    assert record is not None

    assert (
        record.state
        == FindingState.ACTIVE
    )

    assert record.missing_count == 0
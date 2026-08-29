from datetime import (
    datetime,
    timedelta,
    timezone,
)
from pathlib import Path

from aegis.assessment import AssessmentContext
from aegis.change_engine import ChangeEngine
from aegis.context import CampaignContext
from aegis.models import (
    Asset,
    AssetType,
    ChangeType,
    CoverageType,
    ExecutionCoverage,
)
from aegis.results import PluginResult


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


def make_service_result(
    timestamp: datetime,
) -> PluginResult:
    result = PluginResult(
        plugin="service",
        version="0.1.0",
        observations=[],
        coverage=[
            ExecutionCoverage(
                plugin="service",
                target="example.com",
                coverage_type=(
                    CoverageType.SERVICE
                ),
                ports=[80],
            )
        ],
    )

    result.timestamp = timestamp

    return result


def test_change_engine_processes_missing_service(
    tmp_path,
):
    context = create_context(
        tmp_path
    )

    confirmed_at = datetime(
        2026,
        8,
        29,
        10,
        0,
        tzinfo=timezone.utc,
    )

    context.assets.save(
        Asset(
            value="example.com:80",
            type=AssetType.SERVICE,
            source="service",
            metadata={
                "host": "example.com",
                "port": 80,
            },
            first_seen=confirmed_at,
            last_seen=confirmed_at,
            last_confirmed=confirmed_at,
            seen_count=1,
            active=True,
        )
    )

    engine = ChangeEngine(
        context
    )

    result = make_service_result(
        confirmed_at
        + timedelta(minutes=5)
    )

    changes = engine.process_missing(
        result,
        saved_path=(
            context.root
            / "service-2.json"
        ),
    )

    assert len(changes) == 1

    change = changes[0]

    assert (
        change.change_type
        == ChangeType.CANDIDATE_MISSING
    )

    assert (
        change.asset_type
        == AssetType.SERVICE
    )

    assert (
        change.asset_value
        == "example.com:80"
    )

    assert (
        change.plugin
        == "service"
    )

    assert (
        change.target
        == "example.com"
    )

    assert (
        change.current_result
        == "service-2.json"
    )

    asset = context.assets.find(
        asset_type=AssetType.SERVICE,
    )[0]

    assert asset.active is True


def test_change_engine_second_missing_inactivates_service(
    tmp_path,
):
    context = create_context(
        tmp_path
    )

    confirmed_at = datetime(
        2026,
        8,
        29,
        10,
        0,
        tzinfo=timezone.utc,
    )

    context.assets.save(
        Asset(
            value="example.com:80",
            type=AssetType.SERVICE,
            source="service",
            metadata={
                "host": "example.com",
                "port": 80,
            },
            first_seen=confirmed_at,
            last_seen=confirmed_at,
            last_confirmed=confirmed_at,
            seen_count=1,
            active=True,
        )
    )

    engine = ChangeEngine(
        context
    )

    # Primeira ausência.
    first = make_service_result(
        confirmed_at
        + timedelta(minutes=5)
    )

    first_changes = engine.process_missing(
        first,
        saved_path=(
            context.root
            / "service-2.json"
        ),
    )

    assert len(first_changes) == 1

    assert (
        first_changes[0].change_type
        == ChangeType.CANDIDATE_MISSING
    )

    asset = context.assets.find(
        asset_type=AssetType.SERVICE,
    )[0]

    assert asset.active is True

    # Segunda ausência.
    second = make_service_result(
        confirmed_at
        + timedelta(minutes=10)
    )

    second_changes = engine.process_missing(
        second,
        saved_path=(
            context.root
            / "service-3.json"
        ),
    )

    assert any(
        change.change_type
        == ChangeType.CANDIDATE_MISSING
        for change in second_changes
    )

    assert any(
        change.change_type
        == ChangeType.INACTIVE
        for change in second_changes
    )

    candidate_changes = [
        change
        for change in second_changes
        if (
            change.change_type
            == ChangeType.CANDIDATE_MISSING
        )
    ]

    assert len(candidate_changes) == 1

    inactive_changes = [
        change
        for change in second_changes
        if (
            change.change_type
            == ChangeType.INACTIVE
        )
    ]

    assert len(inactive_changes) == 1

    inactive = inactive_changes[0]

    assert (
        inactive.asset_type
        == AssetType.SERVICE
    )

    assert (
        inactive.asset_value
        == "example.com:80"
    )

    assert (
        inactive.plugin
        == "service"
    )

    assert (
        inactive.current_result
        == "service-3.json"
    )

    asset = context.assets.find(
        asset_type=AssetType.SERVICE,
    )[0]

    assert asset.active is False


def test_change_engine_records_previous_result(
    tmp_path,
):
    context = create_context(
        tmp_path
    )

    confirmed_at = datetime(
        2026,
        8,
        29,
        10,
        0,
        tzinfo=timezone.utc,
    )

    context.assets.save(
        Asset(
            value="example.com:80",
            type=AssetType.SERVICE,
            source="service",
            metadata={
                "host": "example.com",
                "port": 80,
            },
            first_seen=confirmed_at,
            last_seen=confirmed_at,
            last_confirmed=confirmed_at,
            seen_count=1,
            active=True,
        )
    )

    engine = ChangeEngine(
        context
    )

    result = make_service_result(
        confirmed_at
        + timedelta(minutes=5)
    )

    previous_path = (
        context.root
        / "service-1.json"
    )

    changes = engine.process_missing(
        result,
        saved_path=(
            context.root
            / "service-2.json"
        ),
        previous_path=previous_path,
    )

    assert len(changes) == 1

    change = changes[0]

    assert (
        change.previous_result
        == "service-1.json"
    )

    assert (
        change.current_result
        == "service-2.json"
    )


def test_change_engine_ignores_unknown_plugin(
    tmp_path,
):
    context = create_context(
        tmp_path
    )

    engine = ChangeEngine(
        context
    )

    result = PluginResult(
        plugin="unknown",
        version="0.1.0",
        observations=[],
        coverage=[],
    )

    changes = engine.process_missing(
        result,
        saved_path=(
            context.root
            / "unknown-1.json"
        ),
    )

    assert changes == []
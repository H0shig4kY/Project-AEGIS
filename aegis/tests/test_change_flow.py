from datetime import datetime, timedelta, timezone

from aegis.change_detector import (
    detect_service_changes,
)
from aegis.change_history import (
    find_previous_comparable_result,
)
from aegis.change_store import ChangeStore
from aegis.models import (
    ChangeType,
    CoverageType,
    ExecutionCoverage,
)
from aegis.result_store import ResultStore
from aegis.results import (
    Observation,
    PluginResult,
)


def test_service_change_flow_persists_candidate_missing(
    tmp_path,
):
    results = ResultStore(
        tmp_path / "results"
    )

    changes = ChangeStore(
        tmp_path / "changes"
    )

    now = datetime.now(
        timezone.utc
    )

    previous = PluginResult(
        plugin="service",
        version="0.1.0",
        timestamp=(
            now - timedelta(minutes=5)
        ),
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "host": "example.com",
                    "port": 80,
                },
            ),
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "host": "example.com",
                    "port": 443,
                },
            ),
        ],
        coverage=[
            ExecutionCoverage(
                plugin="service",
                target="example.com",
                coverage_type=(
                    CoverageType.SERVICE
                ),
                ports=[
                    22,
                    80,
                    443,
                ],
            )
        ],
    )

    current = PluginResult(
        plugin="service",
        version="0.1.0",
        timestamp=now,
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "host": "example.com",
                    "port": 443,
                },
            ),
        ],
        coverage=[
            ExecutionCoverage(
                plugin="service",
                target="example.com",
                coverage_type=(
                    CoverageType.SERVICE
                ),
                ports=[
                    22,
                    80,
                    443,
                ],
            )
        ],
    )

    previous_path = results.save(
        previous
    )

    current_path = results.save(
        current
    )

    found = find_previous_comparable_result(
        results,
        current,
        current_path=current_path,
    )

    assert found is not None

    found_path, found_result = found

    assert found_path == previous_path

    detected = detect_service_changes(
        found_result,
        current,
    )

    assert len(detected) == 1

    change = detected[0]

    change.previous_result = (
        previous_path.name
    )

    change.current_result = (
        current_path.name
    )

    path = changes.save(
        change
    )

    stored = changes.load(
        path
    )

    assert (
        stored.change_type
        == ChangeType.CANDIDATE_MISSING
    )

    assert (
        stored.asset_value
        == "example.com:80"
    )

    assert (
        stored.previous_result
        == previous_path.name
    )

    assert (
        stored.current_result
        == current_path.name
    )
from aegis.change_detector import (
    detect_service_changes,
)
from aegis.models import (
    AssetType,
    ChangeType,
    CoverageType,
    ExecutionCoverage,
)
from aegis.results import (
    Observation,
    PluginResult,
)
from aegis.change_store import ChangeStore

def test_service_missing_candidate():
    previous = PluginResult(
        plugin="service",
        version="0.1.0",
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

    changes = detect_service_changes(
        previous,
        current,
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

    assert change.plugin == "service"
    assert change.target == "example.com"

def test_service_no_missing_when_still_present():
    previous = PluginResult(
        plugin="service",
        version="0.1.0",
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
                ports=[443],
            )
        ],
    )

    current = PluginResult(
        plugin="service",
        version="0.1.0",
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
                ports=[443],
            )
        ],
    )

    changes = detect_service_changes(
        previous,
        current,
    )

    assert changes == []

def test_service_missing_not_detected_with_different_coverage():
    previous = PluginResult(
        plugin="service",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "host": "example.com",
                    "port": 80,
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
                    80,
                    443,
                ],
            )
        ],
    )

    current = PluginResult(
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
                ports=[443],
            )
        ],
    )

    changes = detect_service_changes(
        previous,
        current,
    )

    assert changes == []

def test_detected_change_can_be_saved(
    tmp_path,
):
    previous = PluginResult(
        plugin="service",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "host": "example.com",
                    "port": 80,
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
                    80,
                    443,
                ],
            )
        ],
    )

    current = PluginResult(
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
                ports=[
                    80,
                    443,
                ],
            )
        ],
    )

    changes = detect_service_changes(
        previous,
        current,
    )

    assert len(changes) == 1

    change = changes[0]

    change.previous_result = (
        "service-previous.json"
    )

    change.current_result = (
        "service-current.json"
    )

    store = ChangeStore(
        tmp_path / "changes"
    )

    path = store.save(
        change
    )

    assert path.exists()

    stored = store.load(
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
        == "service-previous.json"
    )

    assert (
        stored.current_result
        == "service-current.json"
    )
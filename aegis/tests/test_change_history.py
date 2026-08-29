from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.change_history import (
    find_previous_comparable_result,
)
from aegis.models import (
    CoverageType,
    ExecutionCoverage,
)
from aegis.result_store import ResultStore
from aegis.results import PluginResult


def make_result(
    timestamp,
    ports,
):
    return PluginResult(
        plugin="service",
        version="0.1.0",
        timestamp=timestamp,
        coverage=[
            ExecutionCoverage(
                plugin="service",
                target="example.com",
                coverage_type=(
                    CoverageType.SERVICE
                ),
                ports=ports,
            )
        ],
    )


def test_finds_previous_comparable_result(
    tmp_path,
):
    store = ResultStore(
        tmp_path / "results"
    )

    now = datetime.now(
        timezone.utc
    )

    previous = make_result(
        now - timedelta(minutes=10),
        [22, 80, 443],
    )

    current = make_result(
        now,
        [22, 80, 443],
    )

    previous_path = store.save(
        previous
    )

    current_path = store.save(
        current
    )

    found = find_previous_comparable_result(
        store,
        current,
        current_path=current_path,
    )

    assert found is not None

    path, result = found

    assert path == previous_path
    assert result.timestamp == previous.timestamp


def test_different_coverage_is_not_comparable(
    tmp_path,
):
    store = ResultStore(
        tmp_path / "results"
    )

    now = datetime.now(
        timezone.utc
    )

    previous = make_result(
        now - timedelta(minutes=10),
        [80, 443],
    )

    current = make_result(
        now,
        [22, 80, 443],
    )

    store.save(previous)

    current_path = store.save(
        current
    )

    found = find_previous_comparable_result(
        store,
        current,
        current_path=current_path,
    )

    assert found is None


def test_result_without_coverage_is_ignored(
    tmp_path,
):
    store = ResultStore(
        tmp_path / "results"
    )

    now = datetime.now(
        timezone.utc
    )

    legacy = PluginResult(
        plugin="service",
        version="0.1.0",
        timestamp=(
            now - timedelta(minutes=10)
        ),
    )

    current = make_result(
        now,
        [22, 80, 443],
    )

    store.save(legacy)

    current_path = store.save(
        current
    )

    found = find_previous_comparable_result(
        store,
        current,
        current_path=current_path,
    )

    assert found is None
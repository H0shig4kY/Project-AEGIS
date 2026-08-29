from pathlib import Path

from aegis.results import PluginResult
from aegis.result_store import ResultStore


def _coverage_signature(
    result: PluginResult,
) -> set[tuple]:
    return {
        (
            item.plugin,
            item.target,
            item.coverage_type.value,
            tuple(item.ports),
        )
        for item in result.coverage
    }


def find_previous_comparable_result(
    store: ResultStore,
    current: PluginResult,
    current_path: Path | None = None,
) -> tuple[Path, PluginResult] | None:
    """
    Find the newest previous result with:
      - same plugin
      - same execution coverage

    The current result itself is excluded.
    """

    current_signature = _coverage_signature(
        current
    )

    if not current_signature:
        return None

    candidates: list[
        tuple[Path, PluginResult]
    ] = []

    for path in store.list():
        if (
            current_path is not None
            and path.resolve()
            == current_path.resolve()
        ):
            continue

        try:
            result = store.load(path)
        except ValueError:
            continue

        if result.plugin != current.plugin:
            continue

        if not result.coverage:
            # Legacy result without coverage.
            continue

        if (
            _coverage_signature(result)
            != current_signature
        ):
            continue

        # It must genuinely be older.
        if result.timestamp >= current.timestamp:
            continue

        candidates.append(
            (
                path,
                result,
            )
        )

    if not candidates:
        return None

    return max(
        candidates,
        key=lambda item: item[1].timestamp,
    )
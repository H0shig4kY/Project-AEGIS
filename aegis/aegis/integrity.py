import hashlib
from pathlib import Path
from aegis.models import IntegrityBaselineType


def sha256_file(
    path: Path,
    chunk_size: int = 65536,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()


def verify_sha256(
    path: Path,
    expected: str,
) -> bool:
    return sha256_file(path) == expected

def collect_expected_hashes(
    assets,
    filename: str,
) -> set[str]:
    hashes = set()

    for asset in assets:
        for provenance in asset.provenance:
            if (
                provenance.result_file == filename
                and provenance.result_sha256
            ):
                hashes.add(
                    provenance.result_sha256
                )

    return hashes


def verify_result_file(
    path: Path,
    assets,
    integrity_record=None,
) -> tuple[
    str,
    str | None,
    str,
]:
    current_sha256 = sha256_file(path)

    # Preferred source: campaign integrity manifest.
    if integrity_record is not None:
        expected_sha256 = (
            integrity_record.sha256
        )

        if current_sha256 != expected_sha256:
            return (
                "FAILED",
                expected_sha256,
                current_sha256,
            )

        if (
            integrity_record.baseline_type
            == IntegrityBaselineType.RETROSPECTIVE
        ):
            return (
                "BASELINED",
                expected_sha256,
                current_sha256,
            )

        return (
            "OK",
            expected_sha256,
            current_sha256,
        )

    # Legacy fallback: integrity stored in asset provenance.
    records = collect_expected_integrity(
        assets,
        path.name,
    )

    if not records:
        return (
            "UNKNOWN",
            None,
            current_sha256,
        )

    hashes = {
        hash_value
        for hash_value, _ in records
    }

    if len(hashes) > 1:
        return (
            "CONFLICT",
            None,
            current_sha256,
        )

    expected_sha256 = next(
        iter(hashes)
    )

    if current_sha256 != expected_sha256:
        return (
            "FAILED",
            expected_sha256,
            current_sha256,
        )

    baseline_types = {
        baseline
        for _, baseline in records
        if baseline is not None
    }

    if baseline_types == {
        "retrospective"
    }:
        return (
            "BASELINED",
            expected_sha256,
            current_sha256,
        )

    return (
        "OK",
        expected_sha256,
        current_sha256,
    )

def baseline_result_hash(
    filename: str,
    result_sha256: str,
    assets,
) -> int:
    updated = 0

    for asset in assets:
        changed = False

        for provenance in asset.provenance:
            if (
                provenance.result_file == filename
                and provenance.result_sha256 is None
            ):
                provenance.result_sha256 = (
                    result_sha256
                )
                provenance.integrity_baseline = (
                    IntegrityBaselineType.RETROSPECTIVE
                )
                changed = True

        if changed:
            updated += 1

    return updated

def collect_expected_integrity(
    assets,
    filename: str,
) -> list[tuple[str, str | None]]:
    records = []

    for asset in assets:
        for provenance in asset.provenance:
            if (
                provenance.result_file == filename
                and provenance.result_sha256
            ):
                baseline = (
                    provenance.integrity_baseline.value
                    if provenance.integrity_baseline
                    else None
                )

                records.append(
                    (
                        provenance.result_sha256,
                        baseline,
                    )
                )

    return records
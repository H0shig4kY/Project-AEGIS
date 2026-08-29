from datetime import datetime, timezone
from pathlib import Path

from aegis.models import (
    IntegrityBaselineType,
    ResultIntegrityManifest,
    ResultIntegrityRecord,
)


class IntegrityStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.path = (
            self.directory
            / "results-manifest.json"
        )

    def load(self) -> ResultIntegrityManifest:
        if not self.path.exists():
            return ResultIntegrityManifest()

        return ResultIntegrityManifest.model_validate_json(
            self.path.read_text(
                encoding="utf-8"
            )
        )

    def save(
        self,
        manifest: ResultIntegrityManifest,
    ) -> None:
        self.path.write_text(
            manifest.model_dump_json(indent=2),
            encoding="utf-8",
        )

    def upsert(
        self,
        filename: str,
        sha256: str,
        baseline_type: IntegrityBaselineType,
        created_at: datetime,
    ) -> ResultIntegrityRecord:
        manifest = self.load()

        for record in manifest.results:
            if record.filename == filename:
                record.sha256 = sha256
                record.baseline_type = baseline_type
                record.created_at = created_at

                self.save(manifest)
                return record

        record = ResultIntegrityRecord(
            filename=filename,
            sha256=sha256,
            baseline_type=baseline_type,
            created_at=created_at,
        )

        manifest.results.append(record)

        self.save(manifest)

        return record

    def get(
        self,
        filename: str,
    ) -> ResultIntegrityRecord | None:
        manifest = self.load()

        for record in manifest.results:
            if record.filename == filename:
                return record

        return None

    def mark_verified(
        self,
        filename: str,
    ) -> None:
        manifest = self.load()

        for record in manifest.results:
            if record.filename == filename:
                record.verified_at = datetime.now(
                    timezone.utc
                )
                self.save(manifest)
                return
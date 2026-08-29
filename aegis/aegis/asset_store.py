from pathlib import Path

from aegis.models import (
    Asset,
    AssetProvenance,
    AssetType,
)


class AssetStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def _filename(self, asset: Asset) -> str:
        safe_value = (
            asset.value
            .replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
            .replace("*", "_")
            .replace("?", "_")
            .replace('"', "_")
            .replace("<", "_")
            .replace(">", "_")
            .replace("|", "_")
        )

        return (
            f"{asset.type.value}-"
            f"{safe_value}.json"
        )

    @staticmethod
    def _provenance_key(
        provenance: AssetProvenance,
    ) -> tuple:
        """
        Return a stable identity key for provenance.

        Modern provenance uses deterministic IDs.

        Legacy provenance does not have an observation_id,
        so stable historical fields are used instead.
        """

        if provenance.observation_id is not None:
            return (
                "modern",
                provenance.result_id,
                provenance.observation_id,
            )

        return (
            "legacy",
            provenance.plugin,
            provenance.plugin_version,
            provenance.observation_type,
            provenance.target,
            provenance.observed_at,
            provenance.result_file,
        )

    @staticmethod
    def _enrich_provenance(
        existing: AssetProvenance,
        incoming: AssetProvenance,
    ) -> None:
        """
        Enrich an existing provenance record with
        information learned later.
        """

        if incoming.result_file is not None:
            existing.result_file = (
                incoming.result_file
            )

        if incoming.observation_id is not None:
            existing.observation_id = (
                incoming.observation_id
            )

        if incoming.result_id is not None:
            existing.result_id = (
                incoming.result_id
            )

        if incoming.result_sha256 is not None:
            existing.result_sha256 = (
                incoming.result_sha256
            )

        if (
            incoming.integrity_baseline
            is not None
        ):
            existing.integrity_baseline = (
                incoming.integrity_baseline
            )

    def _normalize_provenance(
        self,
        provenance_items: list[AssetProvenance],
    ) -> list[AssetProvenance]:
        """
        Deduplicate provenance while preserving
        the richest available record.
        """

        unique: list[AssetProvenance] = []
        by_key: dict[
            tuple,
            AssetProvenance,
        ] = {}

        for provenance in provenance_items:
            key = self._provenance_key(
                provenance
            )

            existing = by_key.get(key)

            if existing is None:
                unique.append(provenance)
                by_key[key] = provenance
                continue

            self._enrich_provenance(
                existing,
                provenance,
            )

        return unique

    @staticmethod
    def _update_lifecycle(
        asset: Asset,
    ) -> None:
        """
        Recalculate lifecycle from provenance.

        Provenance is the source of truth whenever
        it exists.
        """

        if not asset.provenance:
            return

        observed_times = [
            provenance.observed_at
            for provenance in asset.provenance
        ]

        asset.first_seen = min(
            observed_times
        )

        asset.last_seen = max(
            observed_times
        )

        asset.last_confirmed = (
            asset.last_seen
        )

        asset.seen_count = len(
            asset.provenance
        )

        asset.active = True

    def save(self, asset: Asset) -> Path:
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = (
            self.directory
            / self._filename(asset)
        )

        if path.exists():
            existing = self.load(path)

            # Keep the latest metadata discovered
            # for this logical asset.
            existing.metadata.update(
                asset.metadata
            )

            # First normalize historical provenance.
            existing.provenance = (
                self._normalize_provenance(
                    existing.provenance
                )
            )

            existing_by_key = {
                self._provenance_key(
                    provenance
                ): provenance
                for provenance
                in existing.provenance
            }

            # Merge incoming provenance.
            for incoming in asset.provenance:
                key = self._provenance_key(
                    incoming
                )

                matched = existing_by_key.get(
                    key
                )

                if matched is None:
                    existing.provenance.append(
                        incoming
                    )

                    existing_by_key[key] = (
                        incoming
                    )

                    continue

                # Same evidence already exists:
                # enrich it instead of duplicating it.
                self._enrich_provenance(
                    matched,
                    incoming,
                )

            # Normalize once more in case old files
            # already contained duplicates.
            existing.provenance = (
                self._normalize_provenance(
                    existing.provenance
                )
            )

            if existing.provenance:
                self._update_lifecycle(
                    existing
                )

            else:
                # Fallback for assets created before
                # provenance/lifecycle existed.
                if existing.first_seen is None:
                    existing.first_seen = (
                        asset.first_seen
                    )

                elif (
                    asset.first_seen is not None
                    and asset.first_seen
                    < existing.first_seen
                ):
                    existing.first_seen = (
                        asset.first_seen
                    )

                if existing.last_seen is None:
                    existing.last_seen = (
                        asset.last_seen
                    )

                elif (
                    asset.last_seen is not None
                    and asset.last_seen
                    > existing.last_seen
                ):
                    existing.last_seen = (
                        asset.last_seen
                    )

                existing.seen_count += (
                    asset.seen_count
                )

            asset = existing

        else:
            # A new asset can theoretically arrive
            # with duplicate provenance too.
            asset.provenance = (
                self._normalize_provenance(
                    asset.provenance
                )
            )

            if asset.provenance:
                self._update_lifecycle(
                    asset
                )

        path.write_text(
            asset.model_dump_json(indent=2),
            encoding="utf-8",
        )

        return path

    def list(self) -> list[Path]:
        return sorted(
            self.directory.glob("*.json")
        )

    def load(self, path: Path) -> Asset:
        return Asset.model_validate_json(
            path.read_text(
                encoding="utf-8"
            )
        )

    def find(
        self,
        asset_type: AssetType | None = None,
        source: str | None = None,
    ) -> list[Asset]:
        assets: list[Asset] = []

        for path in self.list():
            asset = self.load(path)

            if asset_type is not None:
                if asset.type != asset_type:
                    continue

            if source is not None:
                if asset.source != source:
                    continue

            assets.append(asset)

        return assets

    def set_active(
        self,
        asset_type: AssetType,
        value: str,
        active: bool,
    ) -> Asset | None:
        for path in self.list():
            asset = self.load(path)

            if (
                asset.type == asset_type
                and asset.value == value
            ):
                asset.active = active

                path.write_text(
                    asset.model_dump_json(
                        indent=2
                    ),
                    encoding="utf-8",
                )

                return asset

        return None
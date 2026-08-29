import hashlib
from pathlib import Path

from aegis.models import (
    AssetRelation,
    AssetRelationType,
    AssetType,
    RelationProvenance,
)


class RelationStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    @staticmethod
    def _relation_id(
        relation: AssetRelation,
    ) -> str:
        canonical = "|".join(
            (
                relation.source_type.value,
                relation.source_value,
                relation.relation.value,
                relation.target_type.value,
                relation.target_value,
            )
        )

        return hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

    def _filename(
        self,
        relation: AssetRelation,
    ) -> str:
        return (
            f"{self._relation_id(relation)}.json"
        )

    @staticmethod
    def _provenance_key(
        provenance: RelationProvenance,
    ) -> tuple:
        if provenance.observation_id is not None:
            return (
                provenance.result_id,
                provenance.observation_id,
            )

        return (
            provenance.plugin,
            provenance.plugin_version,
            provenance.observation_type,
            provenance.target,
            provenance.observed_at,
            provenance.result_file,
        )

    @staticmethod
    def _update_lifecycle(
        relation: AssetRelation,
    ) -> None:
        if not relation.provenance:
            return

        observed_times = [
            item.observed_at
            for item in relation.provenance
        ]

        relation.first_seen = min(
            observed_times
        )

        relation.last_seen = max(
            observed_times
        )

        relation.last_confirmed = (
            relation.last_seen
        )

        relation.seen_count = len(
            relation.provenance
        )

        relation.active = True
    def save(
        self,
        relation: AssetRelation,
    ) -> Path:
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = (
            self.directory
            / self._filename(relation)
        )

        if path.exists():
            existing = self.load(path)

            existing_keys = {
                self._provenance_key(item)
                for item in existing.provenance
            }

            for incoming in relation.provenance:
                key = self._provenance_key(
                    incoming
                )

                if key in existing_keys:
                    continue

                existing.provenance.append(
                    incoming
                )
                existing_keys.add(key)

            relation = existing

        self._update_lifecycle(
            relation
        )

        path.write_text(
            relation.model_dump_json(indent=2),
            encoding="utf-8",
        )

        return path

    def list(self) -> list[Path]:
        return sorted(
            self.directory.glob("*.json")
        )

    def load(
        self,
        path: Path,
    ) -> AssetRelation:
        return AssetRelation.model_validate_json(
            path.read_text(
                encoding="utf-8"
            )
        )

    def find(
        self,
        source_type: AssetType | None = None,
        source_value: str | None = None,
        relation_type: AssetRelationType | None = None,
        target_type: AssetType | None = None,
        target_value: str | None = None,
    ) -> list[AssetRelation]:
        relations: list[AssetRelation] = []

        for path in self.list():
            relation = self.load(path)

            if (
                source_type is not None
                and relation.source_type
                != source_type
            ):
                continue

            if (
                source_value is not None
                and relation.source_value
                != source_value
            ):
                continue

            if (
                relation_type is not None
                and relation.relation
                != relation_type
            ):
                continue

            if (
                target_type is not None
                and relation.target_type
                != target_type
            ):
                continue

            if (
                target_value is not None
                and relation.target_value
                != target_value
            ):
                continue

            relations.append(relation)

        return relations

    def walk_from(
        self,
        source_type: AssetType,
        source_value: str,
        max_depth: int = 10,
    ) -> list[tuple[int, AssetRelation]]:
        walked: list[
            tuple[int, AssetRelation]
        ] = []

        visited_nodes: set[
            tuple[AssetType, str]
        ] = set()

        def walk(
            asset_type: AssetType,
            value: str,
            depth: int,
        ) -> None:
            if depth > max_depth:
                return

            node_key = (
                asset_type,
                value,
            )

            if node_key in visited_nodes:
                return

            visited_nodes.add(
                node_key
            )

            relations = self.find(
                source_type=asset_type,
                source_value=value,
            )

            for relation in relations:
                walked.append(
                    (
                        depth,
                        relation,
                    )
                )

                walk(
                    relation.target_type,
                    relation.target_value,
                    depth + 1,
                )

        walk(
            source_type,
            source_value,
            1,
        )

        return walked

    def set_active(
        self,
        source_type: AssetType,
        source_value: str,
        relation: AssetRelationType,
        target_type: AssetType,
        target_value: str,
        active: bool,
    ) -> AssetRelation | None:
        for path in self.list():
            stored = self.load(
                path
            )

            if (
                stored.source_type
                == source_type
                and stored.source_value
                == source_value
                and stored.relation
                == relation
                and stored.target_type
                == target_type
                and stored.target_value
                == target_value
            ):
                stored.active = active

                path.write_text(
                    stored.model_dump_json(
                        indent=2
                    ),
                    encoding="utf-8",
                )

                return stored

        return None
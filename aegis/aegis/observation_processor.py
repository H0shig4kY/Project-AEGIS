from pathlib import Path

from aegis.asset_extractor import (
    assets_from_observation,
)
from aegis.asset_store import AssetStore
from aegis.models import (
    AssetProvenance,
    RelationProvenance,
)
from aegis.provenance import (
    build_observation_id,
    build_result_id,
)
from aegis.relation_extractor import (
    relations_from_observation,
)
from aegis.relation_store import RelationStore
from aegis.results import (
    PluginResult,
    ProcessingResult,
    RejectedAsset,
)
from aegis.scope import ScopeEngine


class ObservationProcessor:
    def __init__(
        self,
        asset_store: AssetStore,
        scope: ScopeEngine,
        relation_store: RelationStore | None = None,
    ):
        self.asset_store = asset_store
        self.scope = scope
        self.relation_store = relation_store

    def process(
        self,
        result: PluginResult,
        result_path: Path | None = None,
        result_sha256: str | None = None,
    ) -> ProcessingResult:

        accepted = []
        rejected = []

        result_id = build_result_id(
            result
        )

        for observation in result.observations:
            extracted = assets_from_observation(
                observation
            )

            observation_id = build_observation_id(
                result.plugin,
                observation,
            )

            # Assets rejected specifically while
            # processing this observation.
            rejected_keys = set()

            for asset in extracted:
                provenance = AssetProvenance(
                    plugin=result.plugin,
                    plugin_version=result.version,
                    observation_type=(
                        observation.type
                    ),
                    target=observation.target,
                    observed_at=result.timestamp,
                    result_file=(
                        result_path.name
                        if result_path is not None
                        else None
                    ),
                    observation_id=(
                        observation_id
                    ),
                    result_id=result_id,
                    result_sha256=(
                        result_sha256
                    ),
                )

                asset.provenance.append(
                    provenance
                )

                asset.first_seen = (
                    result.timestamp
                )

                asset.last_seen = (
                    result.timestamp
                )

                asset.seen_count = 1

                decision = self.scope.evaluate(
                    asset
                )

                if decision.allowed:
                    self.asset_store.save(
                        asset
                    )

                    accepted.append(
                        asset
                    )

                    continue

                # Remember rejected endpoints so
                # relations pointing to them are
                # not promoted into the graph.
                rejected_keys.add(
                    (
                        asset.type,
                        asset.value,
                    )
                )

                if decision.reason is None:
                    raise RuntimeError(
                        "Rejected scope decision "
                        "without a reason."
                    )

                rejected.append(
                    RejectedAsset(
                        asset=asset,
                        reason=decision.reason,
                    )
                )

            # Relations are derived only after
            # scope decisions for this observation.
            if self.relation_store is not None:
                relations = (
                    relations_from_observation(
                        observation
                    )
                )

                for relation in relations:
                    target_key = (
                        relation.target_type,
                        relation.target_value,
                    )

                    if target_key in rejected_keys:
                        continue

                    relation_provenance = (
                        RelationProvenance(
                            plugin=result.plugin,
                            plugin_version=result.version,
                            observation_type=(
                                observation.type
                            ),
                            target=observation.target,
                            observed_at=result.timestamp,
                            observation_id=(
                                observation_id
                            ),
                            result_id=result_id,
                            result_file=(
                                result_path.name
                                if result_path is not None
                                else None
                            ),
                            result_sha256=(
                                result_sha256
                            ),
                        )
                    )

                    relation.provenance.append(
                        relation_provenance
                    )

                    self.relation_store.save(
                        relation
                    )

        return ProcessingResult(
            accepted=accepted,
            rejected=rejected,
        )
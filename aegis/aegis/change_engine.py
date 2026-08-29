from pathlib import Path

from aegis.asset_lifecycle import (
    AssetLifecycleManager,
)
from aegis.assessment import AssessmentContext
from aegis.change_detector import (
    detect_missing_active_services,
    detect_missing_dns_relations,
    detect_missing_exposes_relations,
    detect_missing_presents_relations,
)
from aegis.models import (
    AssetRelationType,
    AssetType,
    ChangeRecord,
)
from aegis.relation_lifecycle import (
    RelationLifecycleManager,
)
from aegis.results import (
    PluginResult,
)


class ChangeEngine:
    def __init__(
        self,
        context: AssessmentContext,
    ):
        self.context = context

        self.asset_lifecycle = (
            AssetLifecycleManager(
                context.assets,
                context.changes,
            )
        )

        self.relation_lifecycle = (
            RelationLifecycleManager(
                context.relations,
                context.changes,
            )
        )

    # -------------------------------------------------
    # INTERNAL HELPERS
    # -------------------------------------------------

    def _persist_asset_changes(
        self,
        changes: list[ChangeRecord],
        *,
        result_timestamp,
        saved_path: Path,
        previous_path: Path | None = None,
    ) -> list[ChangeRecord]:
        persisted: list[ChangeRecord] = []

        for change in changes:
            if previous_path is not None:
                change.previous_result = (
                    previous_path.name
                )

            change.current_result = (
                saved_path.name
            )

            change.detected_at = (
                result_timestamp
            )

            self.context.changes.save(
                change
            )

            persisted.append(
                change
            )

            inactive_change = (
                self.asset_lifecycle.process_missing(
                    change
                )
            )

            if inactive_change is not None:
                persisted.append(
                    inactive_change
                )

        return persisted

    def _persist_relation_changes(
        self,
        changes: list[ChangeRecord],
        *,
        result_timestamp,
        saved_path: Path,
        previous_path: Path | None = None,
    ) -> list[ChangeRecord]:
        persisted: list[ChangeRecord] = []

        for change in changes:
            if previous_path is not None:
                change.previous_result = (
                    previous_path.name
                )

            change.current_result = (
                saved_path.name
            )

            change.detected_at = (
                result_timestamp
            )

            self.context.changes.save(
                change
            )

            persisted.append(
                change
            )

            inactive_change = (
                self.relation_lifecycle.process_missing(
                    change
                )
            )

            if inactive_change is not None:
                persisted.append(
                    inactive_change
                )

        return persisted

    # -------------------------------------------------
    # PRE-PROCESSING
    # missing -> inactive
    # -------------------------------------------------

    def process_missing(
        self,
        result: PluginResult,
        *,
        saved_path: Path,
        previous_path: Path | None = None,
    ) -> list[ChangeRecord]:
        changes: list[ChangeRecord] = []

        # ---------------------------------------------
        # SERVICE
        # ---------------------------------------------

        if result.plugin == "service":
            asset_changes = (
                detect_missing_active_services(
                    result,
                    self.context.assets.find(),
                )
            )

            changes.extend(
                self._persist_asset_changes(
                    asset_changes,
                    result_timestamp=(
                        result.timestamp
                    ),
                    saved_path=saved_path,
                    previous_path=previous_path,
                )
            )

            exposes_changes = (
                detect_missing_exposes_relations(
                    result,
                    self.context.relations.find(),
                )
            )

            changes.extend(
                self._persist_relation_changes(
                    exposes_changes,
                    result_timestamp=(
                        result.timestamp
                    ),
                    saved_path=saved_path,
                    previous_path=previous_path,
                )
            )

        # ---------------------------------------------
        # DNS
        # ---------------------------------------------

        elif result.plugin == "dns":
            dns_changes = (
                detect_missing_dns_relations(
                    result,
                    self.context.relations.find(),
                )
            )

            changes.extend(
                self._persist_relation_changes(
                    dns_changes,
                    result_timestamp=(
                        result.timestamp
                    ),
                    saved_path=saved_path,
                    previous_path=previous_path,
                )
            )

        # ---------------------------------------------
        # TLS
        # ---------------------------------------------

        elif result.plugin == "tls":
            presents_changes = (
                detect_missing_presents_relations(
                    result,
                    self.context.relations.find(),
                )
            )

            changes.extend(
                self._persist_relation_changes(
                    presents_changes,
                    result_timestamp=(
                        result.timestamp
                    ),
                    saved_path=saved_path,
                    previous_path=previous_path,
                )
            )

        return changes

    # -------------------------------------------------
    # POST-PROCESSING
    # inactive -> reactivated
    # -------------------------------------------------

    def process_reactivated(
        self,
        result: PluginResult,
        *,
        processing,
        inactive_assets_before: set,
        inactive_relations_before: set,
        saved_path: Path,
        previous_path: Path | None = None,
    ) -> list[ChangeRecord]:
        changes: list[ChangeRecord] = []

        # ---------------------------------------------
        # SERVICE
        # ---------------------------------------------

        if result.plugin == "service":
            # -----------------------------------------
            # SERVICE ASSET REACTIVATION
            # -----------------------------------------

            for asset in processing.accepted:
                key = (
                    asset.type,
                    asset.value,
                )

                if (
                    key
                    not in inactive_assets_before
                ):
                    continue

                target = (
                    asset.provenance[-1].target
                    if asset.provenance
                    else asset.value
                )

                change = (
                    self.asset_lifecycle.build_reactivated(
                        asset=asset,
                        plugin="service",
                        target=target,
                        detected_at=(
                            result.timestamp
                        ),
                        previous_result=(
                            previous_path.name
                            if previous_path
                            is not None
                            else None
                        ),
                        current_result=(
                            saved_path.name
                        ),
                    )
                )

                self.context.changes.save(
                    change
                )

                changes.append(
                    change
                )

            # -----------------------------------------
            # EXPOSES RELATION REACTIVATION
            # -----------------------------------------

            changes.extend(
                self._process_reactivated_relations(
                    relation_type=(
                        AssetRelationType.EXPOSES
                    ),
                    plugin="service",
                    result_timestamp=(
                        result.timestamp
                    ),
                    inactive_relations_before=(
                        inactive_relations_before
                    ),
                    saved_path=saved_path,
                    previous_path=previous_path,
                )
            )

        # ---------------------------------------------
        # DNS
        # ---------------------------------------------

        elif result.plugin == "dns":
            changes.extend(
                self._process_reactivated_relations(
                    relation_type=(
                        AssetRelationType.RESOLVES_TO
                    ),
                    plugin="dns",
                    result_timestamp=(
                        result.timestamp
                    ),
                    inactive_relations_before=(
                        inactive_relations_before
                    ),
                    saved_path=saved_path,
                    previous_path=previous_path,
                )
            )

        # ---------------------------------------------
        # TLS
        # ---------------------------------------------

        elif result.plugin == "tls":
            changes.extend(
                self._process_reactivated_relations(
                    relation_type=(
                        AssetRelationType.PRESENTS
                    ),
                    plugin="tls",
                    result_timestamp=(
                        result.timestamp
                    ),
                    inactive_relations_before=(
                        inactive_relations_before
                    ),
                    saved_path=saved_path,
                    previous_path=previous_path,
                )
            )

        return changes

    def _process_reactivated_relations(
        self,
        *,
        relation_type: AssetRelationType,
        plugin: str,
        result_timestamp,
        inactive_relations_before: set,
        saved_path: Path,
        previous_path: Path | None = None,
    ) -> list[ChangeRecord]:
        changes: list[ChangeRecord] = []

        for relation in (
            self.context.relations.find()
        ):
            key = (
                relation.source_type,
                relation.source_value,
                relation.relation,
                relation.target_type,
                relation.target_value,
            )

            if (
                key
                not in inactive_relations_before
            ):
                continue

            if not relation.active:
                continue

            if (
                relation.relation
                != relation_type
            ):
                continue

            if (
                relation.source_type
                == AssetType.SERVICE
            ):
                target = (
                    relation.source_value.rsplit(
                        ":",
                        1,
                    )[0]
                )
            else:
                target = (
                    relation.source_value
                )

            change = (
                self.relation_lifecycle.build_reactivated(
                    relation=relation,
                    plugin=plugin,
                    target=target,
                    detected_at=(
                        result_timestamp
                    ),
                    previous_result=(
                        previous_path.name
                        if previous_path
                        is not None
                        else None
                    ),
                    current_result=(
                        saved_path.name
                    ),
                )
            )

            self.context.changes.save(
                change
            )

            changes.append(
                change
            )

        return changes
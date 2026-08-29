from aegis.change_state import (
    should_mark_relation_inactive,
)
from aegis.change_store import ChangeStore
from aegis.models import (
    AssetRelation,
    ChangeRecord,
    ChangeType,
)
from aegis.relation_store import (
    RelationStore,
)


class RelationLifecycleManager:
    def __init__(
        self,
        relation_store: RelationStore,
        change_store: ChangeStore,
        threshold: int = 2,
    ):
        self.relation_store = relation_store
        self.change_store = change_store
        self.threshold = threshold

    def process_missing(
        self,
        change: ChangeRecord,
    ) -> ChangeRecord | None:
        """
        Process one relation CANDIDATE_MISSING.

        Returns an INACTIVE ChangeRecord when
        the threshold is reached.
        """

        if (
            change.change_type
            != ChangeType.CANDIDATE_MISSING
        ):
            return None

        if (
            change.relation_type is None
            or change.source_type is None
            or change.source_value is None
            or change.target_type is None
            or change.target_value is None
        ):
            return None

        relation = self._find_relation(
            change
        )

        if relation is None:
            return None

        if not relation.active:
            return None

        if not should_mark_relation_inactive(
            self.change_store,
            change.relation_type,
            change.source_type,
            change.source_value,
            change.target_type,
            change.target_value,
            relation.last_confirmed,
            threshold=self.threshold,
        ):
            return None

        updated = (
            self.relation_store.set_active(
                change.source_type,
                change.source_value,
                change.relation_type,
                change.target_type,
                change.target_value,
                False,
            )
        )

        if updated is None:
            return None

        inactive_change = ChangeRecord(
            change_type=(
                ChangeType.INACTIVE
            ),
            relation_type=(
                change.relation_type
            ),
            source_type=(
                change.source_type
            ),
            source_value=(
                change.source_value
            ),
            target_type=(
                change.target_type
            ),
            target_value=(
                change.target_value
            ),
            plugin=change.plugin,
            target=change.target,
            detected_at=change.detected_at,
            previous_result=(
                change.previous_result
            ),
            current_result=(
                change.current_result
            ),
        )

        self.change_store.save(
            inactive_change
        )

        return inactive_change

    def build_reactivated(
        self,
        relation: AssetRelation,
        plugin: str,
        target: str,
        detected_at,
        current_result: str,
        previous_result: str | None = None,
    ) -> ChangeRecord:
        return ChangeRecord(
            change_type=(
                ChangeType.REACTIVATED
            ),
            relation_type=(
                relation.relation
            ),
            source_type=(
                relation.source_type
            ),
            source_value=(
                relation.source_value
            ),
            target_type=(
                relation.target_type
            ),
            target_value=(
                relation.target_value
            ),
            plugin=plugin,
            target=target,
            detected_at=detected_at,
            previous_result=previous_result,
            current_result=current_result,
        )

    def _find_relation(
        self,
        change: ChangeRecord,
    ) -> AssetRelation | None:
        for relation in (
            self.relation_store.find()
        ):
            if (
                relation.relation
                == change.relation_type
                and relation.source_type
                == change.source_type
                and relation.source_value
                == change.source_value
                and relation.target_type
                == change.target_type
                and relation.target_value
                == change.target_value
            ):
                return relation

        return None
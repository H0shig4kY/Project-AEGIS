from aegis.change_state import (
    should_mark_inactive,
)
from aegis.change_store import ChangeStore
from aegis.asset_store import AssetStore
from aegis.models import (
    Asset,
    ChangeRecord,
    ChangeType,
)


class AssetLifecycleManager:
    def __init__(
        self,
        asset_store: AssetStore,
        change_store: ChangeStore,
        threshold: int = 2,
    ):
        self.asset_store = asset_store
        self.change_store = change_store
        self.threshold = threshold

    def process_missing(
        self,
        change: ChangeRecord,
    ) -> ChangeRecord | None:
        """
        Process one asset CANDIDATE_MISSING.

        Returns an INACTIVE ChangeRecord when
        the threshold is reached.
        """

        if (
            change.change_type
            != ChangeType.CANDIDATE_MISSING
        ):
            return None

        if (
            change.asset_type is None
            or change.asset_value is None
        ):
            return None

        asset = self._find_asset(
            change
        )

        if asset is None:
            return None

        if not asset.active:
            return None

        if not should_mark_inactive(
            self.change_store,
            change.asset_type,
            change.asset_value,
            asset.last_confirmed,
            threshold=self.threshold,
        ):
            return None

        updated = (
            self.asset_store.set_active(
                change.asset_type,
                change.asset_value,
                False,
            )
        )

        if updated is None:
            return None

        inactive_change = ChangeRecord(
            change_type=(
                ChangeType.INACTIVE
            ),
            asset_type=(
                change.asset_type
            ),
            asset_value=(
                change.asset_value
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
        asset: Asset,
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
            asset_type=asset.type,
            asset_value=asset.value,
            plugin=plugin,
            target=target,
            detected_at=detected_at,
            previous_result=previous_result,
            current_result=current_result,
        )

    def _find_asset(
        self,
        change: ChangeRecord,
    ) -> Asset | None:
        for asset in self.asset_store.find(
            asset_type=change.asset_type,
        ):
            if (
                asset.value
                == change.asset_value
            ):
                return asset

        return None
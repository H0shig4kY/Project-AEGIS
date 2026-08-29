from datetime import datetime

from aegis.change_store import ChangeStore
from aegis.models import (
    AssetType,
    ChangeType,
    AssetRelationType,
)


def count_missing_since_confirmation(
    store: ChangeStore,
    asset_type: AssetType,
    asset_value: str,
    last_confirmed: datetime | None,
) -> int:
    changes = store.find(
        asset_type=asset_type,
        asset_value=asset_value,
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
    )

    if last_confirmed is None:
        return len(changes)

    return sum(
        1
        for change in changes
        if change.detected_at
        > last_confirmed
    )


def should_mark_inactive(
    store: ChangeStore,
    asset_type: AssetType,
    asset_value: str,
    last_confirmed: datetime | None,
    threshold: int = 2,
) -> bool:
    return (
        count_missing_since_confirmation(
            store,
            asset_type,
            asset_value,
            last_confirmed,
        )
        >= threshold
    )

def count_relation_missing_since_confirmation(
    store: ChangeStore,
    relation_type: AssetRelationType,
    source_type: AssetType,
    source_value: str,
    target_type: AssetType,
    target_value: str,
    last_confirmed: datetime | None,
) -> int:
    changes = store.find(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        relation_type=relation_type,
        source_type=source_type,
        source_value=source_value,
        target_type=target_type,
        target_value=target_value,
    )

    if last_confirmed is None:
        return len(changes)

    return sum(
        1
        for change in changes
        if change.detected_at > last_confirmed
    )


def should_mark_relation_inactive(
    store: ChangeStore,
    relation_type: AssetRelationType,
    source_type: AssetType,
    source_value: str,
    target_type: AssetType,
    target_value: str,
    last_confirmed: datetime | None,
    threshold: int = 2,
) -> bool:
    return (
        count_relation_missing_since_confirmation(
            store,
            relation_type,
            source_type,
            source_value,
            target_type,
            target_value,
            last_confirmed,
        )
        >= threshold
    )
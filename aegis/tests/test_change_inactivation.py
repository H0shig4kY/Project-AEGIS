from datetime import (
    datetime,
    timedelta,
    timezone,
)

from aegis.asset_store import AssetStore
from aegis.change_state import (
    should_mark_inactive,
)
from aegis.change_store import ChangeStore
from aegis.models import (
    Asset,
    AssetType,
    ChangeRecord,
    ChangeType,
)


def make_missing(
    detected_at: datetime,
    current_result: str,
) -> ChangeRecord:
    return ChangeRecord(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
        plugin="service",
        target="example.com",
        current_result=current_result,
        detected_at=detected_at,
    )


def test_service_becomes_inactive_after_two_missing(
    tmp_path,
):
    asset_store = AssetStore(
        tmp_path / "assets"
    )

    change_store = ChangeStore(
        tmp_path / "changes"
    )

    confirmed_at = datetime(
        2026,
        8,
        27,
        10,
        0,
        tzinfo=timezone.utc,
    )

    # Serviço conhecido e anteriormente
    # confirmado.
    asset = Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
        first_seen=confirmed_at,
        last_seen=confirmed_at,
        last_confirmed=confirmed_at,
        seen_count=1,
        active=True,
    )

    asset_store.save(asset)

    # O save() pode atualizar lifecycle,
    # portanto usamos o estado persistido.
    stored_asset = asset_store.find(
        asset_type=AssetType.SERVICE,
    )[0]

    last_confirmed = (
        stored_asset.last_confirmed
    )

    assert last_confirmed is not None
    assert stored_asset.active is True

    # Primeira ausência.
    first_missing = make_missing(
        detected_at=(
            last_confirmed
            + timedelta(minutes=5)
        ),
        current_result="service-2.json",
    )

    change_store.save(
        first_missing
    )

    assert (
        should_mark_inactive(
            change_store,
            AssetType.SERVICE,
            "example.com:80",
            last_confirmed,
        )
        is False
    )

    # O asset continua ativo após
    # uma única ausência.
    current_asset = asset_store.find(
        asset_type=AssetType.SERVICE,
    )[0]

    assert current_asset.active is True

    # Segunda ausência consecutiva.
    second_missing = make_missing(
        detected_at=(
            last_confirmed
            + timedelta(minutes=10)
        ),
        current_result="service-3.json",
    )

    change_store.save(
        second_missing
    )

    assert (
        should_mark_inactive(
            change_store,
            AssetType.SERVICE,
            "example.com:80",
            last_confirmed,
        )
        is True
    )

    # Promoção para inactive.
    updated = asset_store.set_active(
        AssetType.SERVICE,
        "example.com:80",
        False,
    )

    assert updated is not None
    assert updated.active is False

    # Regista também o evento histórico.
    inactive_change = (
        second_missing.model_copy(
            update={
                "change_type": (
                    ChangeType.INACTIVE
                ),
            }
        )
    )

    change_store.save(
        inactive_change
    )

    # Confirma estado persistido.
    persisted_asset = asset_store.find(
        asset_type=AssetType.SERVICE,
    )[0]

    assert persisted_asset.active is False

    # Confirma histórico de mudança.
    inactive_changes = change_store.find(
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
        change_type=ChangeType.INACTIVE,
    )

    assert len(inactive_changes) == 1

    inactive = inactive_changes[0]

    assert (
        inactive.change_type
        == ChangeType.INACTIVE
    )

    assert (
        inactive.asset_type
        == AssetType.SERVICE
    )

    assert (
        inactive.asset_value
        == "example.com:80"
    )
from aegis.change_store import (
    ChangeStore,
)
from aegis.models import (
    AssetType,
    ChangeRecord,
    ChangeType,
    AssetRelationType,
)


def make_change() -> ChangeRecord:
    return ChangeRecord(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
        plugin="service",
        target="example.com",
        previous_result=(
            "service-previous.json"
        ),
        current_result=(
            "service-current.json"
        ),
    )


def test_change_store_saves_change(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    change = make_change()

    path = store.save(
        change
    )

    assert path.exists()
    assert path.is_file()


def test_change_store_loads_change(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    original = make_change()

    path = store.save(
        original
    )

    loaded = store.load(
        path
    )

    assert loaded == original


def test_change_store_save_is_idempotent(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    change = make_change()

    first_path = store.save(
        change
    )

    second_path = store.save(
        change
    )

    assert first_path == second_path

    assert len(
        store.list()
    ) == 1


def test_change_store_find(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    store.save(
        make_change()
    )

    matches = store.find(
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
    )

    assert len(matches) == 1

    assert (
        matches[0].asset_value
        == "example.com:80"
    )

def test_change_store_find_relation_change(
    tmp_path,
):
    store = ChangeStore(
        tmp_path / "changes"
    )

    change = ChangeRecord(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        relation_type=(
            AssetRelationType.RESOLVES_TO
        ),
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        target_type=AssetType.IP,
        target_value="192.0.2.10",
        plugin="dns",
        target="example.com",
    )

    store.save(
        change
    )

    matches = store.find(
        change_type=(
            ChangeType.CANDIDATE_MISSING
        ),
        relation_type=(
            AssetRelationType.RESOLVES_TO
        ),
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        target_type=AssetType.IP,
        target_value="192.0.2.10",
    )

    assert len(matches) == 1

    stored = matches[0]

    assert (
        stored.relation_type
        == AssetRelationType.RESOLVES_TO
    )

    assert (
        stored.source_value
        == "example.com"
    )

    assert (
        stored.target_value
        == "192.0.2.10"
    )
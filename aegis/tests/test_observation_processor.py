from pathlib import Path

from aegis.asset_store import AssetStore
from aegis.models import AssetType
from aegis.observation_processor import ObservationProcessor
from aegis.results import Observation, PluginResult
from aegis.scope import ScopeEngine

def create_result() -> PluginResult:
    return PluginResult(
        plugin="dns",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="dns_resolution",
                data={
                    "addresses": [
                        "192.0.2.10",
                        "192.0.2.11",
                    ]
                },
            )
        ],
    )

def create_scope() -> ScopeEngine:
    scope = ScopeEngine()

    scope.add("example.com")
    scope.add("192.0.2.0/24")

    return scope

def test_process_creates_assets(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    processor = ObservationProcessor(
        asset_store=store,
        scope=create_scope(),
    )

    processing = processor.process(
        create_result()
    )

    assets = processing.accepted

    assert processing.discovered_count == 3
    assert processing.accepted_count == 3
    assert processing.rejected_count == 0

    assert len(assets) == 3

    assert assets[0].value == "example.com"
    assert assets[0].type == AssetType.DOMAIN

    assert assets[1].value == "192.0.2.10"
    assert assets[1].type == AssetType.IP

    assert assets[2].value == "192.0.2.11"
    assert assets[2].type == AssetType.IP

def test_process_persists_assets(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    processor = ObservationProcessor(
        asset_store=store,
        scope=create_scope(),
    )

    processing = processor.process(
        create_result()
    )

    stored = store.list()

    assert processing.accepted_count == 3
    assert processing.rejected_count == 0
    assert len(stored) == 3

def test_process_is_idempotent(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    processor = ObservationProcessor(
        asset_store=store,
        scope=create_scope(),
    )

    result = create_result()

    first = processor.process(result)
    second = processor.process(result)

    stored = store.list()

    assert first.accepted_count == 3
    assert second.accepted_count == 3

    # AssetStore deduplicates by asset

def test_process_adds_provenance(tmp_path: Path):
    store = AssetStore(
        tmp_path / "assets"
    )

    processor = ObservationProcessor(
        asset_store=store,
        scope=create_scope(),
    )

    result_path = (
        tmp_path
        / "dns-20260822-test.json"
    )

    processing = processor.process(
        create_result(),
        result_path=result_path,
    )

    asset = processing.accepted[0]

    assert len(asset.provenance) == 1

    provenance = asset.provenance[0]

    assert provenance.plugin == "dns"
    assert provenance.plugin_version == "0.1.0"
    assert (
        provenance.observation_type
        == "dns_resolution"
    )
    assert provenance.target == "example.com"
    assert (
        provenance.result_file
        == "dns-20260822-test.json"
    )

def test_process_stores_result_sha256(
    tmp_path,
):
    store = AssetStore(
        tmp_path / "assets"
    )

    processor = ObservationProcessor(
        asset_store=store,
        scope=create_scope(),
    )

    processing = processor.process(
        create_result(),
        result_path=(
            tmp_path / "dns-test.json"
        ),
        result_sha256="a" * 64,
    )

    asset = processing.accepted[0]

    assert (
        asset.provenance[0].result_sha256
        == "a" * 64
    )
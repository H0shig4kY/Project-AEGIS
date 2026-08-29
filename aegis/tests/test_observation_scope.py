from aegis.asset_store import AssetStore
from aegis.models import AssetType
from aegis.observation_processor import ObservationProcessor
from aegis.results import (
    Observation,
    PluginResult,
    RejectionReason,
)
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
                        "93.184.216.34",
                        "10.10.10.10",
                    ]
                },
            )
        ],
    )

def test_processor_only_stores_in_scope_assets(tmp_path):
    store = AssetStore(tmp_path)
    scope = ScopeEngine()

    scope.add("example.com")

    processor = ObservationProcessor(
        asset_store=store,
        scope=scope,
    )

    processing = processor.process(
        create_result()
    )

    assert processing.discovered_count == 3
    assert processing.accepted_count == 1
    assert processing.rejected_count == 2

    assert processing.accepted[0].value == "example.com"
    assert processing.accepted[0].type == AssetType.DOMAIN

    rejected_values = [
        item.asset.value
        for item in processing.rejected
    ]

    rejected_reasons = [
        item.reason
        for item in processing.rejected
    ]

    assert "93.184.216.34" in rejected_values
    assert "10.10.10.10" in rejected_values

    assert all(
        reason == RejectionReason.OUTSIDE_SCOPE
        for reason in rejected_reasons
    )

    stored = store.find()

    assert len(stored) == 1
    assert stored[0].value == "example.com"

def test_processor_rejects_out_of_scope_domain(tmp_path):
    store = AssetStore(tmp_path)
    scope = ScopeEngine()

    scope.add("example.com")

    result = PluginResult(
        plugin="dns",
        version="0.1.0",
        observations=[
            Observation(
                target="evil.com",
                type="dns_resolution",
                data={
                    "addresses": [],
                },
            )
        ],
    )

    processor = ObservationProcessor(
        asset_store=store,
        scope=scope,
    )

    processing = processor.process(result)

    assert processing.discovered_count == 1
    assert processing.accepted_count == 0
    assert processing.rejected_count == 1

    assert processing.accepted == []

    assert processing.rejected[0].asset.value == "evil.com"
    assert (
        processing.rejected[0].reason
        == RejectionReason.OUTSIDE_SCOPE
    )

    assert store.find() == []

def test_processor_allows_ip_inside_cidr(tmp_path):
    store = AssetStore(tmp_path)
    scope = ScopeEngine()

    scope.add("192.168.1.0/24")

    result = PluginResult(
        plugin="dns",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="dns_resolution",
                data={
                    "addresses": [
                        "192.168.1.50",
                        "192.168.2.50",
                    ],
                },
            )
        ],
    )

    processor = ObservationProcessor(
        asset_store=store,
        scope=scope,
    )

    processing = processor.process(result)

    accepted_values = [
        asset.value
        for asset in processing.accepted
    ]

    rejected_values = [
        item.asset.value
        for item in processing.rejected
    ]

    rejected_reasons = [
        item.reason
        for item in processing.rejected
    ]

    assert processing.discovered_count == 3
    assert processing.accepted_count == 1
    assert processing.rejected_count == 2

    assert "192.168.1.50" in accepted_values

    assert "example.com" in rejected_values
    assert "192.168.2.50" in rejected_values

    assert all(
        reason == RejectionReason.OUTSIDE_SCOPE
        for reason in rejected_reasons
    )

    stored = store.find()

    assert len(stored) == 1
    assert stored[0].value == "192.168.1.50"
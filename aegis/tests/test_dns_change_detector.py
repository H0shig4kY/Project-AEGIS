from aegis.change_detector import (
    detect_missing_dns_relations,
)
from aegis.models import (
    AssetRelation,
    AssetRelationType,
    AssetType,
    ChangeType,
    CoverageType,
    ExecutionCoverage,
)
from aegis.results import (
    Observation,
    PluginResult,
)


def make_dns_result(
    addresses: list[str],
) -> PluginResult:
    return PluginResult(
        plugin="dns",
        version="0.1.0",
        observations=[
            Observation(
                target="example.com",
                type="dns_resolution",
                data={
                    "addresses": addresses,
                },
            )
        ],
        coverage=[
            ExecutionCoverage(
                plugin="dns",
                target="example.com",
                coverage_type=(
                    CoverageType.DNS
                ),
            )
        ],
    )


def make_relation(
    address: str,
    active: bool = True,
) -> AssetRelation:
    return AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=(
            AssetRelationType.RESOLVES_TO
        ),
        target_type=AssetType.IP,
        target_value=address,
        active=active,
    )


def test_dns_missing_relation_is_detected():
    current = make_dns_result(
        addresses=[
            "192.0.2.20",
        ]
    )

    relation = make_relation(
        "192.0.2.10"
    )

    changes = detect_missing_dns_relations(
        current,
        [relation],
    )

    assert len(changes) == 1

    change = changes[0]

    assert (
        change.change_type
        == ChangeType.CANDIDATE_MISSING
    )

    assert (
        change.relation_type
        == AssetRelationType.RESOLVES_TO
    )

    assert (
        change.source_type
        == AssetType.DOMAIN
    )

    assert (
        change.source_value
        == "example.com"
    )

    assert (
        change.target_type
        == AssetType.IP
    )

    assert (
        change.target_value
        == "192.0.2.10"
    )

    assert change.plugin == "dns"
    assert change.target == "example.com"


def test_dns_present_relation_is_not_missing():
    current = make_dns_result(
        addresses=[
            "192.0.2.10",
        ]
    )

    relation = make_relation(
        "192.0.2.10"
    )

    changes = detect_missing_dns_relations(
        current,
        [relation],
    )

    assert changes == []


def test_dns_inactive_relation_is_ignored():
    current = make_dns_result(
        addresses=[]
    )

    relation = make_relation(
        "192.0.2.10",
        active=False,
    )

    changes = detect_missing_dns_relations(
        current,
        [relation],
    )

    assert changes == []


def test_dns_relation_outside_coverage_is_ignored():
    current = PluginResult(
        plugin="dns",
        version="0.1.0",
        observations=[
            Observation(
                target="other.example.com",
                type="dns_resolution",
                data={
                    "addresses": [],
                },
            )
        ],
        coverage=[
            ExecutionCoverage(
                plugin="dns",
                target="other.example.com",
                coverage_type=(
                    CoverageType.DNS
                ),
            )
        ],
    )

    relation = make_relation(
        "192.0.2.10"
    )

    changes = detect_missing_dns_relations(
        current,
        [relation],
    )

    assert changes == []
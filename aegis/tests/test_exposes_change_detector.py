from aegis.change_detector import (
    detect_missing_exposes_relations,
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


def make_service_result(
    observations: list[Observation],
    ports: list[int],
) -> PluginResult:
    return PluginResult(
        plugin="service",
        version="0.1.0",
        observations=observations,
        coverage=[
            ExecutionCoverage(
                plugin="service",
                target="example.com",
                coverage_type=(
                    CoverageType.SERVICE
                ),
                ports=ports,
            )
        ],
    )


def make_exposes_relation(
    service_value: str,
    active: bool = True,
) -> AssetRelation:
    return AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=(
            AssetRelationType.EXPOSES
        ),
        target_type=AssetType.SERVICE,
        target_value=service_value,
        active=active,
    )


def test_missing_exposes_relation_is_detected():
    current = make_service_result(
        observations=[],
        ports=[
            80,
            443,
        ],
    )

    relation = make_exposes_relation(
        "example.com:80"
    )

    changes = (
        detect_missing_exposes_relations(
            current,
            [relation],
        )
    )

    assert len(changes) == 1

    change = changes[0]

    assert (
        change.change_type
        == ChangeType.CANDIDATE_MISSING
    )

    assert (
        change.relation_type
        == AssetRelationType.EXPOSES
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
        == AssetType.SERVICE
    )

    assert (
        change.target_value
        == "example.com:80"
    )

    assert (
        change.plugin
        == "service"
    )

    assert (
        change.target
        == "example.com"
    )


def test_present_exposes_relation_is_not_missing():
    current = make_service_result(
        observations=[
            Observation(
                target="example.com",
                type="service_open",
                data={
                    "host": "example.com",
                    "port": 80,
                },
            )
        ],
        ports=[
            80,
            443,
        ],
    )

    relation = make_exposes_relation(
        "example.com:80"
    )

    changes = (
        detect_missing_exposes_relations(
            current,
            [relation],
        )
    )

    assert changes == []


def test_inactive_exposes_relation_is_ignored():
    current = make_service_result(
        observations=[],
        ports=[
            80,
            443,
        ],
    )

    relation = make_exposes_relation(
        "example.com:80",
        active=False,
    )

    changes = (
        detect_missing_exposes_relations(
            current,
            [relation],
        )
    )

    assert changes == []


def test_exposes_relation_outside_coverage_is_ignored():
    current = make_service_result(
        observations=[],
        ports=[
            443,
        ],
    )

    relation = make_exposes_relation(
        "example.com:80"
    )

    changes = (
        detect_missing_exposes_relations(
            current,
            [relation],
        )
    )

    assert changes == []
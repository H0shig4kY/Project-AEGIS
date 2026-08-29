from aegis.change_detector import (
    detect_missing_presents_relations,
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


CERT_A = "a" * 64
CERT_B = "b" * 64


def make_tls_result(
    certificate: str | None,
) -> PluginResult:
    observations = []

    if certificate is not None:
        observations.append(
            Observation(
                target="example.com",
                type="tls_handshake",
                data={
                    "host": "example.com",
                    "port": 443,
                    "certificate_sha256": (
                        certificate
                    ),
                },
            )
        )

    return PluginResult(
        plugin="tls",
        version="0.1.0",
        observations=observations,
        coverage=[
            ExecutionCoverage(
                plugin="tls",
                target="example.com",
                coverage_type=(
                    CoverageType.TLS
                ),
            )
        ],
    )


def make_presents_relation(
    certificate: str,
    active: bool = True,
) -> AssetRelation:
    return AssetRelation(
        source_type=(
            AssetType.SERVICE
        ),
        source_value=(
            "example.com:443"
        ),
        relation=(
            AssetRelationType.PRESENTS
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=(
            certificate
        ),
        active=active,
    )


def test_missing_presents_relation_is_detected():
    current = make_tls_result(
        CERT_B
    )

    relation = make_presents_relation(
        CERT_A
    )

    changes = (
        detect_missing_presents_relations(
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
        == AssetRelationType.PRESENTS
    )

    assert (
        change.source_type
        == AssetType.SERVICE
    )

    assert (
        change.source_value
        == "example.com:443"
    )

    assert (
        change.target_type
        == AssetType.CERTIFICATE
    )

    assert (
        change.target_value
        == CERT_A
    )

    assert change.plugin == "tls"
    assert change.target == "example.com"


def test_present_presents_relation_is_not_missing():
    current = make_tls_result(
        CERT_A
    )

    relation = make_presents_relation(
        CERT_A
    )

    changes = (
        detect_missing_presents_relations(
            current,
            [relation],
        )
    )

    assert changes == []


def test_inactive_presents_relation_is_ignored():
    current = make_tls_result(
        None
    )

    relation = make_presents_relation(
        CERT_A,
        active=False,
    )

    changes = (
        detect_missing_presents_relations(
            current,
            [relation],
        )
    )

    assert changes == []


def test_presents_relation_outside_coverage_is_ignored():
    current = PluginResult(
        plugin="tls",
        version="0.1.0",
        observations=[],
        coverage=[
            ExecutionCoverage(
                plugin="tls",
                target="other.example.com",
                coverage_type=(
                    CoverageType.TLS
                ),
            )
        ],
    )

    relation = make_presents_relation(
        CERT_A
    )

    changes = (
        detect_missing_presents_relations(
            current,
            [relation],
        )
    )

    assert changes == []
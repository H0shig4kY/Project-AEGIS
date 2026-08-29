from aegis.models import (
    AssetRelationType,
    AssetType,
)
from aegis.relation_extractor import (
    relations_from_observation,
)
from aegis.results import Observation


def test_dns_observation_creates_relation():
    observation = Observation(
        target="example.com",
        type="dns_resolution",
        data={
            "addresses": [
                "192.0.2.10",
            ],
        },
    )

    relations = relations_from_observation(
        observation
    )

    assert len(relations) == 1

    relation = relations[0]

    assert (
        relation.source_type
        == AssetType.DOMAIN
    )
    assert (
        relation.source_value
        == "example.com"
    )
    assert (
        relation.relation
        == AssetRelationType.RESOLVES_TO
    )
    assert (
        relation.target_type
        == AssetType.IP
    )
    assert (
        relation.target_value
        == "192.0.2.10"
    )


def test_service_observation_creates_relation():
    observation = Observation(
        target="example.com",
        type="service_open",
        data={
            "host": "example.com",
            "port": 443,
        },
    )

    relations = relations_from_observation(
        observation
    )

    assert len(relations) == 1

    relation = relations[0]

    assert (
        relation.relation
        == AssetRelationType.EXPOSES
    )

    assert (
        relation.target_value
        == "example.com:443"
    )


def test_tls_observation_creates_relation():
    observation = Observation(
        target="example.com",
        type="tls_handshake",
        data={
            "host": "example.com",
            "port": 443,
            "certificate_sha256": (
                "a" * 64
            ),
        },
    )

    relations = relations_from_observation(
        observation
    )

    assert len(relations) == 1

    relation = relations[0]

    assert (
        relation.source_type
        == AssetType.SERVICE
    )

    assert (
        relation.source_value
        == "example.com:443"
    )

    assert (
        relation.relation
        == AssetRelationType.PRESENTS
    )

    assert (
        relation.target_type
        == AssetType.CERTIFICATE
    )

    assert (
        relation.target_value
        == "a" * 64
    )
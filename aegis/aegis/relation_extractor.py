from aegis.models import (
    AssetRelation,
    AssetRelationType,
    AssetType,
)
from aegis.results import Observation


def relations_from_observation(
    observation: Observation,
) -> list[AssetRelation]:
    relations: list[AssetRelation] = []

    if observation.type == "dns_resolution":
        domain = observation.target

        for address in observation.data.get(
            "addresses",
            [],
        ):
            relations.append(
                AssetRelation(
                    source_type=AssetType.DOMAIN,
                    source_value=domain,
                    relation=(
                        AssetRelationType.RESOLVES_TO
                    ),
                    target_type=AssetType.IP,
                    target_value=address,
                )
            )

    if observation.type == "service_open":
        host = observation.data.get("host")
        port = observation.data.get("port")

        if host and port is not None:
            try:
                import ipaddress

                ipaddress.ip_address(host)
                source_type = AssetType.IP

            except ValueError:
                source_type = AssetType.DOMAIN

            relations.append(
                AssetRelation(
                    source_type=source_type,
                    source_value=host,
                    relation=(
                        AssetRelationType.EXPOSES
                    ),
                    target_type=AssetType.SERVICE,
                    target_value=f"{host}:{port}",
                )
            )

    if observation.type == "tls_handshake":
        host = observation.data.get("host")
        port = observation.data.get("port")

        certificate_sha256 = (
            observation.data.get(
                "certificate_sha256"
            )
        )

        if (
            host
            and port is not None
            and certificate_sha256
        ):
            relations.append(
                AssetRelation(
                    source_type=AssetType.SERVICE,
                    source_value=f"{host}:{port}",
                    relation=(
                        AssetRelationType.PRESENTS
                    ),
                    target_type=(
                        AssetType.CERTIFICATE
                    ),
                    target_value=(
                        certificate_sha256
                    ),
                )
            )

    return relations
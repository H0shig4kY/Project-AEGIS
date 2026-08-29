from aegis.models import (
    Asset,
    AssetType,
    CertificateMetadata,
    FingerprintConfidence,
    FingerprintSource,
    ServiceMetadata,
    TLSMetadata,
)

from aegis.results import Observation

def assets_from_observation(
    observation: Observation,
) -> list[Asset]:
    assets: list[Asset] = []

    if observation.type == "dns_resolution":
        assets.append(
            Asset(
                value=observation.target,
                type=AssetType.DOMAIN,
                source="dns",
            )
        )

        for address in observation.data.get(
            "addresses",
            [],
        ):
            assets.append(
                Asset(
                    value=address,
                    type=AssetType.IP,
                    source="dns",
                )
            )

    if observation.type == "http_probe":
        url = observation.data.get("url")

        if url:
            assets.append(
                Asset(
                    value=url,
                    type=AssetType.URL,
                    source="http",
                )
            )

    if observation.type == "service_open":
        host = observation.data.get("host")
        port = observation.data.get("port")

        if host and port is not None:
            metadata = ServiceMetadata(
                host=host,
                port=port,
                transport=observation.data.get(
                    "transport",
                    "tcp",
                ),
                service_name=observation.data.get(
                    "service_name",
                    "unknown",
                ),
                tls=observation.data.get(
                    "tls",
                    False,
                ),
                banner=observation.data.get(
                    "banner"
                ),
                product=observation.data.get(
                    "product"
                ),
                version=observation.data.get(
                    "version"
                ),
                confidence=observation.data.get(
                    "confidence",
                    FingerprintConfidence.MEDIUM,
                ),
                fingerprint_source=observation.data.get(
                    "fingerprint_source",
                    FingerprintSource.PORT,
                ),
            )

            assets.append(
                Asset(
                    value=f"{host}:{port}",
                    type=AssetType.SERVICE,
                    source="service",
                    metadata=metadata.model_dump(),
                )
            )

    if observation.type == "tls_handshake":
        host = observation.data.get("host")
        port = observation.data.get("port")

        if host and port is not None:
            tls_metadata = TLSMetadata(
                host=host,
                port=port,
                transport="tcp",
                tls=True,
                tls_version=observation.data.get(
                    "tls_version"
                ),
                cipher=observation.data.get(
                    "cipher"
                ),
                certificate_subject=observation.data.get(
                    "subject"
                ),
                certificate_issuer=observation.data.get(
                    "issuer"
                ),
                certificate_valid_from=observation.data.get(
                    "valid_from"
                ),
                certificate_valid_to=observation.data.get(
                    "valid_to"
                ),
                certificate_sans=observation.data.get(
                    "sans",
                    [],
                ),
                certificate_sha256=observation.data.get(
                    "certificate_sha256"
                ),
            )

            assets.append(
                Asset(
                    value=f"{host}:{port}",
                    type=AssetType.SERVICE,
                    source="tls",
                    metadata=tls_metadata.model_dump(),
                )
            )

            certificate_sha256 = observation.data.get(
                "certificate_sha256"
            )

            if certificate_sha256:
                certificate_metadata = (
                    CertificateMetadata(
                        host=host,
                        port=port,
                        subject=observation.data.get(
                            "subject"
                        ),
                        issuer=observation.data.get(
                            "issuer"
                        ),
                        valid_from=observation.data.get(
                            "valid_from"
                        ),
                        valid_to=observation.data.get(
                            "valid_to"
                        ),
                        sans=observation.data.get(
                            "sans",
                            [],
                        ),
                        sha256=certificate_sha256,
                        presented_by=(
                            f"{host}:{port}"
                        ),
                    )
                )

                assets.append(
                    Asset(
                        value=certificate_sha256,
                        type=AssetType.CERTIFICATE,
                        source="tls",
                        metadata=(
                            certificate_metadata.model_dump()
                        ),
                    )
                )

    return assets
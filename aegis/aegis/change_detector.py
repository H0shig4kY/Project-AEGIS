from aegis.models import (
    AssetType,
    AssetRelation,
    AssetRelationType,
    ChangeRecord,
    ChangeType,
    CoverageType,
    Asset,
)
from aegis.results import PluginResult


def detect_service_changes(
    previous: PluginResult,
    current: PluginResult,
) -> list[ChangeRecord]:
    changes: list[ChangeRecord] = []

    previous_coverage = {
        (
            item.target,
            tuple(item.ports),
        )
        for item in previous.coverage
        if (
            item.coverage_type
            == CoverageType.SERVICE
        )
    }

    current_coverage = {
        (
            item.target,
            tuple(item.ports),
        )
        for item in current.coverage
        if (
            item.coverage_type
            == CoverageType.SERVICE
        )
    }

    comparable = (
        previous_coverage
        & current_coverage
    )

    previous_services = {
        (
            observation.data.get("host"),
            observation.data.get("port"),
        )
        for observation
        in previous.observations
        if observation.type == "service_open"
    }

    current_services = {
        (
            observation.data.get("host"),
            observation.data.get("port"),
        )
        for observation
        in current.observations
        if observation.type == "service_open"
    }

    for target, ports in comparable:
        for port in ports:
            key = (
                target,
                port,
            )

            if (
                key in previous_services
                and key not in current_services
            ):
                changes.append(
                    ChangeRecord(
                        change_type=(
                            ChangeType.CANDIDATE_MISSING
                        ),
                        asset_type=(
                            AssetType.SERVICE
                        ),
                        asset_value=(
                            f"{target}:{port}"
                        ),
                        plugin="service",
                        target=target,
                    )
                )

    return changes

def detect_missing_active_services(
    current: PluginResult,
    assets: list[Asset],
) -> list[ChangeRecord]:
    changes: list[ChangeRecord] = []

    current_services = {
        (
            observation.data.get("host"),
            observation.data.get("port"),
        )
        for observation in current.observations
        if observation.type == "service_open"
    }

    for coverage in current.coverage:
        if (
            coverage.coverage_type
            != CoverageType.SERVICE
        ):
            continue

        target = coverage.target

        for asset in assets:
            if asset.type != AssetType.SERVICE:
                continue

            if not asset.active:
                continue

            host = asset.metadata.get("host")
            port = asset.metadata.get("port")

            if host != target:
                continue

            if port not in coverage.ports:
                continue

            key = (
                host,
                port,
            )

            if key in current_services:
                continue

            changes.append(
                ChangeRecord(
                    change_type=(
                        ChangeType.CANDIDATE_MISSING
                    ),
                    asset_type=AssetType.SERVICE,
                    asset_value=asset.value,
                    plugin="service",
                    target=target,
                )
            )

    return changes

def detect_missing_dns_relations(
    current: PluginResult,
    relations: list[AssetRelation],
) -> list[ChangeRecord]:
    changes: list[ChangeRecord] = []

    resolved_now: dict[
        str,
        set[str],
    ] = {}

    for observation in current.observations:
        if (
            observation.type
            != "dns_resolution"
        ):
            continue

        resolved_now[
            observation.target
        ] = set(
            observation.data.get(
                "addresses",
                [],
            )
        )

    covered_targets = {
        coverage.target
        for coverage in current.coverage
        if (
            coverage.coverage_type
            == CoverageType.DNS
        )
    }

    for relation in relations:
        if (
            relation.relation
            != AssetRelationType.RESOLVES_TO
        ):
            continue

        if not relation.active:
            continue

        if (
            relation.source_type
            != AssetType.DOMAIN
        ):
            continue

        if (
            relation.target_type
            != AssetType.IP
        ):
            continue

        domain = relation.source_value
        address = relation.target_value

        if domain not in covered_targets:
            continue

        current_addresses = (
            resolved_now.get(
                domain,
                set(),
            )
        )

        if address in current_addresses:
            continue

        changes.append(
            ChangeRecord(
                change_type=(
                    ChangeType.CANDIDATE_MISSING
                ),

                relation_type=(
                    AssetRelationType.RESOLVES_TO
                ),

                source_type=(
                    AssetType.DOMAIN
                ),
                source_value=domain,

                target_type=(
                    AssetType.IP
                ),
                target_value=address,

                plugin="dns",
                target=domain,
            )
        )

    return changes

def detect_missing_exposes_relations(
    current: PluginResult,
    relations: list[AssetRelation],
) -> list[ChangeRecord]:
    changes: list[ChangeRecord] = []

    observed_services = {
        (
            observation.data.get("host"),
            observation.data.get("port"),
        )
        for observation in current.observations
        if observation.type == "service_open"
    }

    coverage_by_target = {
        coverage.target: set(
            coverage.ports
        )
        for coverage in current.coverage
        if (
            coverage.coverage_type
            == CoverageType.SERVICE
        )
    }

    for relation in relations:
        if (
            relation.relation
            != AssetRelationType.EXPOSES
        ):
            continue

        if not relation.active:
            continue

        if (
            relation.source_type
            != AssetType.DOMAIN
        ):
            continue

        if (
            relation.target_type
            != AssetType.SERVICE
        ):
            continue

        host = relation.source_value

        try:
            service_host, port_text = (
                relation.target_value.rsplit(
                    ":",
                    1,
                )
            )

            port = int(
                port_text
            )

        except (
            ValueError,
            TypeError,
        ):
            continue

        if service_host != host:
            continue

        covered_ports = (
            coverage_by_target.get(
                host
            )
        )

        if covered_ports is None:
            continue

        if port not in covered_ports:
            continue

        if (
            host,
            port,
        ) in observed_services:
            continue

        changes.append(
            ChangeRecord(
                change_type=(
                    ChangeType.CANDIDATE_MISSING
                ),
                relation_type=(
                    AssetRelationType.EXPOSES
                ),
                source_type=(
                    AssetType.DOMAIN
                ),
                source_value=host,
                target_type=(
                    AssetType.SERVICE
                ),
                target_value=(
                    relation.target_value
                ),
                plugin="service",
                target=host,
            )
        )

    return changes

def detect_missing_presents_relations(
    current: PluginResult,
    relations: list[AssetRelation],
) -> list[ChangeRecord]:
    changes: list[ChangeRecord] = []

    presented_now: dict[
        str,
        set[str],
    ] = {}

    for observation in current.observations:
        if (
            observation.type
            != "tls_handshake"
        ):
            continue

        host = observation.data.get(
            "host"
        )

        port = observation.data.get(
            "port",
            443,
        )

        certificate_sha256 = (
            observation.data.get(
                "certificate_sha256"
            )
        )

        if (
            host is None
            or certificate_sha256 is None
        ):
            continue

        service_value = (
            f"{host}:{port}"
        )

        presented_now.setdefault(
            service_value,
            set(),
        ).add(
            certificate_sha256
        )

    covered_targets = {
        coverage.target
        for coverage in current.coverage
        if (
            coverage.coverage_type
            == CoverageType.TLS
        )
    }

    for relation in relations:
        if (
            relation.relation
            != AssetRelationType.PRESENTS
        ):
            continue

        if not relation.active:
            continue

        if (
            relation.source_type
            != AssetType.SERVICE
        ):
            continue

        if (
            relation.target_type
            != AssetType.CERTIFICATE
        ):
            continue

        service_value = (
            relation.source_value
        )

        certificate = (
            relation.target_value
        )

        try:
            host, port_text = (
                service_value.rsplit(
                    ":",
                    1,
                )
            )

            port = int(
                port_text
            )

        except (
            ValueError,
            TypeError,
        ):
            continue

        if port != 443:
            continue

        if host not in covered_targets:
            continue

        current_certificates = (
            presented_now.get(
                service_value,
                set(),
            )
        )

        if (
            certificate
            in current_certificates
        ):
            continue

        changes.append(
            ChangeRecord(
                change_type=(
                    ChangeType.CANDIDATE_MISSING
                ),
                relation_type=(
                    AssetRelationType.PRESENTS
                ),
                source_type=(
                    AssetType.SERVICE
                ),
                source_value=(
                    service_value
                ),
                target_type=(
                    AssetType.CERTIFICATE
                ),
                target_value=(
                    certificate
                ),
                plugin="tls",
                target=host,
            )
        )

    return changes
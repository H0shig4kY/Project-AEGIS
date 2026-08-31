from dataclasses import dataclass, field
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from enum import Enum
from typing import Iterable
import hashlib

from aegis.models import (
    Asset,
    AssetRelation,
    AssetRelationType,
    AssetType,
    ChangeRecord,
    ChangeType,
)


class ExposureSeverity(
    str,
    Enum,
):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExposureService:
    value: str
    host: str | None
    port: int | None
    service_name: str | None
    transport: str | None

    active: bool

    tls: bool = False
    certificate: str | None = None

    source: str | None = None


@dataclass
class ExposureFinding:
    rule_id: str
    severity: ExposureSeverity

    title: str
    description: str

    asset_type: AssetType
    asset_value: str

    plugin: str | None = None

    affected_service: str | None = None

    @property
    def finding_id(
        self,
    ) -> str:
        identity = "|".join(
            [
                self.rule_id,
                self.asset_type.value,
                self.asset_value,
                self.affected_service or "",
            ]
        )

        return hashlib.sha256(
            identity.encode(
                "utf-8"
            )
        ).hexdigest()


@dataclass
class ExposureReport:
    services: list[
        ExposureService
    ] = field(
        default_factory=list
    )

    findings: list[
        ExposureFinding
    ] = field(
        default_factory=list
    )

    asset_counts: dict[
        str,
        dict[str, int],
    ] = field(
        default_factory=dict
    )

    def active_services(
        self,
    ) -> list[ExposureService]:
        return [
            service
            for service in self.services
            if service.active
        ]

    def inactive_services(
        self,
    ) -> list[ExposureService]:
        return [
            service
            for service in self.services
            if not service.active
        ]

    def tls_services(
        self,
    ) -> list[ExposureService]:
        return [
            service
            for service in self.services
            if service.tls
        ]


class ExposureAnalyzer:
    def analyze(
        self,
        *,
        assets: Iterable[Asset],
        relations: Iterable[
            AssetRelation
        ],
        changes: Iterable[
            ChangeRecord
        ],
    ) -> ExposureReport:
        assets = list(
            assets
        )

        relations = list(
            relations
        )

        changes = list(
            changes
        )

        report = ExposureReport()

        report.asset_counts = (
            self._build_asset_counts(
                assets
            )
        )

        report.services = (
            self._build_services(
                assets,
                relations,
            )
        )

        report.findings.extend(
            self._detect_service_findings(
                report.services
            )
        )

        report.findings.extend(
            self._detect_certificate_findings(
                assets,
                relations,
            )
        )

        report.findings.extend(
            self._detect_change_findings(
                changes
            )
        )

        return report

    # -------------------------------------------------
    # ASSET COUNTS
    # -------------------------------------------------

    def _build_asset_counts(
        self,
        assets: list[Asset],
    ) -> dict[
        str,
        dict[str, int],
    ]:
        counts: dict[
            str,
            dict[str, int],
        ] = {}

        for asset in assets:
            key = asset.type.value

            if key not in counts:
                counts[key] = {
                    "active": 0,
                    "inactive": 0,
                }

            state = (
                "active"
                if asset.active
                else "inactive"
            )

            counts[
                key
            ][
                state
            ] += 1

        return counts

    # -------------------------------------------------
    # SERVICES
    # -------------------------------------------------

    def _build_services(
        self,
        assets: list[Asset],
        relations: list[
            AssetRelation
        ],
    ) -> list[
        ExposureService
    ]:
        certificates_by_service = (
            self._certificate_relations(
                relations
            )
        )

        services = []

        for asset in assets:
            if (
                asset.type
                != AssetType.SERVICE
            ):
                continue

            metadata = (
                asset.metadata
                or {}
            )

            host = metadata.get(
                "host"
            )

            port = metadata.get(
                "port"
            )

            service_name = (
                metadata.get(
                    "service_name"
                )
                or metadata.get(
                    "name"
                )
            )

            transport = (
                metadata.get(
                    "transport"
                )
            )

            tls = bool(
                metadata.get(
                    "tls",
                    False,
                )
            )

            certificate = (
                certificates_by_service.get(
                    asset.value
                )
            )

            if certificate is not None:
                tls = True

            services.append(
                ExposureService(
                    value=asset.value,
                    host=host,
                    port=port,
                    service_name=(
                        service_name
                    ),
                    transport=(
                        transport
                    ),
                    active=asset.active,
                    tls=tls,
                    certificate=(
                        certificate
                    ),
                    source=asset.source,
                )
            )

        services.sort(
            key=lambda service: (
                service.host or "",
                service.port or 0,
                service.value,
            )
        )

        return services

    def _certificate_relations(
        self,
        relations: list[
            AssetRelation
        ],
    ) -> dict[
        str,
        str,
    ]:
        certificates: dict[
            str,
            str,
        ] = {}

        for relation in relations:
            if (
                relation.relation
                != AssetRelationType.PRESENTS
            ):
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

            if not relation.active:
                continue

            certificates[
                relation.source_value
            ] = (
                relation.target_value
            )

        return certificates

    # -------------------------------------------------
    # SERVICE FINDINGS
    # -------------------------------------------------

    def _detect_service_findings(
        self,
        services: list[
            ExposureService
        ],
    ) -> list[
        ExposureFinding
    ]:
        findings = []

        for service in services:
            if not service.active:
                continue

            if (
                self._is_http_service(
                    service
                )
                and not service.tls
            ):
                findings.append(
                    ExposureFinding(
                        rule_id=(
                            "HTTP_WITHOUT_TLS"
                        ),
                        severity=(
                            ExposureSeverity.MEDIUM
                        ),
                        title=(
                            "HTTP service exposed "
                            "without TLS"
                        ),
                        description=(
                            "An active HTTP service "
                            "is exposed without a "
                            "TLS-protected transport."
                        ),
                        asset_type=(
                            AssetType.SERVICE
                        ),
                        asset_value=(
                            service.value
                        ),
                    )
                )

        return findings

    def _is_http_service(
        self,
        service: ExposureService,
    ) -> bool:
        if (
            service.service_name
            is not None
        ):
            normalized = (
                service.service_name
                .lower()
            )

            if normalized in {
                "http",
                "www",
            }:
                return True

        return (
            service.port == 80
        )

    # -------------------------------------------------
    # CERTIFICATE FINDINGS
    # -------------------------------------------------

    def _detect_certificate_findings(
        self,
        assets: list[
            Asset
        ],
        relations: list[
            AssetRelation
        ],
    ) -> list[
        ExposureFinding
    ]:
        findings = []

        now = datetime.now(
            timezone.utc
        )

        expiring_threshold = (
            now
            + timedelta(
                days=30
            )
        )

        services_by_certificate = (
            self._services_by_certificate(
                relations
            )
        )

        for asset in assets:
            if (
                asset.type
                != AssetType.CERTIFICATE
            ):
                continue

            if not asset.active:
                continue

            metadata = (
                asset.metadata
                or {}
            )

            valid_to_raw = (
                metadata.get(
                    "valid_to"
                )
            )

            if not valid_to_raw:
                continue

            valid_to = (
                self._parse_datetime(
                    valid_to_raw
                )
            )

            if valid_to is None:
                continue

            affected_services = (
                services_by_certificate.get(
                    asset.value,
                    [],
                )
            )

            service_values = (
                affected_services
                if affected_services
                else [None]
            )

            # -----------------------------------------
            # EXPIRED
            # -----------------------------------------

            if valid_to < now:
                for service_value in (
                    service_values
                ):
                    description = (
                        "The TLS certificate "
                        "expired on "
                        f"{valid_to.isoformat()}."
                    )

                    if (
                        service_value
                        is not None
                    ):
                        description += (
                            " Affected service: "
                            f"{service_value}."
                        )

                    findings.append(
                        ExposureFinding(
                            rule_id=(
                                "TLS_CERTIFICATE_EXPIRED"
                            ),
                            severity=(
                                ExposureSeverity.HIGH
                            ),
                            title=(
                                "TLS certificate expired"
                            ),
                            description=(
                                description
                            ),
                            asset_type=(
                                AssetType.CERTIFICATE
                            ),
                            asset_value=(
                                asset.value
                            ),
                            plugin="tls",
                            affected_service=(
                                service_value
                            ),
                        )
                    )

                continue

            # -----------------------------------------
            # EXPIRING SOON
            # -----------------------------------------

            if (
                valid_to
                <= expiring_threshold
            ):
                remaining = (
                    valid_to - now
                )

                days_remaining = max(
                    0,
                    remaining.days,
                )

                for service_value in (
                    service_values
                ):
                    description = (
                        "The TLS certificate "
                        "expires in "
                        f"{days_remaining} days "
                        "on "
                        f"{valid_to.isoformat()}."
                    )

                    if (
                        service_value
                        is not None
                    ):
                        description += (
                            " Affected service: "
                            f"{service_value}."
                        )

                    findings.append(
                        ExposureFinding(
                            rule_id=(
                                "TLS_CERTIFICATE_EXPIRING"
                            ),
                            severity=(
                                ExposureSeverity.MEDIUM
                            ),
                            title=(
                                "TLS certificate "
                                "expiring soon"
                            ),
                            description=(
                                description
                            ),
                            asset_type=(
                                AssetType.CERTIFICATE
                            ),
                            asset_value=(
                                asset.value
                            ),
                            plugin="tls",
                            affected_service=(
                                service_value
                            ),
                        )
                    )

        return findings

    def _services_by_certificate(
        self,
        relations: list[
            AssetRelation
        ],
    ) -> dict[
        str,
        list[str],
    ]:
        services: dict[
            str,
            list[str],
        ] = {}

        for relation in relations:
            if (
                relation.relation
                != AssetRelationType.PRESENTS
            ):
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

            if not relation.active:
                continue

            certificate = (
                relation.target_value
            )

            service = (
                relation.source_value
            )

            values = (
                services.setdefault(
                    certificate,
                    [],
                )
            )

            if service not in values:
                values.append(
                    service
                )

        return services

    def _parse_datetime(
        self,
        value,
    ) -> datetime | None:
        if isinstance(
            value,
            datetime,
        ):
            parsed = value

        elif isinstance(
            value,
            str,
        ):
            normalized = (
                value.strip()
            )

            if normalized.endswith(
                "Z"
            ):
                normalized = (
                    normalized[:-1]
                    + "+00:00"
                )

            try:
                parsed = (
                    datetime.fromisoformat(
                        normalized
                    )
                )
            except ValueError:
                return None

        else:
            return None

        if (
            parsed.tzinfo
            is None
        ):
            parsed = (
                parsed.replace(
                    tzinfo=timezone.utc
                )
            )

        return (
            parsed.astimezone(
                timezone.utc
            )
        )

    # -------------------------------------------------
    # CHANGE FINDINGS
    # -------------------------------------------------

    def _detect_change_findings(
        self,
        changes: list[
            ChangeRecord
        ],
    ) -> list[
        ExposureFinding
    ]:
        findings = []

        changes = sorted(
            changes,
            key=lambda change: (
                change.detected_at
            ),
            reverse=True,
        )

        seen_events: set[
            tuple[
                str,
                str,
            ]
        ] = set()

        for change in changes:
            if (
                change.asset_type
                != AssetType.SERVICE
            ):
                continue

            if (
                change.asset_value
                is None
            ):
                continue

            if (
                change.change_type
                == ChangeType.REACTIVATED
            ):
                key = (
                    "SERVICE_REACTIVATED",
                    change.asset_value,
                )

                if key in seen_events:
                    continue

                seen_events.add(
                    key
                )

                findings.append(
                    ExposureFinding(
                        rule_id=(
                            "SERVICE_REACTIVATED"
                        ),
                        severity=(
                            ExposureSeverity.INFO
                        ),
                        title=(
                            "Service became "
                            "exposed again"
                        ),
                        description=(
                            "A previously inactive "
                            "service has been "
                            "observed again."
                        ),
                        asset_type=(
                            AssetType.SERVICE
                        ),
                        asset_value=(
                            change.asset_value
                        ),
                        plugin=(
                            change.plugin
                        ),
                    )
                )

        return findings
from enum import Enum
from typing import Any
from datetime import datetime, timezone

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)


class TargetType(str, Enum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP = "ip"
    CIDR = "cidr"


class Target(BaseModel):
    value: str
    type: TargetType
    description: str | None = None


class AssetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    SERVICE = "service"
    CERTIFICATE = "certificate"


class FingerprintConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FingerprintSource(str, Enum):
    PORT = "port"
    BANNER = "banner"

class IntegrityBaselineType(str, Enum):
    ORIGINAL = "original"
    RETROSPECTIVE = "retrospective"

class AssetRelationType(str, Enum):
    RESOLVES_TO = "resolves_to"
    EXPOSES = "exposes"
    PRESENTS = "presents"


class AssetRelation(BaseModel):
    source_type: AssetType
    source_value: str

    relation: AssetRelationType

    target_type: AssetType
    target_value: str

class ResultIntegrityRecord(BaseModel):
    filename: str
    sha256: str
    baseline_type: IntegrityBaselineType
    created_at: datetime
    verified_at: datetime | None = None


class ResultIntegrityManifest(BaseModel):
    results: list[ResultIntegrityRecord] = Field(
        default_factory=list
    )


class ServiceMetadata(BaseModel):
    host: str
    port: int
    transport: str = "tcp"
    service_name: str = "unknown"
    tls: bool = False
    banner: str | None = None
    product: str | None = None
    version: str | None = None

    confidence: FingerprintConfidence = (
        FingerprintConfidence.MEDIUM
    )

    fingerprint_source: FingerprintSource = (
        FingerprintSource.PORT
    )

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: int) -> int:
        if value < 1 or value > 65535:
            raise ValueError(
                "Port must be between 1 and 65535."
            )

        return value

    @field_validator("transport")
    @classmethod
    def validate_transport(cls, value: str) -> str:
        normalized = value.lower()

        if normalized not in {"tcp", "udp"}:
            raise ValueError(
                "Transport must be tcp or udp."
            )

        return normalized

class AssetProvenance(BaseModel):
    plugin: str
    plugin_version: str | None = None
    observation_type: str
    target: str
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )
    result_file: str | None = None

    observation_id: str | None = None
    result_id: str | None = None
    result_sha256: str | None = None
    integrity_baseline: IntegrityBaselineType | None = None

class Asset(BaseModel):
    value: str
    type: AssetType
    source: str

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    provenance: list[AssetProvenance] = Field(
        default_factory=list
    )

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_confirmed: datetime | None = None

    seen_count: int = 0
    active: bool = True

class TLSMetadata(BaseModel):
    host: str
    port: int
    transport: str = "tcp"
    tls: bool = True
    tls_version: str | None = None
    cipher: str | None = None
    certificate_subject: object | None = None
    certificate_issuer: object | None = None
    certificate_valid_from: str | None = None
    certificate_valid_to: str | None = None
    certificate_sans: list[str] = Field(
        default_factory=list
    )
    certificate_sha256: str | None = None

class CertificateMetadata(BaseModel):
    host: str
    port: int = 443

    subject: Any | None = None
    issuer: Any | None = None

    valid_from: str | None = None
    valid_to: str | None = None

    sans: list[str] = Field(
        default_factory=list
    )

    sha256: str
    presented_by: str

    @field_validator("sha256")
    @classmethod
    def validate_sha256(
        cls,
        value: str,
    ) -> str:
        normalized = value.lower()

        if (
            len(normalized) != 64
            or any(
                character not in "0123456789abcdef"
                for character in normalized
            )
        ):
            raise ValueError(
                "Certificate SHA-256 must be "
                "a 64-character hexadecimal value."
            )

        return normalized

class RelationProvenance(BaseModel):
    plugin: str
    plugin_version: str | None = None
    observation_type: str
    target: str

    observed_at: datetime

    observation_id: str | None = None
    result_id: str | None = None
    result_file: str | None = None
    result_sha256: str | None = None


class AssetRelation(BaseModel):
    source_type: AssetType
    source_value: str

    relation: AssetRelationType

    target_type: AssetType
    target_value: str

    provenance: list[RelationProvenance] = Field(
        default_factory=list
    )

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_confirmed: datetime | None = None

    seen_count: int = 0
    active: bool = True

class CoverageType(str, Enum):
    DNS = "dns"
    HTTP = "http"
    SERVICE = "service"
    TLS = "tls"


class ExecutionCoverage(BaseModel):
    plugin: str
    target: str
    coverage_type: CoverageType

    ports: list[int] = Field(
        default_factory=list
    )

class AssetChange(BaseModel):
    change_type: ChangeType
    asset_type: AssetType
    asset_value: str

    plugin: str
    target: str

    previous_result: str | None = None
    current_result: str | None = None

class ChangeRecord(BaseModel):
    change_type: ChangeType

    asset_type: AssetType | None = None
    asset_value: str | None = None

    relation_type: AssetRelationType | None = None

    source_type: AssetType | None = None
    source_value: str | None = None

    target_type: AssetType | None = None
    target_value: str | None = None

    plugin: str
    target: str

    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    previous_result: str | None = None
    current_result: str | None = None

class ChangeType(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    CANDIDATE_MISSING = "candidate_missing"
    INACTIVE = "inactive"
    REACTIVATED = "reactivated"
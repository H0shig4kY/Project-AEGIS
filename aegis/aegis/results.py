from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from aegis.models import (
    Asset,
    ExecutionCoverage,
)


class Observation(BaseModel):
    target: str
    type: str
    data: dict = Field(
        default_factory=dict
    )


class PluginResult(BaseModel):
    plugin: str
    version: str
    status: str = "success"

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    observations: list[Observation] = Field(
        default_factory=list
    )

    coverage: list[ExecutionCoverage] = Field(
        default_factory=list
    )


class RejectionReason(str, Enum):
    OUTSIDE_SCOPE = "outside_scope"
    UNSUPPORTED_TYPE = "unsupported_type"


class ScopeDecision(BaseModel):
    allowed: bool
    reason: RejectionReason | None = None


class RejectedAsset(BaseModel):
    asset: Asset
    reason: RejectionReason


class ProcessingResult(BaseModel):
    accepted: list[Asset] = Field(
        default_factory=list
    )

    rejected: list[RejectedAsset] = Field(
        default_factory=list
    )

    @property
    def discovered_count(self) -> int:
        return (
            len(self.accepted)
            + len(self.rejected)
        )

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)
from __future__ import annotations

from datetime import datetime

from aegis.exposure import (
    ExposureAnalyzer,
    ExposureReport,
)
from aegis.finding_lifecycle import (
    FindingLifecycleManager,
)


class FindingProcessor:
    """
    Coordinates exposure analysis with persistent
    finding lifecycle management.

    This class is intended to be called after an
    assessment observation/execution has completed.
    """

    def __init__(
        self,
        *,
        asset_store,
        relation_store,
        change_store,
        finding_store,
    ):
        self.asset_store = (
            asset_store
        )

        self.relation_store = (
            relation_store
        )

        self.change_store = (
            change_store
        )

        self.finding_store = (
            finding_store
        )

        self.analyzer = (
            ExposureAnalyzer()
        )

        self.lifecycle = (
            FindingLifecycleManager(
                finding_store
            )
        )

    def process(
        self,
        *,
        observed_at: datetime | None = None,
        observed_plugin: str | None = None,
    ) -> ExposureReport:
        report = self.analyzer.analyze(
            assets=(
                self.asset_store.find()
            ),
            relations=(
                self.relation_store.find()
            ),
            changes=(
                self.change_store.find()
            ),
        )

        self.lifecycle.process(
            list(
                report.findings
            ),
            observed_at=observed_at,
            observed_plugin=(
                observed_plugin
            ),
        )

        return report
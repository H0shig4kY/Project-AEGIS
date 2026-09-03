from datetime import (
    datetime,
    timezone,
)

from aegis.exposure import (
    ExposureFinding,
)
from aegis.finding_store import (
    FindingStore,
)
from aegis.models import (
    FindingRecord,
    FindingState,
)


class FindingLifecycleManager:
    def __init__(
        self,
        store: FindingStore,
    ):
        self.store = store

    def process(
        self,
        current_findings: list[
            ExposureFinding
        ],
        *,
        observed_at: datetime | None = None,
        observed_plugin: str | None = None,
    ) -> list[
        FindingRecord
    ]:
        if observed_at is None:
            observed_at = datetime.now(
                timezone.utc
            )

        existing = {
            record.finding_id: record
            for record
            in self.store.find()
        }

        current_ids = {
            finding.finding_id
            for finding
            in current_findings
        }

        updated: list[
            FindingRecord
        ] = []

        # -------------------------------------------------
        # PRESENT FINDINGS
        # -------------------------------------------------

        for finding in current_findings:
            if (
                observed_plugin is not None
                and finding.coverage_plugins
                and observed_plugin
                not in finding.coverage_plugins
            ):
                continue

            record = existing.get(
                finding.finding_id
            )

            if record is None:
                record = FindingRecord(
                    finding_id=(
                        finding.finding_id
                    ),
                    rule_id=(
                        finding.rule_id
                    ),
                    severity=(
                        finding.severity.value
                    ),
                    title=(
                        finding.title
                    ),
                    description=(
                        finding.description
                    ),
                    asset_type=(
                        finding.asset_type
                    ),
                    asset_value=(
                        finding.asset_value
                    ),
                    affected_service=(
                        finding.affected_service
                    ),
                    plugin=(
                        finding.plugin
                    ),
                    coverage_plugins=(
                        finding.coverage_plugins
                    ),
                    state=(
                        FindingState.ACTIVE
                    ),
                    first_seen=(
                        observed_at
                    ),
                    last_seen=(
                        observed_at
                    ),
                    last_confirmed=(
                        observed_at
                    ),
                    seen_count=1,
                    missing_count=0,
                    active=True,
                )

            else:
                record.last_seen = (
                    observed_at
                )

                record.last_confirmed = (
                    observed_at
                )

                record.seen_count += 1
                record.missing_count = 0

                record.state = (
                    FindingState.ACTIVE
                )

                record.active = True

                record.severity = (
                    finding.severity.value
                )

                record.title = (
                    finding.title
                )

                record.description = (
                    finding.description
                )

                record.affected_service = (
                    finding.affected_service
                )

                record.plugin = (
                    finding.plugin
                )

                record.coverage_plugins = (
                    finding.coverage_plugins
                )

            self.store.save(
                record
            )

            updated.append(
                record
            )

        # -------------------------------------------------
        # MISSING FINDINGS
        # -------------------------------------------------

        for (
            finding_id,
            record,
        ) in existing.items():
            if (
                finding_id
                in current_ids
            ):
                continue

            if not record.active:
                continue

            if (
                observed_plugin is not None
                and record.coverage_plugins
                and observed_plugin
                not in record.coverage_plugins
            ):
                continue

            record.missing_count += 1

            if (
                record.missing_count
                >= 2
            ):
                record.state = (
                    FindingState.RESOLVED
                )

                record.active = False

            else:
                record.state = (
                    FindingState.CANDIDATE_MISSING
                )

            self.store.save(
                record
            )

            updated.append(
                record
            )

        return updated
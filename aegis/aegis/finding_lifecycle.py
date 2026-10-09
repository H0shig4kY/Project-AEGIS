import hashlib

from datetime import (
    datetime,
    timezone,
)

from aegis.exposure import (
    ExposureFinding,
)
from aegis.finding_history_store import (
    FindingHistoryStore,
)
from aegis.finding_store import (
    FindingStore,
)
from aegis.models import (
    FindingEvent,
    FindingEventType,
    FindingRecord,
    FindingState,
)


class FindingLifecycleManager:
    def __init__(
        self,
        store: FindingStore,
        history_store: (
            FindingHistoryStore
            | None
        ) = None,
    ):
        self.store = store
        self.history_store = (
            history_store
        )

    def process(
        self, current_findings: list[ExposureFinding], *,
        observed_at: datetime | None = None, observed_plugin: str | None = None,
    ) -> list[FindingRecord]:
        with self.store.transaction():
            return self._process(current_findings, observed_at=observed_at,
                                 observed_plugin=observed_plugin)

    def _process(
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

            is_new = (
                record is None
            )

            previous_state = None

            if is_new:
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
                previous_state = (
                    record.state
                )

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

            # -------------------------------------------------
            # CREATED EVENT
            # -------------------------------------------------

            if (
                is_new
                and self.history_store
                is not None
            ):
                event = (
                    self._create_event(
                        finding_id=(
                            finding.finding_id
                        ),
                        event_type=(
                            FindingEventType.CREATED
                        ),
                        from_state=None,
                        to_state=(
                            FindingState.ACTIVE
                        ),
                        detected_at=(
                            observed_at
                        ),
                        observed_plugin=(
                            observed_plugin
                        ),
                        rule_id=(
                            finding.rule_id
                        ),
                        asset_type=(
                            finding.asset_type
                        ),
                        asset_value=(
                            finding.asset_value
                        ),
                    )
                )

                self.history_store.save(
                    event
                )

            # -------------------------------------------------
            # REACTIVATION / RETURN TO ACTIVE EVENT
            # -------------------------------------------------

            if (
                not is_new
                and self.history_store
                is not None
                and previous_state
                != record.state
            ):
                event = (
                    self._create_event(
                        finding_id=(
                            record.finding_id
                        ),
                        event_type=(
                            FindingEventType.STATE_CHANGED
                        ),
                        from_state=(
                            previous_state
                        ),
                        to_state=(
                            record.state
                        ),
                        detected_at=(
                            observed_at
                        ),
                        observed_plugin=(
                            observed_plugin
                        ),
                        rule_id=(
                            record.rule_id
                        ),
                        asset_type=(
                            record.asset_type
                        ),
                        asset_value=(
                            record.asset_value
                        ),
                    )
                )

                self.history_store.save(
                    event
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

            previous_state = (
                record.state
            )

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

            if (
                self.history_store
                is not None
                and previous_state
                != record.state
            ):
                event = (
                    self._create_event(
                        finding_id=(
                            record.finding_id
                        ),
                        event_type=(
                            FindingEventType.STATE_CHANGED
                        ),
                        from_state=(
                            previous_state
                        ),
                        to_state=(
                            record.state
                        ),
                        detected_at=(
                            observed_at
                        ),
                        observed_plugin=(
                            observed_plugin
                        ),
                        rule_id=(
                            record.rule_id
                        ),
                        asset_type=(
                            record.asset_type
                        ),
                        asset_value=(
                            record.asset_value
                        ),
                    )
                )

                self.history_store.save(
                    event
                )

            updated.append(
                record
            )

        return updated

    def _create_event(
        self,
        *,
        finding_id: str,
        event_type: FindingEventType,
        from_state: FindingState | None,
        to_state: FindingState,
        detected_at: datetime,
        observed_plugin: str | None,
        rule_id: str | None,
        asset_type,
        asset_value: str | None,
    ) -> FindingEvent:
        identity = "|".join(
            [
                finding_id,
                event_type.value,
                (
                    from_state.value
                    if from_state
                    else ""
                ),
                to_state.value,
                detected_at.isoformat(),
                observed_plugin or "",
            ]
        )

        event_id = hashlib.sha256(
            identity.encode(
                "utf-8"
            )
        ).hexdigest()

        return FindingEvent(
            event_id=event_id,
            finding_id=finding_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            detected_at=detected_at,
            plugin=observed_plugin,
            rule_id=rule_id,
            asset_type=asset_type,
            asset_value=asset_value,
        )
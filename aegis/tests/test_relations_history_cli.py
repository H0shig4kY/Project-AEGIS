import json
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from pathlib import Path

from typer.testing import CliRunner

from aegis.assessment import AssessmentContext
from aegis.cli import app
from aegis.context import CampaignContext
from aegis.models import (
    AssetRelation,
    AssetRelationType,
    AssetType,
    ChangeRecord,
    ChangeType,
)


runner = CliRunner()


def create_context(
    tmp_path: Path,
) -> AssessmentContext:
    campaign = tmp_path / "campaign"
    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    return AssessmentContext(
        CampaignContext(
            campaign
        )
    )


def make_relation(
    observed_at: datetime,
) -> AssetRelation:
    return AssetRelation(
        source_type=AssetType.DOMAIN,
        source_value="example.com",
        relation=(
            AssetRelationType.RESOLVES_TO
        ),
        target_type=AssetType.IP,
        target_value="192.0.2.10",
        first_seen=observed_at,
        last_seen=observed_at,
        last_confirmed=observed_at,
        seen_count=1,
        active=True,
    )


def test_relations_history_relation_not_found(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "relations",
            "history",
            "domain",
            "example.com",
            "resolves_to",
            "ip",
            "192.0.2.10",
        ],
    )

    assert result.exit_code == 1

    assert (
        "Error: relation not found."
        in result.output
    )


def test_relations_history_shows_lifecycle_and_changes(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    start = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    relation = make_relation(
        start
    )

    context.relations.save(
        relation
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.CANDIDATE_MISSING
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
            detected_at=(
                start
                + timedelta(minutes=5)
            ),
            current_result="dns-2.json",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.INACTIVE
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
            detected_at=(
                start
                + timedelta(minutes=10)
            ),
            current_result="dns-3.json",
        )
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.REACTIVATED
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
            detected_at=(
                start
                + timedelta(minutes=15)
            ),
            current_result="dns-4.json",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "relations",
            "history",
            "domain",
            "example.com",
            "resolves_to",
            "ip",
            "192.0.2.10",
        ],
    )

    assert result.exit_code == 0

    assert (
        "Relation history"
        in result.output
    )

    assert (
        "DOMAIN example.com"
        in result.output
    )

    assert (
        "--resolves_to--> "
        "IP 192.0.2.10"
        in result.output
    )

    assert (
        "Lifecycle"
        in result.output
    )

    assert (
        "Active: yes"
        in result.output
    )

    assert (
        "CANDIDATE_MISSING"
        in result.output
    )

    assert (
        "INACTIVE"
        in result.output
    )

    assert (
        "REACTIVATED"
        in result.output
    )

    # Confirma que a ordem temporal está correta.
    candidate_position = (
        result.output.index(
            "CANDIDATE_MISSING"
        )
    )

    inactive_position = (
        result.output.index(
            "INACTIVE"
        )
    )

    reactivated_position = (
        result.output.index(
            "REACTIVATED"
        )
    )

    assert (
        candidate_position
        < inactive_position
        < reactivated_position
    )


def test_relations_history_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    start = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    relation = make_relation(
        start
    )

    context.relations.save(
        relation
    )

    context.changes.save(
        ChangeRecord(
            change_type=(
                ChangeType.INACTIVE
            ),
            relation_type=(
                AssetRelationType.RESOLVES_TO
            ),
            source_type=AssetType.DOMAIN,
            source_value="example.com",
            target_type=AssetType.IP,
            target_value="192.0.2.10",
            plugin="dns",
            target="example.com",
            detected_at=(
                start
                + timedelta(minutes=10)
            ),
            current_result="dns-3.json",
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "relations",
            "history",
            "domain",
            "example.com",
            "resolves_to",
            "ip",
            "192.0.2.10",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert (
        payload["relation"]["source_type"]
        == "domain"
    )

    assert (
        payload["relation"]["source_value"]
        == "example.com"
    )

    assert (
        payload["relation"]["relation_type"]
        == "resolves_to"
    )

    assert (
        payload["relation"]["target_type"]
        == "ip"
    )

    assert (
        payload["relation"]["target_value"]
        == "192.0.2.10"
    )

    assert (
        payload["relation"]["active"]
        is True
    )

    assert len(
        payload["timeline"]
    ) >= 2

    events = [
        item["event"]
        for item in payload["timeline"]
    ]

    assert (
        "first_seen"
        in events
    )

    assert (
        "inactive"
        in events
    )
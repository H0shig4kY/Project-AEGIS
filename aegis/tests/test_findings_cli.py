import json

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from typer.testing import CliRunner

from aegis.assessment import (
    AssessmentContext,
)

from aegis.cli import app

from aegis.context import (
    CampaignContext,
)

from aegis.models import (
    Asset,
    AssetType,
    FindingState,
)


runner = CliRunner()


def create_context(
    tmp_path: Path,
) -> AssessmentContext:
    campaign = (
        tmp_path
        / "campaign"
    )

    campaign.mkdir()

    (
        campaign
        / "aegis.yaml"
    ).write_text(
        "name: test\n",
        encoding="utf-8",
    )

    return AssessmentContext(
        CampaignContext(
            campaign
        )
    )

def create_finding_with_history(
    context,
):
    context.assets.save(
        Asset(
            type=AssetType.SERVICE,
            value="example.com:80",
            source="service",
            metadata={
                "service_name": "http",
                "port": 80,
                "transport": "tcp",
            },
        )
    )

    observed_at = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=observed_at,
        observed_plugin="service",
    )

    finding = (
        context.findings.find()[0]
    )

    return (
        finding,
        observed_at,
    )


def add_http_finding_asset(
    context,
):
    context.assets.save(
        Asset(
            value="example.com:80",
            type=AssetType.SERVICE,
            source="service",
            metadata={
                "host": "example.com",
                "port": 80,
                "service_name": "http",
                "transport": "tcp",
                "tls": False,
            },
            active=True,
        )
    )

    context.finding_processor.process(
        observed_at=datetime(
            2026,
            9,
            3,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        observed_plugin="service",
    )


def get_http_finding_id(
    context,
):
    findings = (
        context.findings.find()
    )

    assert len(
        findings
    ) == 1

    return (
        findings[0]
        .finding_id
    )


def test_findings_list_empty(
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
            "findings",
            "list",
        ],
    )

    assert result.exit_code == 0

    assert (
        "No findings found."
        in result.output
    )


def test_findings_list(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    finding_id = (
        get_http_finding_id(
            context
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
        ],
    )

    assert result.exit_code == 0

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )

    assert (
        "MEDIUM"
        in result.output
    )

    assert (
        "ACTIVE"
        in result.output
    )

    assert (
        finding_id[:8]
        in result.output
    )


def test_findings_filter_by_severity(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--severity",
            "medium",
        ],
    )

    assert result.exit_code == 0

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )


def test_findings_filter_by_rule(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--rule",
            "HTTP_WITHOUT_TLS",
        ],
    )

    assert result.exit_code == 0

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )


def test_findings_filter_by_asset_type(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--asset-type",
            "service",
        ],
    )

    assert result.exit_code == 0

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )


def test_findings_filter_by_state(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--state",
            "active",
        ],
    )

    assert result.exit_code == 0

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )


def test_findings_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert len(
        payload
    ) == 1

    finding = payload[0]

    assert "id" in finding

    assert len(
        finding["id"]
    ) == 64

    assert (
        finding["rule_id"]
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        finding["severity"]
        == "medium"
    )

    assert (
        finding["state"]
        == "active"
    )

    assert (
        finding["active"]
        is True
    )

    assert (
        finding["asset_type"]
        == "service"
    )

    assert (
        finding["asset_value"]
        == "example.com:80"
    )

    assert (
        finding["affected_service"]
        is None
    )

    assert (
        finding["plugin"]
        is None
    )

    assert (
        finding["seen_count"]
        == 1
    )

    assert (
        finding["missing_count"]
        == 0
    )

    assert (
        finding["coverage_plugins"]
        == [
            "service",
            "http",
        ]
    )

    assert (
        finding["first_seen"]
        is not None
    )

    assert (
        finding["last_seen"]
        is not None
    )

    assert (
        finding["last_confirmed"]
        is not None
    )


def test_findings_rejects_invalid_severity(
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
            "findings",
            "list",
            "--severity",
            "impossible",
        ],
    )

    assert result.exit_code == 1

    assert (
        "invalid severity"
        in result.output
    )


def test_findings_rejects_invalid_state(
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
            "findings",
            "list",
            "--state",
            "impossible",
        ],
    )

    assert result.exit_code == 1

    assert (
        "invalid finding state"
        in result.output
    )


def test_findings_show(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    finding_id = (
        get_http_finding_id(
            context
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding_id[:12],
        ],
    )

    assert result.exit_code == 0

    assert (
        "FINDING DETAIL"
        in result.output
    )

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )

    assert (
        finding_id[:12]
        in result.output
    )

    assert (
        "ACTIVE"
        in result.output
    )

    assert (
        "service, http"
        in result.output
    )


def test_findings_show_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    finding_id = (
        get_http_finding_id(
            context
        )
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding_id[:12],
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert (
        payload["id"]
        == finding_id
    )

    assert (
        payload["rule_id"]
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        payload["severity"]
        == "medium"
    )

    assert (
        payload["state"]
        == "active"
    )

    assert (
        payload["active"]
        is True
    )

    assert (
        payload["asset_value"]
        == "example.com:80"
    )

    assert (
        payload["seen_count"]
        == 1
    )

    assert (
        payload["missing_count"]
        == 0
    )

    assert (
        payload["coverage_plugins"]
        == [
            "service",
            "http",
        ]
    )

    assert (
        payload["first_seen"]
        is not None
    )

    assert (
        payload["last_seen"]
        is not None
    )

    assert (
        payload["last_confirmed"]
        is not None
    )


def test_findings_show_not_found(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    add_http_finding_asset(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            "deadbeef",
        ],
    )

    assert result.exit_code == 1

    assert (
        "finding not found"
        in result.output
    )

def test_findings_history_shows_events(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    (
        finding,
        observed_at,
    ) = create_finding_with_history(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "history",
            finding.finding_id,
        ],
    )

    assert result.exit_code == 0

    assert (
        "Finding history"
        in result.output
    )

    assert (
        finding.finding_id
        in result.output
    )

    assert (
        "HTTP_WITHOUT_TLS"
        in result.output
    )

    assert (
        "CREATED"
        in result.output
    )

    assert (
        "ACTIVE"
        in result.output
    )

    assert (
        observed_at.isoformat()
        in result.output
    )

    assert (
        "service"
        in result.output
    )

def test_findings_history_accepts_unique_id_prefix(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    (
        finding,
        _,
    ) = create_finding_with_history(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "history",
            finding.finding_id[:12],
        ],
    )

    assert result.exit_code == 0

    assert (
        finding.finding_id
        in result.output
    )

    assert (
        "CREATED"
        in result.output
    )

def test_findings_history_json(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    (
        finding,
        observed_at,
    ) = create_finding_with_history(
        context
    )

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "history",
            finding.finding_id,
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    assert (
        payload["finding"]["id"]
        == finding.finding_id
    )

    assert (
        payload["finding"]["rule_id"]
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        payload["finding"]["state"]
        == "active"
    )

    assert len(
        payload["timeline"]
    ) == 1

    event = (
        payload["timeline"][0]
    )

    assert (
        event["event_type"]
        == "created"
    )

    assert (
        event["from_state"]
        is None
    )

    assert (
        event["to_state"]
        == "active"
    )

    assert (
        event["detected_at"]
        == observed_at.isoformat()
    )

    assert (
        event["plugin"]
        == "service"
    )

    assert (
        event["rule_id"]
        == "HTTP_WITHOUT_TLS"
    )

    assert (
        event["asset_type"]
        == "service"
    )

    assert (
        event["asset_value"]
        == "example.com:80"
    )

def test_findings_history_finding_not_found(
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
            "findings",
            "history",
            "does-not-exist",
        ],
    )

    assert result.exit_code == 1

    assert (
        "finding not found"
        in result.output
    )

def test_findings_history_shows_complete_lifecycle_timeline(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    # -------------------------------------------------
    # 1. CREATE
    # None -> ACTIVE
    # -------------------------------------------------

    asset = Asset(
        type=AssetType.SERVICE,
        value="example.com:80",
        source="service",
        metadata={
            "service_name": "http",
            "port": 80,
            "transport": "tcp",
        },
        active=True,
    )

    context.assets.save(
        asset
    )

    created_at = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=created_at,
        observed_plugin="service",
    )

    finding = (
        context.findings.find()[0]
    )

    # -------------------------------------------------
    # 2. FIRST MISSING
    # ACTIVE -> CANDIDATE_MISSING
    # -------------------------------------------------

    context.assets.set_active(
        AssetType.SERVICE,
        "example.com:80",
        False,
    )

    candidate_at = datetime(
        2026,
        9,
        3,
        11,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=candidate_at,
        observed_plugin="service",
    )

    # -------------------------------------------------
    # 3. SECOND MISSING
    # CANDIDATE_MISSING -> RESOLVED
    # -------------------------------------------------

    resolved_at = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=resolved_at,
        observed_plugin="service",
    )

    # -------------------------------------------------
    # 4. REAPPEARANCE
    # RESOLVED -> ACTIVE
    # -------------------------------------------------

    context.assets.set_active(
        AssetType.SERVICE,
        "example.com:80",
        True,
    )

    reactivated_at = datetime(
        2026,
        9,
        3,
        13,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=reactivated_at,
        observed_plugin="service",
    )

    reactivated_finding = (
        context.findings.get(
            finding.finding_id
        )
    )

    assert (
        reactivated_finding
        is not None
    )

    assert (
        reactivated_finding.state
        == FindingState.ACTIVE
    )

    assert (
        reactivated_finding.active
        is True
    )

    # -------------------------------------------------
    # CLI
    # -------------------------------------------------

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "history",
            finding.finding_id,
        ],
    )

    assert result.exit_code == 0

    # -------------------------------------------------
    # EVENTS
    # -------------------------------------------------

    assert (
        "CREATED NONE -> ACTIVE"
        in result.output
    )

    assert (
        "STATE_CHANGED "
        "ACTIVE -> CANDIDATE_MISSING"
        in result.output
    )

    assert (
        "STATE_CHANGED "
        "CANDIDATE_MISSING -> RESOLVED"
        in result.output
    )

    assert (
        "STATE_CHANGED "
        "RESOLVED -> ACTIVE"
        in result.output
    )

    # -------------------------------------------------
    # CHRONOLOGICAL ORDER
    # -------------------------------------------------

    created_position = (
        result.output.index(
            "CREATED NONE -> ACTIVE"
        )
    )

    candidate_position = (
        result.output.index(
            "ACTIVE -> CANDIDATE_MISSING"
        )
    )

    resolved_position = (
        result.output.index(
            "CANDIDATE_MISSING -> RESOLVED"
        )
    )

    reactivated_position = (
        result.output.index(
            "RESOLVED -> ACTIVE"
        )
    )

    assert (
        created_position
        < candidate_position
        < resolved_position
        < reactivated_position
    )

def test_findings_history_json_complete_lifecycle_timeline(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    # -------------------------------------------------
    # 1. CREATE
    # None -> ACTIVE
    # -------------------------------------------------

    context.assets.save(
        Asset(
            type=AssetType.SERVICE,
            value="example.com:80",
            source="service",
            metadata={
                "service_name": "http",
                "port": 80,
                "transport": "tcp",
            },
            active=True,
        )
    )

    created_at = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=created_at,
        observed_plugin="service",
    )

    finding = (
        context.findings.find()[0]
    )

    # -------------------------------------------------
    # 2. ACTIVE -> CANDIDATE_MISSING
    # -------------------------------------------------

    context.assets.set_active(
        AssetType.SERVICE,
        "example.com:80",
        False,
    )

    candidate_at = datetime(
        2026,
        9,
        3,
        11,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=candidate_at,
        observed_plugin="service",
    )

    # -------------------------------------------------
    # 3. CANDIDATE_MISSING -> RESOLVED
    # -------------------------------------------------

    resolved_at = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=resolved_at,
        observed_plugin="service",
    )

    # -------------------------------------------------
    # 4. RESOLVED -> ACTIVE
    # -------------------------------------------------

    context.assets.set_active(
        AssetType.SERVICE,
        "example.com:80",
        True,
    )

    reactivated_at = datetime(
        2026,
        9,
        3,
        13,
        0,
        tzinfo=timezone.utc,
    )

    context.finding_processor.process(
        observed_at=reactivated_at,
        observed_plugin="service",
    )

    # -------------------------------------------------
    # CLI JSON
    # -------------------------------------------------

    monkeypatch.chdir(
        context.root
    )

    result = runner.invoke(
        app,
        [
            "findings",
            "history",
            finding.finding_id,
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(
        result.output
    )

    # -------------------------------------------------
    # CURRENT FINDING
    # -------------------------------------------------

    assert (
        payload["finding"]["id"]
        == finding.finding_id
    )

    assert (
        payload["finding"]["state"]
        == "active"
    )

    assert (
        payload["finding"]["active"]
        is True
    )

    # -------------------------------------------------
    # COMPLETE TIMELINE
    # -------------------------------------------------

    timeline = (
        payload["timeline"]
    )

    assert len(timeline) == 4

    transitions = [
        (
            event["event_type"],
            event["from_state"],
            event["to_state"],
        )
        for event in timeline
    ]

    assert transitions == [
        (
            "created",
            None,
            "active",
        ),
        (
            "state_changed",
            "active",
            "candidate_missing",
        ),
        (
            "state_changed",
            "candidate_missing",
            "resolved",
        ),
        (
            "state_changed",
            "resolved",
            "active",
        ),
    ]

    # -------------------------------------------------
    # TIMESTAMPS
    # -------------------------------------------------

    assert [
        event["detected_at"]
        for event in timeline
    ] == [
        created_at.isoformat(),
        candidate_at.isoformat(),
        resolved_at.isoformat(),
        reactivated_at.isoformat(),
    ]

    # All transitions were driven by service coverage.
    assert all(
        event["plugin"] == "service"
        for event in timeline
    )
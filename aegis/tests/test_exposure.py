from datetime import (
    datetime,
    timezone,
)

from aegis.exposure import (
    ExposureAnalyzer,
    ExposureSeverity,
    ExposureFinding,
)
from aegis.models import (
    Asset,
    AssetRelation,
    AssetRelationType,
    AssetType,
    ChangeRecord,
    ChangeType,
)

from datetime import (
    datetime,
    timezone,
    timedelta,
)


def test_exposure_analyzer_builds_service():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        metadata={
            "host": "example.com",
            "port": 443,
            "service_name": "https",
            "transport": "tcp",
            "tls": True,
        },
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    assert len(
        report.services
    ) == 1

    service = report.services[0]

    assert (
        service.value
        == "example.com:443"
    )

    assert (
        service.host
        == "example.com"
    )

    assert (
        service.port
        == 443
    )

    assert service.tls is True
    assert service.active is True


def test_exposure_analyzer_links_certificate():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        metadata={
            "host": "example.com",
            "port": 443,
        },
        active=True,
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=(
            AssetRelationType.PRESENTS
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value="a" * 64,
        source="tls",
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[
            relation,
        ],
        changes=[],
    )

    service = report.services[0]

    assert service.tls is True

    assert (
        service.certificate
        == "a" * 64
    )


def test_exposure_detects_http_without_tls():
    analyzer = ExposureAnalyzer()

    asset = Asset(
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

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    findings = [
        finding
        for finding
        in report.findings
        if (
            finding.rule_id
            == "HTTP_WITHOUT_TLS"
        )
    ]

    assert len(
        findings
    ) == 1

    finding = findings[0]

    assert (
        finding.asset_value
        == "example.com:80"
    )

    assert (
        finding.severity
        == ExposureSeverity.MEDIUM
    )


def test_https_does_not_trigger_http_without_tls():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="example.com:443",
        type=AssetType.SERVICE,
        source="service",
        metadata={
            "host": "example.com",
            "port": 443,
            "service_name": "https",
            "tls": True,
        },
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    assert not any(
        finding.rule_id
        == "HTTP_WITHOUT_TLS"
        for finding
        in report.findings
    )


def test_inactive_http_does_not_trigger_finding():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="example.com:80",
        type=AssetType.SERVICE,
        source="service",
        metadata={
            "host": "example.com",
            "port": 80,
            "service_name": "http",
            "tls": False,
        },
        active=False,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    assert not any(
        finding.rule_id
        == "HTTP_WITHOUT_TLS"
        for finding
        in report.findings
    )


def test_reactivated_service_creates_info_finding():
    analyzer = ExposureAnalyzer()

    change = ChangeRecord(
        change_type=(
            ChangeType.REACTIVATED
        ),
        asset_type=(
            AssetType.SERVICE
        ),
        asset_value=(
            "example.com:443"
        ),
        plugin="service",
        target="example.com",
        detected_at=datetime(
            2026,
            8,
            31,
            10,
            0,
            tzinfo=timezone.utc,
        ),
    )

    report = analyzer.analyze(
        assets=[],
        relations=[],
        changes=[
            change,
        ],
    )

    findings = [
        finding
        for finding
        in report.findings
        if (
            finding.rule_id
            == "SERVICE_REACTIVATED"
        )
    ]

    assert len(
        findings
    ) == 1

    assert (
        findings[0].severity
        == ExposureSeverity.INFO
    )


def test_asset_counts():
    analyzer = ExposureAnalyzer()

    assets = [
        Asset(
            value="example.com",
            type=AssetType.DOMAIN,
            source="scope",
            active=True,
        ),
        Asset(
            value="example.com:80",
            type=AssetType.SERVICE,
            source="service",
            active=True,
        ),
        Asset(
            value="example.com:443",
            type=AssetType.SERVICE,
            source="service",
            active=False,
        ),
    ]

    report = analyzer.analyze(
        assets=assets,
        relations=[],
        changes=[],
    )

    assert (
        report.asset_counts[
            "domain"
        ][
            "active"
        ]
        == 1
    )

    assert (
        report.asset_counts[
            "service"
        ][
            "active"
        ]
        == 1
    )

    assert (
        report.asset_counts[
            "service"
        ][
            "inactive"
        ]
        == 1
    )

def test_expired_certificate_creates_high_finding():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="a" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                - timedelta(
                    days=1
                )
            ).isoformat(),
        },
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    findings = [
        finding
        for finding
        in report.findings
        if (
            finding.rule_id
            == "TLS_CERTIFICATE_EXPIRED"
        )
    ]

    assert len(
        findings
    ) == 1

    assert (
        findings[0].severity
        == ExposureSeverity.HIGH
    )

    assert (
        findings[0].asset_value
        == "a" * 64
    )

def test_expiring_certificate_creates_medium_finding():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="b" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                + timedelta(
                    days=10
                )
            ).isoformat(),
        },
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    findings = [
        finding
        for finding
        in report.findings
        if (
            finding.rule_id
            == "TLS_CERTIFICATE_EXPIRING"
        )
    ]

    assert len(
        findings
    ) == 1

    assert (
        findings[0].severity
        == ExposureSeverity.MEDIUM
    )

def test_valid_certificate_does_not_create_finding():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="c" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                + timedelta(
                    days=90
                )
            ).isoformat(),
        },
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    assert not any(
        finding.rule_id
        in {
            "TLS_CERTIFICATE_EXPIRED",
            "TLS_CERTIFICATE_EXPIRING",
        }
        for finding
        in report.findings
    )

def test_inactive_certificate_does_not_create_finding():
    analyzer = ExposureAnalyzer()

    asset = Asset(
        value="d" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                - timedelta(
                    days=1
                )
            ).isoformat(),
        },
        active=False,
    )

    report = analyzer.analyze(
        assets=[
            asset,
        ],
        relations=[],
        changes=[],
    )

    assert not any(
        finding.rule_id
        in {
            "TLS_CERTIFICATE_EXPIRED",
            "TLS_CERTIFICATE_EXPIRING",
        }
        for finding
        in report.findings
    )

def test_expired_certificate_identifies_affected_service():
    analyzer = ExposureAnalyzer()

    certificate_value = (
        "e" * 64
    )

    certificate = Asset(
        value=certificate_value,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                - timedelta(
                    days=1
                )
            ).isoformat(),
        },
        active=True,
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=(
            AssetRelationType.PRESENTS
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=certificate_value,
        source="tls",
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            certificate,
        ],
        relations=[
            relation,
        ],
        changes=[],
    )

    finding = next(
        finding
        for finding in report.findings
        if (
            finding.rule_id
            == "TLS_CERTIFICATE_EXPIRED"
        )
    )

    assert (
        finding.affected_service
        == "example.com:443"
    )

    assert (
        "example.com:443"
        in finding.description
    )

def test_expiring_certificate_identifies_affected_service():
    analyzer = ExposureAnalyzer()

    certificate_value = (
        "f" * 64
    )

    certificate = Asset(
        value=certificate_value,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                + timedelta(
                    days=10
                )
            ).isoformat(),
        },
        active=True,
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=(
            AssetRelationType.PRESENTS
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=certificate_value,
        source="tls",
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            certificate,
        ],
        relations=[
            relation,
        ],
        changes=[],
    )

    finding = next(
        finding
        for finding in report.findings
        if (
            finding.rule_id
            == "TLS_CERTIFICATE_EXPIRING"
        )
    )

    assert (
        finding.affected_service
        == "example.com:443"
    )

def test_certificate_without_service_keeps_finding():
    analyzer = ExposureAnalyzer()

    certificate = Asset(
        value="1" * 64,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                - timedelta(
                    days=1
                )
            ).isoformat(),
        },
        active=True,
    )

    report = analyzer.analyze(
        assets=[
            certificate,
        ],
        relations=[],
        changes=[],
    )

    finding = next(
        finding
        for finding in report.findings
        if (
            finding.rule_id
            == "TLS_CERTIFICATE_EXPIRED"
        )
    )

    assert (
        finding.affected_service
        is None
    )

def test_inactive_presents_relation_not_correlated():
    analyzer = ExposureAnalyzer()

    certificate_value = (
        "2" * 64
    )

    certificate = Asset(
        value=certificate_value,
        type=AssetType.CERTIFICATE,
        source="tls",
        metadata={
            "valid_to": (
                datetime.now(
                    timezone.utc
                )
                - timedelta(
                    days=1
                )
            ).isoformat(),
        },
        active=True,
    )

    relation = AssetRelation(
        source_type=AssetType.SERVICE,
        source_value="example.com:443",
        relation=(
            AssetRelationType.PRESENTS
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=certificate_value,
        source="tls",
        active=False,
    )

    report = analyzer.analyze(
        assets=[
            certificate,
        ],
        relations=[
            relation,
        ],
        changes=[],
    )

    finding = next(
        finding
        for finding in report.findings
        if (
            finding.rule_id
            == "TLS_CERTIFICATE_EXPIRED"
        )
    )

    assert (
        finding.affected_service
        is None
    )

def test_finding_id_is_deterministic():
    finding_a = ExposureFinding(
        rule_id="HTTP_WITHOUT_TLS",
        severity=ExposureSeverity.MEDIUM,
        title="HTTP service exposed without TLS",
        description="Description A",
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
    )

    finding_b = ExposureFinding(
        rule_id="HTTP_WITHOUT_TLS",
        severity=ExposureSeverity.HIGH,
        title="Changed title",
        description="Changed description",
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
    )

    assert (
        finding_a.finding_id
        == finding_b.finding_id
    )

    assert len(
        finding_a.finding_id
    ) == 64


def test_finding_id_changes_with_asset():
    finding_a = ExposureFinding(
        rule_id="HTTP_WITHOUT_TLS",
        severity=ExposureSeverity.MEDIUM,
        title="HTTP without TLS",
        description="Test",
        asset_type=AssetType.SERVICE,
        asset_value="example.com:80",
    )

    finding_b = ExposureFinding(
        rule_id="HTTP_WITHOUT_TLS",
        severity=ExposureSeverity.MEDIUM,
        title="HTTP without TLS",
        description="Test",
        asset_type=AssetType.SERVICE,
        asset_value="example.com:8080",
    )

    assert (
        finding_a.finding_id
        != finding_b.finding_id
    )
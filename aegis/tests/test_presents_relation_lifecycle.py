from pathlib import Path

from typer.testing import CliRunner

from aegis.assessment import AssessmentContext
from aegis.cli import app
from aegis.context import CampaignContext
from aegis.models import (
    AssetRelationType,
    AssetType,
    ChangeType,
)
from aegis.results import Observation


runner = CliRunner()

CERT_A = "a" * 64
CERT_B = "b" * 64


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


def reopen_context(
    campaign_dir: Path,
) -> AssessmentContext:
    return AssessmentContext(
        CampaignContext(
            campaign_dir
        )
    )


def get_presents_relation(
    context: AssessmentContext,
    certificate: str,
):
    return next(
        relation
        for relation
        in context.relations.find()
        if (
            relation.source_type
            == AssetType.SERVICE
            and relation.source_value
            == "example.com:443"
            and relation.relation
            == AssetRelationType.PRESENTS
            and relation.target_type
            == AssetType.CERTIFICATE
            and relation.target_value
            == certificate
        )
    )


def get_certificate_asset(
    context: AssessmentContext,
    certificate: str,
):
    return next(
        asset
        for asset
        in context.assets.find(
            asset_type=AssetType.CERTIFICATE,
        )
        if asset.value == certificate
    )


def test_presents_relation_lifecycle(
    tmp_path,
    monkeypatch,
):
    context = create_context(
        tmp_path
    )

    campaign_dir = context.root

    context.scope.add(
        "example.com"
    )

    certificates = [
        CERT_A,
        CERT_B,
        CERT_B,
        CERT_A,
    ]

    call_index = {
        "value": 0,
    }

    def fake_inspect_tls(
        host,
        port,
    ):
        certificate = certificates[
            call_index["value"]
        ]

        return Observation(
            target=host,
            type="tls_handshake",
            data={
                "host": host,
                "port": port,
                "tls_version": "TLSv1.3",
                "cipher": (
                    "TLS_AES_256_GCM_SHA384"
                ),
                "subject": None,
                "issuer": None,
                "valid_from": None,
                "valid_to": None,
                "sans": [
                    "example.com",
                ],
                "certificate_sha256": (
                    certificate
                ),
            },
        )

    monkeypatch.setattr(
        (
            "aegis.plugins.builtin."
            "tls.plugin.inspect_tls"
        ),
        fake_inspect_tls,
    )

    monkeypatch.chdir(
        campaign_dir
    )

    # -------------------------------------------------
    # RUN #1
    # SERVICE apresenta CERT_A.
    # A relation PRESENTS deve nascer ativa.
    # -------------------------------------------------

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "tls",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation_a = get_presents_relation(
        context,
        CERT_A,
    )

    assert relation_a.active is True

    certificate_a = get_certificate_asset(
        context,
        CERT_A,
    )

    assert certificate_a.active is True

    # -------------------------------------------------
    # RUN #2
    # Serviço passa a apresentar CERT_B.
    #
    # CERT_A deixa de ser apresentado:
    # CANDIDATE_MISSING #1.
    #
    # A relação antiga continua ativa.
    # -------------------------------------------------

    call_index["value"] = 1

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "tls",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation_a = get_presents_relation(
        context,
        CERT_A,
    )

    relation_b = get_presents_relation(
        context,
        CERT_B,
    )

    assert relation_a.active is True
    assert relation_b.active is True

    missing_a = context.changes.find(
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
            "example.com:443"
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=CERT_A,
    )

    assert len(missing_a) == 1

    # O certificado A enquanto asset continua ativo.
    #
    # O que está em dúvida é a relação
    # SERVICE --presents--> CERT_A.
    certificate_a = get_certificate_asset(
        context,
        CERT_A,
    )

    assert certificate_a.active is True

    # -------------------------------------------------
    # RUN #3
    # Continua a apresentar CERT_B.
    #
    # CERT_A:
    # CANDIDATE_MISSING #2
    # → PRESENTS torna-se INACTIVE.
    # -------------------------------------------------

    call_index["value"] = 2

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "tls",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation_a = get_presents_relation(
        context,
        CERT_A,
    )

    relation_b = get_presents_relation(
        context,
        CERT_B,
    )

    assert relation_a.active is False
    assert relation_b.active is True

    missing_a = context.changes.find(
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
            "example.com:443"
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=CERT_A,
    )

    assert len(missing_a) == 2

    inactive_a = context.changes.find(
        change_type=(
            ChangeType.INACTIVE
        ),
        relation_type=(
            AssetRelationType.PRESENTS
        ),
        source_type=(
            AssetType.SERVICE
        ),
        source_value=(
            "example.com:443"
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=CERT_A,
    )

    assert len(inactive_a) == 1

    # Continua a não inativar o asset certificado.
    certificate_a = get_certificate_asset(
        context,
        CERT_A,
    )

    assert certificate_a.active is True

    # -------------------------------------------------
    # RUN #4
    # CERT_A volta a ser apresentado.
    #
    # A antiga relação PRESENTS deve reativar.
    # -------------------------------------------------

    call_index["value"] = 3

    result = runner.invoke(
        app,
        [
            "plugin",
            "run",
            "tls",
        ],
    )

    assert result.exit_code == 0

    context = reopen_context(
        campaign_dir
    )

    relation_a = get_presents_relation(
        context,
        CERT_A,
    )

    assert relation_a.active is True

    reactivated_a = context.changes.find(
        change_type=(
            ChangeType.REACTIVATED
        ),
        relation_type=(
            AssetRelationType.PRESENTS
        ),
        source_type=(
            AssetType.SERVICE
        ),
        source_value=(
            "example.com:443"
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=CERT_A,
    )

    assert len(reactivated_a) == 1

    reactivated = reactivated_a[0]

    assert (
        reactivated.plugin
        == "tls"
    )

    assert (
        reactivated.target
        == "example.com"
    )

    assert (
        reactivated.current_result
        is not None
    )

    # O histórico INACTIVE continua preservado
    # depois da reativação.
    inactive_a = context.changes.find(
        change_type=(
            ChangeType.INACTIVE
        ),
        relation_type=(
            AssetRelationType.PRESENTS
        ),
        source_type=(
            AssetType.SERVICE
        ),
        source_value=(
            "example.com:443"
        ),
        target_type=(
            AssetType.CERTIFICATE
        ),
        target_value=CERT_A,
    )

    assert len(inactive_a) == 1

    # E CERT_A continua a existir como asset ativo.
    certificate_a = get_certificate_asset(
        context,
        CERT_A,
    )

    assert certificate_a.active is True
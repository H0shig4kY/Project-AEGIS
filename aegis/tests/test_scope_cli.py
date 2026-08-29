from pathlib import Path

from typer.testing import CliRunner

from aegis.cli import app


runner = CliRunner()


def create_campaign(
    tmp_path: Path,
):
    campaign = tmp_path / "campaign"
    campaign.mkdir()

    (campaign / "aegis.yaml").write_text(
        "name: test\n",
        encoding="utf-8",
    )

    return campaign


def test_scope_add_duplicate_reports_already_in_scope(
    tmp_path,
    monkeypatch,
):
    campaign = create_campaign(
        tmp_path
    )

    monkeypatch.chdir(
        campaign
    )

    first = runner.invoke(
        app,
        [
            "scope",
            "add",
            "104.20.23.154",
        ],
    )

    assert first.exit_code == 0

    assert (
        "Added ip: 104.20.23.154"
        in first.output
    )

    second = runner.invoke(
        app,
        [
            "scope",
            "add",
            "104.20.23.154",
        ],
    )

    assert second.exit_code == 0

    assert (
        "Already in scope: 104.20.23.154"
        in second.output
    )
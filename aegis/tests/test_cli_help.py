from typer.testing import CliRunner

from aegis.cli import app


runner = CliRunner()


def test_root_cli_shows_interface():
    result = runner.invoke(
        app,
        [],
    )

    assert result.exit_code == 0

    assert "AEGIS" in result.output
    assert "ARGUS" in result.output

    assert "USAGE" in result.output
    assert "COMMANDS" in result.output

    assert "scope" in result.output
    assert "plugin" in result.output
    assert "assets" in result.output
    assert "relations" in result.output
    assert "changes" in result.output
    assert "results" in result.output

    assert (
        "aegis <command> --help"
        in result.output
    )


def test_root_help_still_works():
    result = runner.invoke(
        app,
        [
            "--help",
        ],
    )

    assert result.exit_code == 0

    assert "Usage" in result.output
    assert "scope" in result.output
    assert "plugin" in result.output


def test_info_uses_rich_interface():
    result = runner.invoke(
        app,
        [
            "info",
        ],
    )

    assert result.exit_code == 0

    assert "CAPABILITIES" in result.output
    assert "TRACKED RELATIONS" in result.output
    assert "LIFECYCLE" in result.output

    assert "resolves_to" in result.output
    assert "exposes" in result.output
    assert "presents" in result.output
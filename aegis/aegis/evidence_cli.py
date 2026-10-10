"""Evidence commands: explicit writes, read-only queries, no network activity."""

from pathlib import Path

import typer
from pydantic import ValidationError

from aegis.context import find_campaign
from aegis.evidence_manager import EvidenceManager
from aegis.evidence_store import EvidenceReader
from aegis.finding_snapshot import require_finding
from aegis.findings_report import render_json
from aegis.validation_errors import validation_summary


def _campaign():
    campaign = find_campaign()
    if campaign is None:
        raise LookupError('No AEGIS assessment found')
    return campaign


def _run(action, json_output):
    try:
        value = action()
        if hasattr(value, 'model_dump'):
            value = value.model_dump(mode='json')
        if json_output:
            typer.echo(render_json(value), nl=False)
        elif isinstance(value, list):
            if not value:
                typer.echo('No evidence associations.')
            for record in value:
                typer.echo(f"{record['evidence_id']} {record['kind']} {record['registered_at']}")
        else:
            typer.echo(render_json(value), nl=False)
    except (ValueError, LookupError, OSError, TypeError) as error:
        message = validation_summary(error) if isinstance(error, ValidationError) else str(error)
        typer.echo(f'Error: {message}', err=True)
        raise typer.Exit(code=1) from error


def register_evidence_commands(findings_app):
    app = typer.Typer(help='Associate and verify immutable evidence; no network requests.')
    findings_app.add_typer(app, name='evidence')

    @app.command('add-file')
    def add_file(finding_id: str, path: Path,
                 actor: str = typer.Option(..., '--actor'),
                 reason: str = typer.Option(..., '--reason'),
                 json_output: bool = typer.Option(False, '--json')):
        """Capture a regular local file and associate it with a finding."""
        _run(lambda: EvidenceManager(_campaign()).attach_file(finding_id, path,
            actor=actor, reason=reason), json_output)

    @app.command('add-observation')
    def add_observation(finding_id: str,
                        result_filename: str = typer.Option(..., '--result'),
                        observation_index: int = typer.Option(..., '--index', min=0),
                        actor: str = typer.Option(..., '--actor'),
                        reason: str = typer.Option(..., '--reason'),
                        json_output: bool = typer.Option(False, '--json')):
        """Snapshot one explicitly selected stored observation."""
        _run(lambda: EvidenceManager(_campaign()).attach_observation(finding_id,
            result_filename, observation_index, actor=actor, reason=reason), json_output)

    @app.command('add-reference')
    def add_reference(finding_id: str,
                      source: str = typer.Option(..., '--source'),
                      actor: str = typer.Option(..., '--actor'),
                      reason: str = typer.Option(..., '--reason'),
                      json_output: bool = typer.Option(False, '--json')):
        """Associate a declarative external reference without fetching it."""
        _run(lambda: EvidenceManager(_campaign()).attach_reference(finding_id,
            source, actor=actor, reason=reason), json_output)

    @app.command('list')
    def list_evidence(finding_id: str, json_output: bool = typer.Option(False, '--json')):
        """List associations after reading and verifying captured bytes."""
        def read():
            campaign = _campaign()
            require_finding(campaign, finding_id)
            return [record.model_dump(mode='json') for record in
                    EvidenceReader(campaign).list_for_finding(finding_id)]
        _run(read, json_output)

    @app.command('show')
    def show(evidence_id: str, json_output: bool = typer.Option(False, '--json')):
        """Show verified metadata, never captured content."""
        _run(lambda: EvidenceReader(_campaign()).get(evidence_id), json_output)

    @app.command('verify')
    def verify(evidence_id: str, json_output: bool = typer.Option(False, '--json')):
        """Verify bytes without persisting verification timestamps or repairs."""
        _run(lambda: EvidenceReader(_campaign()).verify(evidence_id), json_output)

"""Explicit custody writes and package output; all inspection commands are read-only."""
from enum import Enum
from pathlib import Path

import typer

from aegis.atomic_storage import StorageIntegrityError
from aegis.assessment_package import AssessmentExporter, AssessmentPackageReader
from aegis.context import find_campaign
from aegis.custody import CustodyManager, CustodyReader, read, strict_json
from aegis.findings_report import render_json


class ExportProfile(str, Enum):
    SHARE = 'share'
    FORENSIC = 'forensic'


def campaign():
    value = find_campaign()
    if value is None:
        raise LookupError('Assessment not found')
    return value


def run(action):
    try:
        result = action()
        typer.echo(render_json(result), nl=False)
    except RuntimeError as error:
        # Python 3.12 Path.resolve reports a symlink cycle as RuntimeError.
        # Preserve unrelated programming errors rather than hiding them.
        if not str(error).startswith('Symlink loop from '):
            raise
        typer.echo('Error: a path contains a symbolic-link cycle.',err=True)
        raise typer.Exit(1) from None
    except (OSError, ValueError, LookupError, TypeError, RecursionError, OverflowError):
        # Inputs and parser/OS diagnostics may contain source values or paths.
        typer.echo('Error: operation failed validation, access or integrity checks; no automatic recovery was performed.',err=True)
        raise typer.Exit(1) from None


def register_custody_commands(app, findings_app):
    assessment = typer.Typer(help='Portable assessment exports and explicit custody operations.')
    custody = typer.Typer(help='Hash integrity only; operators are declared, not authenticated.')
    package = typer.Typer(help='Inspect packages without extraction, import or network access.')
    app.add_typer(assessment,name='assessment')
    assessment.add_typer(custody,name='custody')
    assessment.add_typer(package,name='package')

    @custody.command('init')
    def initialize(actor: str=typer.Option(...,'--actor'),reason: str=typer.Option(...,'--reason'),
                   json_output: bool=typer.Option(False,'--json')):
        """Explicitly activate custody with an inventory of existing evidence."""
        run(lambda: CustodyManager(campaign()).initialize(actor=actor,reason=reason))

    @custody.command('recover')
    def recover(actor: str=typer.Option(...,'--actor'),reason: str=typer.Option(...,'--reason'),
                json_output: bool=typer.Option(False,'--json')):
        """Complete a valid pending intent; never overwrite contradictory data."""
        run(lambda: CustodyManager(campaign()).recover(actor=actor,reason=reason))

    @custody.command('verify')
    def verify(checkpoint: Path|None=typer.Option(None,'--checkpoint'),
               json_output: bool=typer.Option(False,'--json')):
        """Read and verify the chain; an external checkpoint must already be trusted."""
        run(lambda: CustodyReader(campaign()).verify(
            expected_checkpoint=strict_json(read(checkpoint,65536)) if checkpoint else None))

    # Attach to the existing evidence command group, preserving its commands.
    evidence = next(group.typer_instance for group in findings_app.registered_groups if group.name=='evidence')
    @evidence.command('custody-history')
    def history(evidence_id: str,json_output: bool=typer.Option(False,'--json')):
        """List custody events by sequence without recording this consultation."""
        run(lambda: CustodyReader(campaign()).list_events(evidence_id))

    @assessment.command('export')
    def export(output: Path=typer.Option(...,'--output'),
               profile: str=typer.Option('share','--profile',help='Export profile: share or forensic.'),
               include_objects: bool=typer.Option(False,'--include-objects'),
               json_output: bool=typer.Option(False,'--json')):
        """Export outside the assessment. Share is minimization, not anonymization."""
        if profile not in ('share','forensic'):
            typer.echo('Error: --profile must be share or forensic.',err=True)
            raise typer.Exit(2)
        if profile=='forensic':
            typer.echo('Warning: forensic packages may contain sensitive data in plaintext; the package is not encrypted.',err=True)
        run(lambda: AssessmentExporter(campaign()).export(output,profile=profile,include_objects=include_objects))

    @package.command('verify')
    def verify_package(path: Path,expected_sha256: str|None=typer.Option(None,'--expected-sha256'),
                       checkpoint: Path|None=typer.Option(None,'--checkpoint'),
                       json_output: bool=typer.Option(False,'--json')):
        """Verify independently; hashes do not authenticate the package origin."""
        run(lambda: AssessmentPackageReader().verify(path,expected_sha256=expected_sha256,
            expected_checkpoint=strict_json(read(checkpoint,65536)) if checkpoint else None))

    @package.command('inspect')
    def inspect_package(path: Path,json_output: bool=typer.Option(False,'--json')):
        """Validate and show the manifest without extracting files."""
        run(lambda: AssessmentPackageReader().inspect(path))

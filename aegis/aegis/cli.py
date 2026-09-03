from datetime import (
    datetime,
    timezone,
)
from pathlib import Path

import json
import typer

from aegis.assessment import AssessmentContext
from aegis.change_engine import ChangeEngine
from aegis.change_history import (
    find_previous_comparable_result,
)
from aegis.config import AegisConfig
from aegis.context import find_campaign
from aegis.integrity import (
    sha256_file,
    verify_result_file,
)
from aegis.models import (
    AssetRelationType,
    AssetType,
    ChangeType,
    IntegrityBaselineType,
    FindingState,
)
from aegis.plugins.registry import (
    create_plugin_manager,
)
from aegis.scope_manager import ScopeManager

from aegis.cli_ui import (
    print_assets_table,
    print_changes_table,
    print_empty,
    print_error,
    print_info,
    print_plugin_run_output,
    print_plugin_table,
    print_relations_table,
    print_results_table,
    print_root_interface,
    print_scope_table,
    print_success,
    print_version,
    print_warning,
    print_status_dashboard,
    print_commands_reference,
    set_compact_mode,
    print_exposure_dashboard,
    print_findings_table,
    print_finding_detail,
)

from aegis.exposure import (
    ExposureAnalyzer,
    ExposureSeverity,
)

AEGIS_VERSION = "0.1.0"

app = typer.Typer(
    name="aegis",
    help=(
        "AEGIS / ARGUS - Authorized Reconnaissance, "
        "Asset Discovery and Lifecycle Analysis Engine."
    ),
    no_args_is_help=False,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)

scope_app = typer.Typer(
    help="Manage the authorized assessment scope.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

plugin_app = typer.Typer(
    help="List and execute reconnaissance plugins.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

assets_app = typer.Typer(
    help=(
        "Inspect discovered assets, graphs "
        "and lifecycle history."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

relations_app = typer.Typer(
    help=(
        "Inspect relationships between "
        "discovered assets."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

changes_app = typer.Typer(
    help=(
        "Inspect detected asset and relation "
        "lifecycle changes."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

results_app = typer.Typer(
    help=(
        "Inspect and verify persisted "
        "plugin results."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

findings_app = typer.Typer(
    help="Inspect current exposure findings."
)

app.add_typer(
    findings_app,
    name="findings",
)

app.add_typer(
    scope_app,
    name="scope",
)

app.add_typer(
    plugin_app,
    name="plugin",
)

app.add_typer(
    assets_app,
    name="assets",
)

app.add_typer(
    relations_app,
    name="relations",
)

app.add_typer(
    changes_app,
    name="changes",
)

app.add_typer(
    results_app,
    name="results",
)


@app.callback(
    invoke_without_command=True,
)
def main(
    ctx: typer.Context,
    compact: bool = typer.Option(
        False,
        "--compact",
        help=(
            "Force compact terminal layout. "
            "Without this option AEGIS adapts automatically."
        ),
    ),
):
    """AEGIS / ARGUS command-line interface."""

    set_compact_mode(
        True
        if compact
        else None
    )

    if ctx.invoked_subcommand is None:
        print_root_interface()

@app.command()
def version():
    """Show AEGIS / ARGUS version."""

    print_version(
        AEGIS_VERSION
    )

@app.command()
def info():
    """Show AEGIS / ARGUS capabilities."""

    print_info()

@app.command()
def commands():
    """Show common AEGIS / ARGUS commands and examples."""

    print_commands_reference()

@app.command()
def exposure(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output exposure summary as JSON.",
    ),
):
    """Show the current assessed exposure surface."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    # -------------------------------------------------
    # COLLECT CURRENT CAMPAIGN STATE
    # -------------------------------------------------

    assets = context.assets.find()
    relations = context.relations.find()
    changes = context.changes.find()

    # -------------------------------------------------
    # EXPOSURE ANALYSIS
    # -------------------------------------------------

    analyzer = ExposureAnalyzer()

    report = analyzer.analyze(
        assets=assets,
        relations=relations,
        changes=changes,
    )

    # Keep recent exposure-related changes for the
    # dashboard. Exposure findings themselves are
    # produced by ExposureAnalyzer.
    changes.sort(
        key=lambda change: (
            change.detected_at
        ),
        reverse=True,
    )

    recent_changes = [
        change
        for change in changes
        if (
            change.asset_type
            == AssetType.SERVICE
            or change.relation_type
            in {
                AssetRelationType.EXPOSES,
                AssetRelationType.PRESENTS,
            }
        )
    ][:10]

    # Active PRESENTS relations are still useful for
    # the current CLI TLS table.
    tls_relations = [
        relation
        for relation in relations
        if (
            relation.relation
            == AssetRelationType.PRESENTS
            and relation.active
        )
    ]

    # -------------------------------------------------
    # JSON OUTPUT
    # -------------------------------------------------

    if json_output:
        payload = {
            "assets": (
                report.asset_counts
            ),
            "services": [
                {
                    "value": service.value,
                    "host": service.host,
                    "port": service.port,
                    "service_name": (
                        service.service_name
                    ),
                    "transport": (
                        service.transport
                    ),
                    "tls": service.tls,
                    "certificate": (
                        service.certificate
                    ),
                    "source": (
                        service.source
                    ),
                    "active": (
                        service.active
                    ),
                }
                for service
                in report.services
            ],
            "findings": [
                {
                    "rule_id": (
                        finding.rule_id
                    ),
                    "severity": (
                        finding.severity.value
                    ),
                    "title": (
                        finding.title
                    ),
                    "description": (
                        finding.description
                    ),
                    "asset_type": (
                        finding.asset_type.value
                    ),
                    "asset_value": (
                        finding.asset_value
                    ),
                    "affected_service": (
                        finding.affected_service
                    ),
                    "plugin": (
                        finding.plugin
                    ),
                }
                for finding
                in report.findings
            ],
            "tls_relations": [
                {
                    "service": (
                        relation.source_value
                    ),
                    "certificate": (
                        relation.target_value
                    ),
                    "active": (
                        relation.active
                    ),
                }
                for relation
                in tls_relations
            ],
            "recent_changes": [
                {
                    "change_type": (
                        change.change_type.value
                    ),
                    "plugin": (
                        change.plugin
                    ),
                }
                for change
                in recent_changes
            ],
        }

        typer.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )

        return

    # -------------------------------------------------
    # HUMAN-READABLE OUTPUT
    # -------------------------------------------------

    print_exposure_dashboard(
        asset_counts=(
            report.asset_counts
        ),
        services=(
            report.services
        ),
        tls_relations=(
            tls_relations
        ),
        recent_changes=(
            recent_changes
        ),
        findings=(
            report.findings
        ),
    )

@app.command()
def status(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output campaign status as JSON.",
    ),
):
    """Show an operational overview of the current campaign."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    # -------------------------------------------------
    # CAMPAIGN
    # -------------------------------------------------

    campaign_name = (
        campaign.root.name
        if hasattr(
            campaign,
            "root",
        )
        else Path.cwd().name
    )

    # -------------------------------------------------
    # SCOPE
    # -------------------------------------------------

    scope_counts: dict[
        str,
        int,
    ] = {}

    for target in context.scope.list():
        key = target.type.value

        scope_counts[key] = (
            scope_counts.get(
                key,
                0,
            )
            + 1
        )

    # -------------------------------------------------
    # ASSETS
    # -------------------------------------------------

    assets = context.assets.find()

    active_assets = sum(
        1
        for asset in assets
        if asset.active
    )

    inactive_assets = (
        len(assets)
        - active_assets
    )

    # -------------------------------------------------
    # RELATIONS
    # -------------------------------------------------

    relations = (
        context.relations.find()
    )

    active_relations = sum(
        1
        for relation in relations
        if relation.active
    )

    inactive_relations = (
        len(relations)
        - active_relations
    )

    # -------------------------------------------------
    # CHANGES
    # -------------------------------------------------

    changes = (
        context.changes.find()
    )

    changes.sort(
        key=lambda change: (
            change.detected_at
        ),
        reverse=True,
    )

    recent_changes = (
        changes[:5]
    )

    # -------------------------------------------------
    # RESULTS
    # -------------------------------------------------

    result_paths = (
        context.results.list()
    )

    latest_result = None

    if result_paths:
        latest_path = max(
            result_paths,
            key=lambda path: (
                path.stat().st_mtime
            ),
        )

        try:
            latest = (
                context.results.load(
                    latest_path
                )
            )

            latest_result = (
                latest_path,
                latest,
            )

        except Exception:
            latest_result = None


    # -------------------------------------------------
    # INTEGRITY
    # -------------------------------------------------

    integrity_verification = {
        "OK": 0,
        "FAILED": 0,
        "UNKNOWN": 0,
        "CONFLICT": 0,
    }

    integrity_baselines = {
        "ORIGINAL": 0,
        "RETROSPECTIVE": 0,
    }

    for path in result_paths:
        record = (
            context.integrity.get(
                path.name
            )
        )

        status_value, _, _ = (
            verify_result_file(
                path,
                assets,
                integrity_record=record,
            )
        )

        # -----------------------------------------
        # Verification state
        # -----------------------------------------

        if status_value in {
            "OK",
            "BASELINED",
        }:
            integrity_verification[
                "OK"
            ] += 1

        elif status_value in {
            "FAILED",
            "UNKNOWN",
            "CONFLICT",
        }:
            integrity_verification[
                status_value
            ] += 1

        # -----------------------------------------
        # Baseline type
        # -----------------------------------------

        if record is not None:
            baseline_type = (
                record.baseline_type.value.upper()
            )

            if baseline_type in (
                integrity_baselines
            ):
                integrity_baselines[
                    baseline_type
                ] += 1

    # -------------------------------------------------
    # JSON
    # -------------------------------------------------

    if json_output:
        payload = {
            "campaign": (
                campaign_name
            ),
            "scope": (
                scope_counts
            ),
            "assets": {
                "total": len(
                    assets
                ),
                "active": (
                    active_assets
                ),
                "inactive": (
                    inactive_assets
                ),
            },
            "relations": {
                "total": len(
                    relations
                ),
                "active": (
                    active_relations
                ),
                "inactive": (
                    inactive_relations
                ),
            },
            "changes": {
                "total": len(
                    changes
                ),
                "recent": [
                    {
                        "change_type": (
                            change.change_type.value
                        ),
                        "plugin": (
                            change.plugin
                        ),
                    }
                    for change
                    in recent_changes
                ],
            },
            "results": {
                "total": len(
                    result_paths
                ),
            },
            "integrity": {
                "verification": (
                    integrity_verification
                ),
                "baselines": (
                    integrity_baselines
                ),
            },
        }

        if latest_result is not None:
            (
                latest_path,
                latest,
            ) = latest_result

            payload[
                "latest_result"
            ] = {
                "filename": (
                    latest_path.name
                ),
                "plugin": (
                    latest.plugin
                ),
                "version": (
                    latest.version
                ),
                "timestamp": (
                    latest.timestamp.isoformat()
                ),
            }

        else:
            payload[
                "latest_result"
            ] = None

        typer.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )

        return

    # -------------------------------------------------
    # HUMAN OUTPUT
    # -------------------------------------------------

    print_status_dashboard(
        campaign_name=(
            campaign_name
        ),
        scope_counts=(
            scope_counts
        ),
        active_assets=(
            active_assets
        ),
        inactive_assets=(
            inactive_assets
        ),
        active_relations=(
            active_relations
        ),
        inactive_relations=(
            inactive_relations
        ),
        changes_count=(
            len(changes)
        ),
        results_count=(
            len(result_paths)
        ),
        integrity_verification=(
            integrity_verification
        ),
        integrity_baselines=(
            integrity_baselines
        ),
        recent_changes=(
            recent_changes
        ),
        latest_result=(
            latest_result
        ),
    )

@app.command()
def init(name: str):
    """Create a new AEGIS / ARGUS assessment campaign."""

    root = Path.cwd() / name

    if root.exists():
        print_error(
            f"directory already exists: {root}"
        )
        raise typer.Exit(code=1)

    root.mkdir(parents=True)

    (root / "data").mkdir()
    (root / "evidence").mkdir()
    (root / "reports").mkdir()

    config = AegisConfig(root)
    config.create()

    print_success(
        f"AEGIS / ARGUS campaign created: {root}"
    )

def get_scope_manager() -> ScopeManager:
    context = find_campaign()

    if context is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        print_warning(
            "Run this command inside an AEGIS / ARGUS campaign directory."
        )
        raise typer.Exit(code=1)

    return ScopeManager(
        context.scope_file
    )

@scope_app.command("add")
def scope_add(value: str):
    """Add a target to the current campaign scope."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    before = {
        (
            target.type.value,
            target.value,
        )
        for target in context.scope.list()
    }

    try:
        context.scope.add(
            value
        )
    except ValueError as exc:
        print_error(
            str(exc)
        )
        raise typer.Exit(code=1)

    after = {
        (
            target.type.value,
            target.value,
        )
        for target in context.scope.list()
    }

    new_entries = (
        after - before
    )

    if not new_entries:
        print_warning(
            f"Already in scope: {value}"
        )
        return

    target_type, target_value = next(
        iter(new_entries)
    )

    print_success(
        f"Added {target_type}: {target_value}"
    )

@scope_app.command("list")
def scope_list():
    """List all targets in the assessment scope."""

    manager = get_scope_manager()

    targets = manager.list()

    print_scope_table(
        targets
    )

@scope_app.command("remove")
def scope_remove(target: str):
    """Remove a target from the assessment scope."""

    manager = get_scope_manager()

    removed = manager.remove(
        target
    )

    if not removed:
        print_error(
            f"Target not found: {target}"
        )
        raise typer.Exit(code=1)

    print_success(
        f"Removed: {target}"
    )

@plugin_app.command("list")
def plugin_list():
    """List installed AEGIS / ARGUS plugins."""

    manager = create_plugin_manager()

    plugins = manager.list()

    print_plugin_table(
        plugins
    )

@plugin_app.command("run")
def plugin_run(name: str):
    """Execute an AEGIS / ARGUS plugin against the current campaign."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    manager = create_plugin_manager()

    context = AssessmentContext(
        campaign
    )

    change_engine = ChangeEngine(
        context
    )

    detected_changes = []
    previous_path = None

    # -------------------------------------------------
    # PRE-EXECUTION STATE SNAPSHOT
    # -------------------------------------------------

    inactive_assets_before = {
        (
            asset.type,
            asset.value,
        )
        for asset in context.assets.find()
        if not asset.active
    }

    inactive_relations_before = {
        (
            relation.source_type,
            relation.source_value,
            relation.relation,
            relation.target_type,
            relation.target_value,
        )
        for relation in context.relations.find()
        if not relation.active
    }

    try:
        # -------------------------------------------------
        # PLUGIN EXECUTION
        # -------------------------------------------------

        result = manager.execute(
            name,
            context,
        )

        saved_path = context.results.save(
            result
        )

        # -------------------------------------------------
        # PREVIOUS COMPARABLE RESULT
        # -------------------------------------------------

        if result.plugin in {
            "service",
            "dns",
            "tls",
        }:
            previous = (
                find_previous_comparable_result(
                    context.results,
                    result,
                    current_path=saved_path,
                )
            )

            if previous is not None:
                (
                    previous_path,
                    _,
                ) = previous

        # -------------------------------------------------
        # CHANGE ENGINE
        # missing -> inactive
        # -------------------------------------------------

        detected_changes.extend(
            change_engine.process_missing(
                result,
                saved_path=saved_path,
                previous_path=previous_path,
            )
        )

        # -------------------------------------------------
        # RESULT INTEGRITY
        # -------------------------------------------------

        saved_sha256 = sha256_file(
            saved_path
        )

        context.integrity.upsert(
            filename=saved_path.name,
            sha256=saved_sha256,
            baseline_type=(
                IntegrityBaselineType.ORIGINAL
            ),
            created_at=result.timestamp,
        )

        # -------------------------------------------------
        # OBSERVATION PROCESSING
        # -------------------------------------------------

        processing = (
            context.observation_processor.process(
                result,
                result_path=saved_path,
                result_sha256=saved_sha256,
            )
        )

        # -------------------------------------------------
        # CHANGE ENGINE
        # inactive -> reactivated
        # -------------------------------------------------

        detected_changes.extend(
            change_engine.process_reactivated(
                result,
                processing=processing,
                inactive_assets_before=(
                    inactive_assets_before
                ),
                inactive_relations_before=(
                    inactive_relations_before
                ),
                saved_path=saved_path,
                previous_path=previous_path,
            )
        )

        # -------------------------------------------------
        # EXPOSURE FINDING LIFECYCLE
        # -------------------------------------------------

        context.finding_processor.process(
            observed_at=result.timestamp,
            observed_plugin=result.plugin,
        )

    except ValueError as exc:
        print_error(
            str(exc)
        )
        raise typer.Exit(code=1)

    # -------------------------------------------------
    # CLI OUTPUT
    # -------------------------------------------------

    print_plugin_run_output(
        result,
        processing,
        detected_changes,
        saved_path,
    )

@results_app.command("list")
def results_list():
    """List stored plugin results."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    results = context.results.list()

    print_results_table(
        results
    )

@results_app.command("show")
def results_show(filename: str):
    """Show a stored plugin result."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    path = context.results.directory / filename

    if not path.exists():
        typer.echo(
            f"Error: result not found: {filename}"
        )
        raise typer.Exit(code=1)

    try:
        result = context.results.load(path)

    except Exception as exc:
        typer.echo(
            f"Error loading result: {exc}"
        )
        raise typer.Exit(code=1)

    typer.echo(f"Plugin: {result.plugin}")
    typer.echo(f"Version: {result.version}")
    typer.echo(f"Status: {result.status}")
    typer.echo(f"Timestamp: {result.timestamp}")
    typer.echo("")

    typer.echo(
        f"Observations: "
        f"{len(result.observations)}"
    )

    for observation in result.observations:
        typer.echo("")
        typer.echo(
            f"Target: {observation.target}"
        )
        typer.echo(
            f"Type: {observation.type}"
        )
        typer.echo(
            f"Data: {observation.data}"
        )

@results_app.command("verify")
def results_verify(filename: str):
    """Verify the integrity of a stored plugin result."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    result_dir = context.results.directory.resolve()
    path = (result_dir / filename).resolve()

    # Prevent path traversal outside results directory.
    try:
        path.relative_to(result_dir)
    except ValueError:
        typer.echo("Error: invalid result path.")
        raise typer.Exit(code=1)

    if not path.exists() or not path.is_file():
        typer.echo(
            f"Error: result not found: {filename}"
        )
        raise typer.Exit(code=1)

    assets = context.assets.find()

    integrity_record = context.integrity.get(
        filename
    )

    status, expected, current = (
        verify_result_file(
            path,
            assets,
            integrity_record=integrity_record,
        )
    )

    typer.echo("Result integrity")
    typer.echo(f"Result: {filename}")
    typer.echo(
        f"Current SHA-256: {current}"
    )

    if expected is not None:
        typer.echo(
            f"Stored SHA-256: {expected}"
        )
    else:
        typer.echo(
            "Stored SHA-256: unavailable"
        )

    typer.echo(
        f"Integrity: {status}"
    )

    if status in {
        "OK",
        "BASELINED",
    }:
        context.integrity.mark_verified(
            filename
        )
        return

    if status == "UNKNOWN":
        raise typer.Exit(code=2)

    raise typer.Exit(code=1)


@results_app.command("verify-all")
def results_verify_all():
    """Verify integrity of all stored plugin results."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    results = context.results.list()

    if not results:
        typer.echo("No results found.")
        return

    assets = context.assets.find()

    ok_count = 0
    baselined_count = 0
    failed_count = 0
    unknown_count = 0
    conflict_count = 0

    typer.echo("Result integrity")
    typer.echo("")

    for path in results:
        integrity_record = context.integrity.get(
            path.name
        )

        status, _, _ = verify_result_file(
            path,
            assets,
            integrity_record=integrity_record,
        )

        typer.echo(
            f"{path.name:<45} {status}"
        )

        if status == "OK":
            ok_count += 1

            context.integrity.mark_verified(
                path.name
            )

        elif status == "BASELINED":
            baselined_count += 1

            context.integrity.mark_verified(
                path.name
            )

        elif status == "FAILED":
            failed_count += 1

        elif status == "UNKNOWN":
            unknown_count += 1

        elif status == "CONFLICT":
            conflict_count += 1

    typer.echo("")
    typer.echo("Summary")
    typer.echo(
        f"  OK: {ok_count}"
    )
    typer.echo(
        f"  BASELINED: {baselined_count}"
    )
    typer.echo(
        f"  FAILED: {failed_count}"
    )
    typer.echo(
        f"  UNKNOWN: {unknown_count}"
    )
    typer.echo(
        f"  CONFLICT: {conflict_count}"
    )

    if (
        failed_count > 0
        or conflict_count > 0
    ):
        raise typer.Exit(code=1)

    if unknown_count > 0:
        raise typer.Exit(code=2)

@results_app.command("baseline-legacy")
def results_baseline_legacy():
    """Create retrospective integrity baselines for legacy results."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    results = context.results.list()

    if not results:
        typer.echo("No results found.")
        return

    assets = context.assets.find()

    baselined = 0
    skipped = 0

    typer.echo("Legacy result baselines")
    typer.echo("")

    for path in results:
        integrity_record = context.integrity.get(
            path.name
        )

        status, _, current = verify_result_file(
            path,
            assets,
            integrity_record=integrity_record,
        )

        if status != "UNKNOWN":
            skipped += 1
            continue

        # Always create a retrospective baseline
        # in the campaign integrity manifest.
        context.integrity.upsert(
            filename=path.name,
            sha256=current,
            baseline_type=(
                IntegrityBaselineType.RETROSPECTIVE
            ),
            created_at=datetime.now(
                timezone.utc
            ),
        )

        # Also enrich asset provenance when
        # provenance exists for this result.
        for asset in assets:
            changed = False

            for provenance in asset.provenance:
                if (
                    provenance.result_file
                    == path.name
                    and provenance.result_sha256
                    is None
                ):
                    provenance.result_sha256 = (
                        current
                    )

                    provenance.integrity_baseline = (
                        IntegrityBaselineType.RETROSPECTIVE
                    )

                    changed = True

            if changed:
                context.assets.save(asset)

        typer.echo(
            f"{path.name:<45} BASELINED"
        )

        baselined += 1

    typer.echo("")
    typer.echo("Summary")
    typer.echo(
        f"  Baselined: {baselined}"
    )
    typer.echo(
        f"  Skipped: {skipped}"
    )

@results_app.command("integrity-summary")
def results_integrity_summary():
    """Show a summary of the campaign integrity manifest."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    manifest = context.integrity.load()

    total = len(manifest.results)

    original = sum(
        1
        for record in manifest.results
        if record.baseline_type
        == IntegrityBaselineType.ORIGINAL
    )

    retrospective = sum(
        1
        for record in manifest.results
        if record.baseline_type
        == IntegrityBaselineType.RETROSPECTIVE
    )

    verified = sum(
        1
        for record in manifest.results
        if record.verified_at is not None
    )

    unverified = total - verified

    typer.echo("Integrity manifest")
    typer.echo("")
    typer.echo(f"Records: {total}")
    typer.echo(f"Original: {original}")
    typer.echo(
        f"Retrospective: {retrospective}"
    )
    typer.echo(f"Verified: {verified}")
    typer.echo(f"Unverified: {unverified}")

@results_app.command("integrity-show")
def results_integrity_show(filename: str):
    """Show an integrity manifest record."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    record = context.integrity.get(
        filename
    )

    if record is None:
        typer.echo(
            f"Error: integrity record not found: "
            f"{filename}"
        )
        raise typer.Exit(code=1)

    typer.echo("Integrity record")
    typer.echo(f"Result: {record.filename}")
    typer.echo(
        f"SHA-256: {record.sha256}"
    )
    typer.echo(
        f"Baseline: "
        f"{record.baseline_type.value}"
    )
    typer.echo(
        f"Created at: {record.created_at}"
    )

    if record.verified_at is not None:
        typer.echo(
            f"Verified at: "
            f"{record.verified_at}"
        )
    else:
        typer.echo(
            "Verified at: never"
        )

@assets_app.command("show")
def assets_show(filename: str):
    """Show a discovered asset."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    asset_dir = context.assets.directory.resolve()
    path = (asset_dir / filename).resolve()

    # Prevent path traversal outside the assets directory.
    try:
        path.relative_to(asset_dir)
    except ValueError:
        typer.echo("Error: invalid asset path.")
        raise typer.Exit(code=1)

    if not path.exists() or not path.is_file():
        typer.echo(
            f"Error: asset not found: {filename}"
        )
        raise typer.Exit(code=1)

    try:
        asset = context.assets.load(path)

    except ValueError:
        typer.echo(
            f"Error: invalid asset file: {filename}"
        )
        raise typer.Exit(code=1)

    typer.echo("Asset")
    typer.echo(f"Type: {asset.type.value}")
    typer.echo(f"Value: {asset.value}")
    typer.echo(f"Source: {asset.source}")

    if (
        asset.first_seen is not None
        or asset.last_seen is not None
    ):
        typer.echo("Lifecycle")
        typer.echo(
            f"  First seen: {asset.first_seen}"
        )
        typer.echo(
            f"  Last seen: {asset.last_seen}"
        )
        typer.echo(
            f"  Last confirmed: "
            f"{asset.last_confirmed}"
        )
        typer.echo(
            f"  Seen count: {asset.seen_count}"
        )
        typer.echo(
            f"  Active: "
            f"{'yes' if asset.active else 'no'}"
        )

    if asset.metadata:
        typer.echo("")
        typer.echo("Metadata")

        for key, value in asset.metadata.items():
            typer.echo(
                f"  {key}: {value}"
            )

    if asset.provenance:
        typer.echo("")
        typer.echo("Provenance")

        for index, item in enumerate(
            asset.provenance,
            start=1,
        ):
            if len(asset.provenance) > 1:
                typer.echo(
                    f"  Observation #{index}"
                )

            typer.echo(
                f"  Plugin: {item.plugin}"
            )

            if item.plugin_version:
                typer.echo(
                    f"  Plugin version: "
                    f"{item.plugin_version}"
                )

            typer.echo(
                f"  Observation type: "
                f"{item.observation_type}"
            )

            typer.echo(
                f"  Target: {item.target}"
            )

            typer.echo(
                f"  Observed at: "
                f"{item.observed_at}"
            )

            if item.observation_id:
                typer.echo(
                    f"  Observation ID: "
                    f"{item.observation_id[:12]}"
                )
            else:
                typer.echo(
                    "  Observation ID: legacy"
                )

            if item.result_id:
                typer.echo(
                    f"  Result ID: "
                    f"{item.result_id}"
                )

            if item.result_sha256:
                typer.echo(
                    f"  Result SHA-256: "
                    f"{item.result_sha256}"
                )

            if item.result_file:
                typer.echo(
                    f"  Result: "
                    f"{item.result_file}"
                )

            if (
                index < len(asset.provenance)
            ):
                typer.echo("")

@assets_app.command("list")
def assets_list(
    asset_type: str | None = typer.Option(
        None,
        "--type",
        help="Filter by asset type.",
    ),
    source: str | None = typer.Option(
        None,
        "--source",
        help="Filter by discovery source.",
    ),
):
    """List discovered assets."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    selected_type = None

    if asset_type is not None:
        try:
            selected_type = AssetType(
                asset_type.lower()
            )
        except ValueError:
            print_error(
                f"invalid asset type: {asset_type}"
            )
            raise typer.Exit(code=1)

    assets = context.assets.find(
        asset_type=selected_type,
        source=source,
    )

    print_assets_table(
        assets
    )

@assets_app.command("graph")
def assets_graph(
    value: str,
    asset_type: str | None = typer.Option(
        None,
        "--type",
        help="Root asset type.",
    ),
    details: bool = typer.Option(
        False,
        "--details",
        help="Show lifecycle details for each relation.",
    ),
):
    """Show outgoing asset relations recursively."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    assets = context.assets.find()

    matches = [
        asset
        for asset in assets
        if asset.value == value
    ]

    if asset_type is not None:
        try:
            parsed_type = AssetType(
                asset_type.lower()
            )
        except ValueError:
            typer.echo(
                f"Error: unsupported asset type: "
                f"{asset_type}"
            )
            raise typer.Exit(code=1)

        matches = [
            asset
            for asset in matches
            if asset.type == parsed_type
        ]

    if not matches:
        typer.echo(
            f"Error: asset not found: {value}"
        )
        raise typer.Exit(code=1)

    typer.echo("Asset graph")
    typer.echo("")

    for root in matches:
        typer.echo(
            f"{root.type.value.upper()} "
            f"{root.value}"
        )

        walked = context.relations.walk_from(
            root.type,
            root.value,
        )

        if not walked:
            typer.echo(
                "  No outgoing relations."
            )
            typer.echo("")
            continue

        for depth, relation in walked:
            indent = "  " * depth

            typer.echo(
                f"{indent}└── "
                f"{relation.relation.value.upper()} "
                f"{relation.target_type.value.upper()} "
                f"{relation.target_value}"
            )

            if details:
                detail_indent = (
                    "  " * (depth + 1)
                )

                if relation.seen_count > 0:
                    typer.echo(
                        f"{detail_indent}"
                        f"[active: "
                        f"{'yes' if relation.active else 'no'}, "
                        f"seen: {relation.seen_count}, "
                        f"first: {relation.first_seen}, "
                        f"last: {relation.last_seen}, "
                        f"confirmed: "
                        f"{relation.last_confirmed}]"
                    )
                else:
                    typer.echo(
                        f"{detail_indent}"
                        "[lifecycle: legacy/unavailable]"
                    )

        typer.echo("")

@assets_app.command("related")
def assets_related(
    asset_type: str,
    value: str,
):
    """Show incoming and outgoing relations for an asset."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    try:
        parsed_type = AssetType(
            asset_type.lower()
        )
    except ValueError:
        typer.echo(
            f"Error: unsupported asset type: "
            f"{asset_type}"
        )
        raise typer.Exit(code=1)

    outgoing = context.relations.find(
        source_type=parsed_type,
        source_value=value,
    )

    incoming = context.relations.find(
        target_type=parsed_type,
        target_value=value,
    )

    typer.echo("Related assets")
    typer.echo(
        f"Asset: "
        f"{parsed_type.value.upper()} {value}"
    )

    typer.echo("")
    typer.echo("Outgoing")

    if not outgoing:
        typer.echo(
            "  No outgoing relations."
        )
    else:
        for relation in outgoing:
            typer.echo(
                f"  --{relation.relation.value}--> "
                f"{relation.target_type.value.upper()} "
                f"{relation.target_value}"
            )

            typer.echo(
                f"    Seen: "
                f"{relation.seen_count}"
            )

    typer.echo("")
    typer.echo("Incoming")

    if not incoming:
        typer.echo(
            "  No incoming relations."
        )
    else:
        for relation in incoming:
            typer.echo(
                f"  {relation.source_type.value.upper()} "
                f"{relation.source_value} "
                f"--{relation.relation.value}-->"
            )

            typer.echo(
                f"    Seen: "
                f"{relation.seen_count}"
            )

@relations_app.command("list")
def relations_list():
    """List discovered asset relations."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    paths = context.relations.list()

    relations = [
        context.relations.load(
            path
        )
        for path in paths
    ]

    print_relations_table(
        relations
    )

@relations_app.command("show")
def relations_show(filename: str):
    """Show a stored asset relation."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    relation_dir = (
        context.relations.directory.resolve()
    )

    path = (
        relation_dir / filename
    ).resolve()

    try:
        path.relative_to(
            relation_dir
        )
    except ValueError:
        typer.echo(
            "Error: invalid relation path."
        )
        raise typer.Exit(code=1)

    if not path.exists() or not path.is_file():
        typer.echo(
            f"Error: relation not found: "
            f"{filename}"
        )
        raise typer.Exit(code=1)

    relation = context.relations.load(
        path
    )

    typer.echo("Relation")
    typer.echo(
        f"Source type: "
        f"{relation.source_type.value}"
    )
    typer.echo(
        f"Source: "
        f"{relation.source_value}"
    )
    typer.echo(
        f"Relation: "
        f"{relation.relation.value}"
    )
    typer.echo(
        f"Target type: "
        f"{relation.target_type.value}"
    )
    typer.echo(
        f"Target: "
        f"{relation.target_value}"
    )

    if (
        relation.first_seen is not None
        or relation.last_seen is not None
        or relation.last_confirmed is not None
        or relation.seen_count > 0
    ):
        typer.echo("")
        typer.echo("Lifecycle")

        typer.echo(
            f"  First seen: "
            f"{relation.first_seen}"
        )

        typer.echo(
            f"  Last seen: "
            f"{relation.last_seen}"
        )

        typer.echo(
            f"  Last confirmed: "
            f"{relation.last_confirmed}"
        )

        typer.echo(
            f"  Seen count: "
            f"{relation.seen_count}"
        )

        typer.echo(
            f"  Active: "
            f"{'yes' if relation.active else 'no'}"
        )

    if relation.provenance:
        typer.echo("")
        typer.echo("Provenance")

        multiple = (
            len(relation.provenance) > 1
        )

        for index, item in enumerate(
            relation.provenance,
            start=1,
        ):
            if multiple:
                typer.echo(
                    f"  Observation #{index}"
                )

            typer.echo(
                f"  Plugin: "
                f"{item.plugin}"
            )

            if item.plugin_version:
                typer.echo(
                    f"  Plugin version: "
                    f"{item.plugin_version}"
                )

            typer.echo(
                f"  Observation type: "
                f"{item.observation_type}"
            )

            typer.echo(
                f"  Target: "
                f"{item.target}"
            )

            typer.echo(
                f"  Observed at: "
                f"{item.observed_at}"
            )

            if item.observation_id:
                typer.echo(
                    f"  Observation ID: "
                    f"{item.observation_id}"
                )

            if item.result_id:
                typer.echo(
                    f"  Result ID: "
                    f"{item.result_id}"
                )

            if item.result_sha256:
                typer.echo(
                    f"  Result SHA-256: "
                    f"{item.result_sha256}"
                )

            if item.result_file:
                typer.echo(
                    f"  Result: "
                    f"{item.result_file}"
                )

            if index < len(
                relation.provenance
            ):
                typer.echo("")

@relations_app.command("from")
def relations_from(
    asset_type: str,
    value: str,
):
    """List relations originating from an asset."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    try:
        parsed_type = AssetType(
            asset_type.lower()
        )
    except ValueError:
        typer.echo(
            f"Error: unsupported asset type: "
            f"{asset_type}"
        )
        raise typer.Exit(code=1)

    relations = context.relations.find(
        source_type=parsed_type,
        source_value=value,
    )

    if not relations:
        typer.echo("No relations found.")
        return

    typer.echo("Relations")
    typer.echo("")

    for relation in relations:
        typer.echo(
            f"{relation.source_type.value.upper():11} "
            f"{relation.source_value}"
        )

        typer.echo(
            f"  --{relation.relation.value}--> "
            f"{relation.target_type.value.upper()} "
            f"{relation.target_value}"
        )

        typer.echo("")

@relations_app.command("to")
def relations_to(
    asset_type: str,
    value: str,
):
    """List relations pointing to an asset."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(campaign)

    try:
        parsed_type = AssetType(
            asset_type.lower()
        )
    except ValueError:
        typer.echo(
            f"Error: unsupported asset type: "
            f"{asset_type}"
        )
        raise typer.Exit(code=1)

    relations = context.relations.find(
        target_type=parsed_type,
        target_value=value,
    )

    if not relations:
        typer.echo("No relations found.")
        return

    typer.echo("Relations")
    typer.echo("")

    for relation in relations:
        typer.echo(
            f"{relation.source_type.value.upper():11} "
            f"{relation.source_value}"
        )

        typer.echo(
            f"  --{relation.relation.value}--> "
            f"{relation.target_type.value.upper()} "
            f"{relation.target_value}"
        )

        typer.echo("")

@changes_app.command("list")
def changes_list(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output changes as JSON.",
    ),
    change_type: str | None = typer.Option(
        None,
        "--type",
        help="Filter by change type.",
    ),
    asset_type: str | None = typer.Option(
        None,
        "--asset-type",
        help="Filter by asset type.",
    ),
    asset_value: str | None = typer.Option(
        None,
        "--asset",
        help="Filter by asset value.",
    ),
    relation_type: str | None = typer.Option(
        None,
        "--relation-type",
        help="Filter by relation type.",
    ),
    source_type: str | None = typer.Option(
        None,
        "--source-type",
        help="Filter by relation source asset type.",
    ),
    source_value: str | None = typer.Option(
        None,
        "--source",
        help="Filter by relation source value.",
    ),
    target_type: str | None = typer.Option(
        None,
        "--target-type",
        help="Filter by relation target asset type.",
    ),
    target_value: str | None = typer.Option(
        None,
        "--target-value",
        help="Filter by relation target value.",
    ),
    plugin: str | None = typer.Option(
        None,
        "--plugin",
        help="Filter by plugin.",
    ),
):
    """List detected changes in the current campaign."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    parsed_change_type = None

    if change_type is not None:
        try:
            parsed_change_type = ChangeType(
                change_type.lower()
            )
        except ValueError:
            typer.echo(
                f"Error: invalid change type: "
                f"{change_type}"
            )
            raise typer.Exit(code=1)

    parsed_asset_type = None

    if asset_type is not None:
        try:
            parsed_asset_type = AssetType(
                asset_type.lower()
            )
        except ValueError:
            typer.echo(
                f"Error: invalid asset type: "
                f"{asset_type}"
            )
            raise typer.Exit(code=1)

    parsed_relation_type = None

    if relation_type is not None:
        try:
            parsed_relation_type = (
                AssetRelationType(
                    relation_type.lower()
                )
            )
        except ValueError:
            typer.echo(
                f"Error: invalid relation type: "
                f"{relation_type}"
            )
            raise typer.Exit(code=1)

    parsed_source_type = None

    if source_type is not None:
        try:
            parsed_source_type = AssetType(
                source_type.lower()
            )
        except ValueError:
            typer.echo(
                f"Error: invalid source type: "
                f"{source_type}"
            )
            raise typer.Exit(code=1)

    parsed_target_type = None

    if target_type is not None:
        try:
            parsed_target_type = AssetType(
                target_type.lower()
            )
        except ValueError:
            typer.echo(
                f"Error: invalid target type: "
                f"{target_type}"
            )
            raise typer.Exit(code=1)

    changes = context.changes.find(
        asset_type=parsed_asset_type,
        asset_value=asset_value,
        change_type=parsed_change_type,
        relation_type=parsed_relation_type,
        source_type=parsed_source_type,
        source_value=source_value,
        target_type=parsed_target_type,
        target_value=target_value,
    )

    if plugin is not None:
        changes = [
            change
            for change in changes
            if (
                change.plugin.lower()
                == plugin.lower()
            )
        ]

    changes.sort(
        key=lambda change: change.detected_at,
        reverse=True,
    )

    # -----------------------------
    # JSON output
    # -----------------------------

    if json_output:
        payload = []

        for change in changes:
            if change.asset_type is not None:
                payload.append(
                    {
                        "kind": "asset",
                        "change_type": (
                            change.change_type.value
                        ),
                        "asset_type": (
                            change.asset_type.value
                        ),
                        "asset_value": (
                            change.asset_value
                        ),
                        "plugin": change.plugin,
                        "target": change.target,
                        "detected_at": (
                            change.detected_at.isoformat()
                        ),
                        "previous_result": (
                            change.previous_result
                        ),
                        "current_result": (
                            change.current_result
                        ),
                    }
                )

            elif change.relation_type is not None:
                payload.append(
                    {
                        "kind": "relation",
                        "change_type": (
                            change.change_type.value
                        ),
                        "relation_type": (
                            change.relation_type.value
                        ),
                        "source_type": (
                            change.source_type.value
                            if change.source_type
                            else None
                        ),
                        "source_value": (
                            change.source_value
                        ),
                        "target_type": (
                            change.target_type.value
                            if change.target_type
                            else None
                        ),
                        "target_value": (
                            change.target_value
                        ),
                        "plugin": change.plugin,
                        "target": change.target,
                        "detected_at": (
                            change.detected_at.isoformat()
                        ),
                        "previous_result": (
                            change.previous_result
                        ),
                        "current_result": (
                            change.current_result
                        ),
                    }
                )

        typer.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )

        return

    # -----------------------------
    # Human-readable output
    # -----------------------------

    print_changes_table(
        changes
    )

@changes_app.command("show")
def changes_show(
    filename: str,
):
    """Show a stored change."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    change_dir = (
        context.changes.directory.resolve()
    )

    path = (
        change_dir / filename
    ).resolve()

    try:
        path.relative_to(
            change_dir
        )

    except ValueError:
        typer.echo(
            "Error: invalid change path."
        )
        raise typer.Exit(code=1)

    if (
        not path.exists()
        or not path.is_file()
    ):
        typer.echo(
            f"Error: change not found: "
            f"{filename}"
        )
        raise typer.Exit(code=1)

    change = context.changes.load(
        path
    )

    typer.echo(
        "Change"
    )

    typer.echo(
        f"Type: "
        f"{change.change_type.value}"
    )

    if change.asset_type is not None:
        typer.echo(
            "Kind: asset"
        )

        typer.echo(
            f"Asset type: "
            f"{change.asset_type.value}"
        )

        typer.echo(
            f"Asset: "
            f"{change.asset_value}"
        )

    elif change.relation_type is not None:
        typer.echo(
            "Kind: relation"
        )

        typer.echo(
            f"Relation: "
            f"{change.relation_type.value}"
        )

        typer.echo(
            f"Source type: "
            f"{change.source_type.value}"
        )

        typer.echo(
            f"Source: "
            f"{change.source_value}"
        )

        typer.echo(
            f"Target type: "
            f"{change.target_type.value}"
        )

        typer.echo(
            f"Target asset: "
            f"{change.target_value}"
        )

    typer.echo(
        f"Plugin: "
        f"{change.plugin}"
    )

    typer.echo(
        f"Target: "
        f"{change.target}"
    )

    typer.echo(
        f"Detected at: "
        f"{change.detected_at}"
    )

    if change.previous_result:
        typer.echo(
            f"Previous result: "
            f"{change.previous_result}"
        )

    if change.current_result:
        typer.echo(
            f"Current result: "
            f"{change.current_result}"
        )

@assets_app.command("history")
def assets_history(
    asset_type: str,
    value: str,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output history as JSON.",
    ),
):
    """Show the lifecycle and change history of an asset."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    try:
        parsed_type = AssetType(
            asset_type
        )
    except ValueError:
        typer.echo(
            f"Error: invalid asset type: "
            f"{asset_type}"
        )
        raise typer.Exit(code=1)

    assets = context.assets.find(
        asset_type=parsed_type,
    )

    asset = next(
        (
            candidate
            for candidate in assets
            if candidate.value == value
        ),
        None,
    )

    if asset is None:
        typer.echo(
            "Error: asset not found."
        )
        raise typer.Exit(code=1)

    changes = context.changes.find(
        asset_type=parsed_type,
        asset_value=value,
    )

    events = []

    # Primeiro evento conhecido.
    if asset.first_seen is not None:
        events.append(
            (
                asset.first_seen,
                "first_seen",
                None,
            )
        )

    # Observações / confirmações do asset.
    for provenance in asset.provenance:
        events.append(
            (
                provenance.observed_at,
                "observed",
                provenance.result_file,
            )
        )

    # Mudanças de estado.
    for change in changes:
        events.append(
            (
                change.detected_at,
                change.change_type.value,
                change.current_result,
            )
        )

    events.sort(
        key=lambda item: item[0]
    )

    # -----------------------------
    # JSON output
    # -----------------------------

    if json_output:
        payload = {
            "asset": {
                "type": asset.type.value,
                "value": asset.value,
                "source": asset.source,
                "first_seen": (
                    asset.first_seen.isoformat()
                    if asset.first_seen
                    else None
                ),
                "last_seen": (
                    asset.last_seen.isoformat()
                    if asset.last_seen
                    else None
                ),
                "last_confirmed": (
                    asset.last_confirmed.isoformat()
                    if asset.last_confirmed
                    else None
                ),
                "seen_count": (
                    asset.seen_count
                ),
                "active": asset.active,
            },
            "timeline": [
                {
                    "timestamp": (
                        timestamp.isoformat()
                    ),
                    "event": event_type,
                    "result": result_file,
                }
                for (
                    timestamp,
                    event_type,
                    result_file,
                ) in events
            ],
        }

        typer.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )

        return

    # -----------------------------
    # Human-readable output
    # -----------------------------

    typer.echo("ARGUS")
    typer.echo("")
    typer.echo("Asset history")
    typer.echo("")

    typer.echo(
        f"Type: {asset.type.value}"
    )

    typer.echo(
        f"Value: {asset.value}"
    )

    typer.echo(
        f"Source: {asset.source}"
    )

    typer.echo(
        f"Active: "
        f"{'yes' if asset.active else 'no'}"
    )

    typer.echo(
        f"Seen count: {asset.seen_count}"
    )

    if asset.first_seen:
        typer.echo(
            f"First seen: "
            f"{asset.first_seen.isoformat()}"
        )

    if asset.last_seen:
        typer.echo(
            f"Last seen: "
            f"{asset.last_seen.isoformat()}"
        )

    if asset.last_confirmed:
        typer.echo(
            f"Last confirmed: "
            f"{asset.last_confirmed.isoformat()}"
        )

    typer.echo("")
    typer.echo("Timeline")

    if not events:
        typer.echo(
            "  No history found."
        )
        return

    for (
        timestamp,
        event_type,
        result_file,
    ) in events:
        line = (
            f"  {timestamp.isoformat()} "
            f"{event_type.upper()}"
        )

        if result_file:
            line += (
                f" [{result_file}]"
            )

        typer.echo(line)

@relations_app.command("history")
def relations_history(
    source_type: str,
    source_value: str,
    relation_type: str,
    target_type: str,
    target_value: str,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output relation history as JSON.",
    ),
):
    """Show the lifecycle and change history of a relation."""

    campaign = find_campaign()

    if campaign is None:
        typer.echo(
            "Error: no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    try:
        parsed_source_type = AssetType(
            source_type.lower()
        )
    except ValueError:
        typer.echo(
            f"Error: invalid source type: "
            f"{source_type}"
        )
        raise typer.Exit(code=1)

    try:
        parsed_target_type = AssetType(
            target_type.lower()
        )
    except ValueError:
        typer.echo(
            f"Error: invalid target type: "
            f"{target_type}"
        )
        raise typer.Exit(code=1)

    try:
        parsed_relation_type = (
            AssetRelationType(
                relation_type.lower()
            )
        )
    except ValueError:
        typer.echo(
            f"Error: invalid relation type: "
            f"{relation_type}"
        )
        raise typer.Exit(code=1)

    relation = next(
        (
            item
            for item in context.relations.find()
            if (
                item.source_type
                == parsed_source_type
                and item.source_value
                == source_value
                and item.relation
                == parsed_relation_type
                and item.target_type
                == parsed_target_type
                and item.target_value
                == target_value
            )
        ),
        None,
    )

    if relation is None:
        typer.echo(
            "Error: relation not found."
        )
        raise typer.Exit(code=1)

    changes = context.changes.find(
        relation_type=parsed_relation_type,
        source_type=parsed_source_type,
        source_value=source_value,
        target_type=parsed_target_type,
        target_value=target_value,
    )

    events = []

    if relation.first_seen is not None:
        events.append(
            (
                relation.first_seen,
                "first_seen",
                None,
            )
        )

    for provenance in relation.provenance:
        events.append(
            (
                provenance.observed_at,
                "observed",
                provenance.result_file,
            )
        )

    for change in changes:
        events.append(
            (
                change.detected_at,
                change.change_type.value,
                change.current_result,
            )
        )

    events.sort(
        key=lambda item: item[0]
    )

    if json_output:
        payload = {
            "relation": {
                "source_type": (
                    relation.source_type.value
                ),
                "source_value": (
                    relation.source_value
                ),
                "relation_type": (
                    relation.relation.value
                ),
                "target_type": (
                    relation.target_type.value
                ),
                "target_value": (
                    relation.target_value
                ),
                "first_seen": (
                    relation.first_seen.isoformat()
                    if relation.first_seen
                    else None
                ),
                "last_seen": (
                    relation.last_seen.isoformat()
                    if relation.last_seen
                    else None
                ),
                "last_confirmed": (
                    relation.last_confirmed.isoformat()
                    if relation.last_confirmed
                    else None
                ),
                "seen_count": (
                    relation.seen_count
                ),
                "active": (
                    relation.active
                ),
            },
            "timeline": [
                {
                    "timestamp": (
                        timestamp.isoformat()
                    ),
                    "event": event_type,
                    "result": result_file,
                }
                for (
                    timestamp,
                    event_type,
                    result_file,
                ) in events
            ],
        }

        typer.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )

        return

    typer.echo("ARGUS")
    typer.echo("")
    typer.echo("Relation history")
    typer.echo("")

    typer.echo(
        f"{relation.source_type.value.upper()} "
        f"{relation.source_value}"
    )

    typer.echo(
        f"  --{relation.relation.value}--> "
        f"{relation.target_type.value.upper()} "
        f"{relation.target_value}"
    )

    typer.echo("")
    typer.echo("Lifecycle")

    typer.echo(
        f"  First seen: "
        f"{relation.first_seen}"
    )

    typer.echo(
        f"  Last seen: "
        f"{relation.last_seen}"
    )

    typer.echo(
        f"  Last confirmed: "
        f"{relation.last_confirmed}"
    )

    typer.echo(
        f"  Seen count: "
        f"{relation.seen_count}"
    )

    typer.echo(
        f"  Active: "
        f"{'yes' if relation.active else 'no'}"
    )

    typer.echo("")
    typer.echo("Timeline")

    if not events:
        typer.echo(
            "  No history found."
        )
        return

    for (
        timestamp,
        event_type,
        result_file,
    ) in events:
        line = (
            f"  {timestamp.isoformat()} "
            f"{event_type.upper()}"
        )

        if result_file:
            line += (
                f" [{result_file}]"
            )

        typer.echo(
            line
        )

def get_current_findings(
    context: AssessmentContext,
):
    """Return persisted finding lifecycle records."""
    return context.findings.find()


@findings_app.command("list")
def findings_list(
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity.",
    ),
    state: str | None = typer.Option(
        None,
        "--state",
        help="Filter by finding lifecycle state.",
    ),
    rule: str | None = typer.Option(
        None,
        "--rule",
        help="Filter by finding rule.",
    ),
    asset_type: str | None = typer.Option(
        None,
        "--asset-type",
        help="Filter by asset type.",
    ),
    asset_value: str | None = typer.Option(
        None,
        "--asset-value",
        help="Filter by asset value.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output findings as JSON.",
    ),
):
    """List persisted exposure findings."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    findings = get_current_findings(
        context
    )

    # -------------------------------------------------
    # FILTERS
    # -------------------------------------------------

    if severity is not None:
        normalized = severity.lower()

        allowed = {
            item.value
            for item
            in ExposureSeverity
        }

        if normalized not in allowed:
            print_error(
                f"invalid severity: {severity}"
            )
            raise typer.Exit(code=1)

        findings = [
            finding
            for finding in findings
            if finding.severity == normalized
        ]

    if state is not None:
        normalized_state = state.lower()

        allowed_states = {
            item.value
            for item
            in FindingState
        }

        if normalized_state not in allowed_states:
            print_error(
                f"invalid finding state: {state}"
            )
            raise typer.Exit(code=1)

        findings = [
            finding
            for finding in findings
            if finding.state.value == normalized_state
        ]

    if rule is not None:
        normalized_rule = rule.upper()

        findings = [
            finding
            for finding in findings
            if finding.rule_id.upper() == normalized_rule
        ]

    if asset_type is not None:
        try:
            parsed_asset_type = AssetType(
                asset_type.lower()
            )
        except ValueError:
            print_error(
                f"invalid asset type: {asset_type}"
            )
            raise typer.Exit(code=1)

        findings = [
            finding
            for finding in findings
            if finding.asset_type == parsed_asset_type
        ]

    if asset_value is not None:
        findings = [
            finding
            for finding in findings
            if finding.asset_value == asset_value
        ]

    # -------------------------------------------------
    # SORT
    # -------------------------------------------------

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    findings.sort(
        key=lambda finding: (
            severity_order.get(
                finding.severity,
                99,
            ),
            finding.state.value,
            finding.rule_id,
            finding.asset_value,
            finding.affected_service or "",
        )
    )

    # -------------------------------------------------
    # JSON
    # -------------------------------------------------

    if json_output:
        payload = [
            {
                "id": finding.finding_id,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "state": finding.state.value,
                "active": finding.active,
                "title": finding.title,
                "description": finding.description,
                "asset_type": finding.asset_type.value,
                "asset_value": finding.asset_value,
                "affected_service": finding.affected_service,
                "plugin": finding.plugin,
                "coverage_plugins": list(
                    finding.coverage_plugins
                ),
                "first_seen": (
                    finding.first_seen.isoformat()
                    if finding.first_seen
                    else None
                ),
                "last_seen": (
                    finding.last_seen.isoformat()
                    if finding.last_seen
                    else None
                ),
                "last_confirmed": (
                    finding.last_confirmed.isoformat()
                    if finding.last_confirmed
                    else None
                ),
                "seen_count": finding.seen_count,
                "missing_count": finding.missing_count,
            }
            for finding in findings
        ]

        typer.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )
        return

    print_findings_table(
        findings
    )


@findings_app.command("show")
def findings_show(
    finding_id: str = typer.Argument(
        ...,
        help="Finding ID or unique ID prefix.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output finding as JSON.",
    ),
):
    """Show detailed information about a persisted finding."""

    campaign = find_campaign()

    if campaign is None:
        print_error(
            "no AEGIS / ARGUS campaign found."
        )
        raise typer.Exit(code=1)

    context = AssessmentContext(
        campaign
    )

    finding = context.findings.find_by_id(
        finding_id
    )

    if finding is None:
        print_error(
            f"finding not found: {finding_id}"
        )
        raise typer.Exit(code=1)

    if json_output:
        payload = {
            "id": finding.finding_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "state": finding.state.value,
            "active": finding.active,
            "title": finding.title,
            "description": finding.description,
            "asset_type": finding.asset_type.value,
            "asset_value": finding.asset_value,
            "affected_service": finding.affected_service,
            "plugin": finding.plugin,
            "coverage_plugins": list(
                finding.coverage_plugins
            ),
            "first_seen": (
                finding.first_seen.isoformat()
                if finding.first_seen
                else None
            ),
            "last_seen": (
                finding.last_seen.isoformat()
                if finding.last_seen
                else None
            ),
            "last_confirmed": (
                finding.last_confirmed.isoformat()
                if finding.last_confirmed
                else None
            ),
            "seen_count": finding.seen_count,
            "missing_count": finding.missing_count,
        }

        typer.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )
        return

    print_finding_detail(
        finding
    )

if __name__ == "__main__":
    app()
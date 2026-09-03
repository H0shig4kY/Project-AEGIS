from pathlib import Path
from typing import Any, Iterable

import shutil

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group
from rich.rule import Rule

from aegis.models import ChangeType


console = Console()

COMPACT_WIDTH = 100
NARROW_WIDTH = 76

_layout_override: bool | None = None


def set_compact_mode(
    enabled: bool | None,
):
    """
    Override automatic terminal layout detection.

    None:
        Use the current terminal width automatically.

    True:
        Force compact layout.
    """

    global _layout_override
    _layout_override = enabled


def terminal_width() -> int:
    """Return the current Rich console width."""

    return console.size.width

def terminal_is_compact(
    threshold: int = 110,
) -> bool:
    if _layout_override is not None:
        return _layout_override

    width = shutil.get_terminal_size(
        fallback=(120, 30)
    ).columns

    return width < threshold


def terminal_is_narrow() -> bool:
    """Return True for particularly narrow terminals."""

    return (
        terminal_width()
        < NARROW_WIDTH
    )


# ---------------------------------------------------------
# BRANDING
# ---------------------------------------------------------



def print_banner():
    if terminal_is_compact():
        brand = Text()

        brand.append(
            "AEGIS",
            style="bold cyan",
        )

        brand.append(
            " / ",
            style="dim",
        )

        brand.append(
            "ARGUS",
            style="bold magenta",
        )

        brand.append(
            "\nAuthorized Reconnaissance, Asset Discovery "
            "and Lifecycle Analysis Engine.",
            style="bold white",
        )

        if not terminal_is_narrow():
            brand.append(
                "\nEvidence-driven reconnaissance with scope, "
                "provenance and temporal change tracking.",
                style="dim",
            )

        console.print(
            Panel(
                brand,
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        console.print()
        return

    banner = Text()

    banner.append(
        "    _    _____ ____ ___ ____\n",
        style="bold cyan",
    )
    banner.append(
        "   / \\  | ____/ ___|_ _/ ___|\n",
        style="bold cyan",
    )
    banner.append(
        "  / _ \\ |  _|| |  _ | |\\___ \\\n",
        style="bold bright_cyan",
    )
    banner.append(
        " / ___ \\| |__| |_| || | ___) |\n",
        style="bold bright_cyan",
    )
    banner.append(
        "/_/   \\_\\_____\\____|___|____/\n",
        style="bold cyan",
    )

    banner.append(
        "                         / ARGUS",
        style="bold magenta",
    )

    console.print(banner)

    console.print(
        "[bold white]"
        "Authorized Reconnaissance, Asset Discovery "
        "and Lifecycle Analysis Engine."
        "[/bold white]"
    )

    console.print(
        "[dim]"
        "Evidence-driven reconnaissance with scope, "
        "provenance and temporal change tracking."
        "[/dim]"
    )

    console.print()

def _finding_severity_value(
    finding,
) -> str:
    severity = finding.severity

    if hasattr(
        severity,
        "value",
    ):
        return severity.value

    return str(
        severity
    )


def _finding_state_value(
    finding,
) -> str | None:
    state = getattr(
        finding,
        "state",
        None,
    )

    if state is None:
        return None

    if hasattr(
        state,
        "value",
    ):
        return state.value

    return str(
        state
    )


def print_wide_findings(
    findings,
):
    findings_table = Table(
        box=box.ROUNDED,
        header_style="bold yellow",
        expand=True,
    )

    findings_table.add_column(
        "ID",
        width=12,
        no_wrap=True,
    )

    findings_table.add_column(
        "Severity",
        width=12,
        no_wrap=True,
    )

    findings_table.add_column(
        "Rule",
        width=26,
    )

    findings_table.add_column(
        "Asset",
        ratio=2,
    )

    findings_table.add_column(
        "Affected Service",
        ratio=2,
    )

    findings_table.add_column(
        "Description",
        ratio=3,
    )

    severity_styles = {
        "info": "bold cyan",
        "low": "bold green",
        "medium": "bold yellow",
        "high": "bold red",
        "critical": "bold white on red",
    }

    for finding in findings:
        severity = (
            _finding_severity_value(
                finding
            )
        )

        severity_text = Text(
            severity.upper(),
            style=severity_styles.get(
                severity,
                "white",
            ),
        )

        asset_text = (
            f"{finding.asset_type.value.upper()} "
            f"{finding.asset_value}"
        )

        affected_service = (
            finding.affected_service
            or "-"
        )

        findings_table.add_row(
            finding.finding_id[:12],
            severity_text,
            finding.rule_id,
            asset_text,
            affected_service,
            finding.description,
        )

    console.print(
        Panel(
            findings_table,
            title=(
                "[bold yellow] "
                "FINDINGS "
                "[/bold yellow]"
            ),
            title_align="left",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )


def print_compact_findings(
    findings,
):
    content = Table(
        box=None,
        show_header=False,
        expand=True,
        padding=(0, 1),
    )

    content.add_column(
        "Finding",
        ratio=1,
    )

    severity_styles = {
        "info": "bold cyan",
        "low": "bold green",
        "medium": "bold yellow",
        "high": "bold red",
        "critical": "bold white on red",
    }

    for index, finding in enumerate(
        findings
    ):
        severity = (
            _finding_severity_value(
                finding
            )
        )

        severity_text = Text()

        severity_text.append(
            severity.upper(),
            style=severity_styles.get(
                severity,
                "bold white",
            ),
        )

        severity_text.append(
            "  "
        )

        severity_text.append(
            finding.rule_id,
            style="bold",
        )

        body = Text()

        body.append(
            "ID: ",
            style="bold cyan",
        )

        body.append(
            finding.finding_id[:12]
        )

        body.append("\n")

        state = (
            _finding_state_value(
                finding
            )
        )

        if state is not None:
            body.append(
                "State: ",
                style="bold cyan",
            )

            body.append(
                state.upper()
            )

            body.append("\n")

        body.append(
            "Asset: ",
            style="bold cyan",
        )

        body.append(
            f"{finding.asset_type.value.upper()} "
            f"{finding.asset_value}"
        )

        body.append("\n")

        body.append(
            "Service: ",
            style="bold cyan",
        )

        body.append(
            finding.affected_service
            or "-"
        )

        body.append("\n")

        body.append(
            "Plugin: ",
            style="bold cyan",
        )

        body.append(
            finding.plugin
            or "-"
        )

        body.append("\n\n")

        body.append(
            finding.description
        )

        finding_block = Group(
            severity_text,
            body,
        )

        content.add_row(
            finding_block
        )

        if (
            index
            < len(findings) - 1
        ):
            content.add_row(
                Rule(
                    style="bright_black"
                )
            )

    console.print(
        Panel(
            content,
            title=(
                "[bold yellow] "
                "FINDINGS "
                "[/bold yellow]"
            ),
            title_align="left",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )

def print_root_usage():
    usage = Text()

    usage.append(
        "  aegis ",
        style="bold white",
    )

    usage.append(
        "[OPTIONS]",
        style="bold yellow",
    )

    usage.append(
        " COMMAND ",
        style="bold white",
    )

    usage.append(
        "[ARGS]...",
        style="bold yellow",
    )

    console.print(
        Panel(
            usage,
            title="[bold white] USAGE [/bold white]",
            title_align="left",
            border_style="bright_cyan",
            box=box.ROUNDED,
        )
    )



def print_root_commands():
    commands = [
        (
            "version",
            "Show the installed AEGIS / ARGUS version.",
        ),
        (
            "info",
            "Show platform capabilities and lifecycle states.",
        ),
        (
            "status",
            "Show the current campaign operational overview.",
        ),
        (
            "exposure",
            "Show the current assessed exposure surface.",
        ),
        (
            "findings",
            "Inspect current exposure findings.",
        ),
        (
            "commands",
            "Show common commands and practical examples.",
        ),
        (
            "init",
            "Create a new assessment campaign.",
        ),
        (
            "scope",
            "Manage the authorized assessment scope.",
        ),
        (
            "plugin",
            "List and execute reconnaissance plugins.",
        ),
        (
            "assets",
            "Inspect discovered assets, graphs and lifecycle history.",
        ),
        (
            "relations",
            "Inspect relationships between discovered assets.",
        ),
        (
            "changes",
            "Inspect asset and relation lifecycle changes.",
        ),
        (
            "results",
            "Inspect and verify persisted plugin results.",
        ),
    ]

    table = Table(
        show_header=False,
        box=box.ROUNDED,
        border_style="magenta",
        padding=(0, 1),
        expand=True,
    )

    if terminal_is_compact():
        table.add_column(
            "Command",
            width=12,
            style="bold cyan",
            no_wrap=True,
        )

        table.add_column(
            "Description",
            style="white",
            overflow="fold",
        )
    else:
        table.add_column(
            "Command",
            width=18,
            style="bold cyan",
            no_wrap=True,
        )

        table.add_column(
            "Description",
            style="white",
            ratio=4,
            overflow="fold",
        )

    for command, description in commands:
        table.add_row(
            command,
            description,
        )

    console.print(
        Panel(
            table,
            title="[bold cyan] COMMANDS [/bold cyan]",
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 0),
        )
    )

def print_root_tip():
    console.print(
        Panel(
            "[green]Tip:[/green] "
            "Use [bold green]aegis <command> --help[/bold green] "
            "for detailed command help.",
            border_style="bright_black",
            box=box.ROUNDED,
        )
    )


def print_root_interface():
    print_banner()

    print_root_usage()

    console.print()

    print_root_commands()

    console.print()

    print_root_tip()


# ---------------------------------------------------------
# GENERIC OUTPUT
# ---------------------------------------------------------


def print_section(
    title: str,
    *,
    color: str = "cyan",
):
    console.print()

    console.print(
        Text(
            title,
            style=f"bold {color}",
        )
    )


def print_error(
    message: str,
):
    text = Text()

    text.append(
        "Error: ",
        style="bold red",
    )

    text.append(
        message,
        style="white",
    )

    console.print(text)


def print_success(
    message: str,
):
    text = Text()

    text.append(
        "✓ ",
        style="bold green",
    )

    text.append(
        message,
        style="white",
    )

    console.print(text)


def print_warning(
    message: str,
):
    text = Text()

    text.append(
        "! ",
        style="bold yellow",
    )

    text.append(
        message,
        style="white",
    )

    console.print(text)


def print_empty(
    message: str,
):
    console.print(
        Text(
            message,
            style="dim",
        )
    )


def print_saved_path(
    path: Path,
):
    text = Text()

    text.append(
        "Result saved: ",
        style="dim",
    )

    text.append(
        str(path),
        style="cyan",
    )

    console.print()
    console.print(text)


# ---------------------------------------------------------
# STATES / COLORS
# ---------------------------------------------------------


def lifecycle_style(
    change_type: ChangeType,
) -> str:
    value = change_type.value

    if value == "candidate_missing":
        return "yellow"

    if value == "inactive":
        return "red"

    if value == "reactivated":
        return "bright_cyan"

    if value in {
        "new",
        "confirmed",
        "active",
    }:
        return "green"

    return "white"


def lifecycle_text(
    change_type: ChangeType,
) -> Text:
    return Text(
        change_type.value.upper(),
        style=(
            f"bold "
            f"{lifecycle_style(change_type)}"
        ),
    )


def active_state_text(
    active: bool,
) -> Text:
    if active:
        return Text(
            "ACTIVE",
            style="bold green",
        )

    return Text(
        "INACTIVE",
        style="bold red",
    )


def integrity_status_text(
    status: str,
) -> Text:
    normalized = status.upper()

    if normalized in {
        "OK",
        "BASELINED",
    }:
        return Text(
            normalized,
            style="bold green",
        )

    if normalized == "UNKNOWN":
        return Text(
            normalized,
            style="bold yellow",
        )

    if normalized in {
        "FAILED",
        "CONFLICT",
    }:
        return Text(
            normalized,
            style="bold red",
        )

    return Text(
        normalized,
        style="white",
    )


# ---------------------------------------------------------
# VERSION
# ---------------------------------------------------------


def print_version(
    version: str,
):
    body = Text()

    body.append(
        "AEGIS",
        style="bold cyan",
    )

    body.append(
        " / ",
        style="dim",
    )

    body.append(
        "ARGUS",
        style="bold magenta",
    )

    body.append(
        "\n\nVersion: ",
        style="white",
    )

    body.append(
        version,
        style="bold white",
    )

    console.print(
        Panel(
            body,
            title="[bold cyan] VERSION [/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


# ---------------------------------------------------------
# INFO
# ---------------------------------------------------------


def print_info():
    print_banner()

    capabilities = Table(
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )

    capabilities.add_column(
        "Capability",
        style="bold white",
    )

    capabilities.add_column(
        "Description",
    )

    capabilities.add_row(
        "Scope",
        "Authorized domain, IP, URL and service scope management.",
    )

    capabilities.add_row(
        "Reconnaissance",
        "DNS, HTTP, service and TLS discovery.",
    )

    capabilities.add_row(
        "Assets",
        "Asset discovery, metadata, provenance and lifecycle.",
    )

    capabilities.add_row(
        "Relations",
        "Graph relationships between discovered assets.",
    )

    capabilities.add_row(
        "Changes",
        "Missing, inactive and reactivated state tracking.",
    )

    capabilities.add_row(
        "Integrity",
        "SHA-256 result baselines and verification.",
    )

    console.print(
        Panel(
            capabilities,
            title="[bold cyan] CAPABILITIES [/bold cyan]",
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    console.print()

    relations = Table(
        box=box.ROUNDED,
        border_style="magenta",
        show_header=False,
        expand=True,
    )

    relations.add_column(
        style="bold cyan",
    )

    relations.add_column(
        style="magenta",
        justify="center",
    )

    relations.add_column(
        style="bold cyan",
    )

    relations.add_row(
        "DOMAIN",
        "--resolves_to-->",
        "IP",
    )

    relations.add_row(
        "DOMAIN",
        "--exposes-->",
        "SERVICE",
    )

    relations.add_row(
        "SERVICE",
        "--presents-->",
        "CERTIFICATE",
    )

    console.print(
        Panel(
            relations,
            title="[bold magenta] TRACKED RELATIONS [/bold magenta]",
            title_align="left",
            border_style="magenta",
            box=box.ROUNDED,
        )
    )

    console.print()

    lifecycle = Text()

    lifecycle.append(
        "ACTIVE",
        style="bold green",
    )

    lifecycle.append(
        "  →  ",
        style="dim",
    )

    lifecycle.append(
        "CANDIDATE_MISSING",
        style="bold yellow",
    )

    lifecycle.append(
        "  →  ",
        style="dim",
    )

    lifecycle.append(
        "INACTIVE",
        style="bold red",
    )

    lifecycle.append(
        "  →  ",
        style="dim",
    )

    lifecycle.append(
        "REACTIVATED",
        style="bold bright_cyan",
    )

    lifecycle.append(
        "  →  ",
        style="dim",
    )

    lifecycle.append(
        "ACTIVE",
        style="bold green",
    )

    console.print(
        Panel(
            lifecycle,
            title="[bold green] LIFECYCLE [/bold green]",
            title_align="left",
            border_style="green",
            box=box.ROUNDED,
        )
    )


# ---------------------------------------------------------
# SCOPE
# ---------------------------------------------------------


def print_scope_table(
    targets: Iterable[Any],
):
    targets = list(targets)

    if not targets:
        print_empty(
            "Scope is empty."
        )
        return

    table = Table(
        title="Assessment Scope",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        expand=True,
    )

    table.add_column(
        "Type",
        width=14,
    )

    table.add_column(
        "Target",
        style="bold white",
    )

    for target in targets:
        table.add_row(
            target.type.value.upper(),
            target.value,
        )

    console.print()
    console.print(table)


# ---------------------------------------------------------
# PLUGINS
# ---------------------------------------------------------


def print_plugin_table(
    plugins: Iterable[Any],
):
    plugins = list(plugins)

    if not plugins:
        print_empty(
            "No plugins installed."
        )
        return

    table = Table(
        title="ARGUS Plugins",
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold magenta",
        expand=True,
    )

    table.add_column(
        "Plugin",
        width=16,
        style="bold cyan",
    )

    table.add_column(
        "Version",
        width=12,
    )

    table.add_column(
        "Description",
    )

    for plugin in plugins:
        table.add_row(
            plugin.name,
            plugin.version,
            plugin.description,
        )

    console.print()
    console.print(table)


# ---------------------------------------------------------
# ASSETS
# ---------------------------------------------------------



def print_assets_table(
    assets: Iterable[Any],
):
    assets = list(assets)

    if not assets:
        print_empty(
            "No assets found."
        )
        return

    table = Table(
        title="Discovered Assets",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        expand=True,
    )

    if terminal_is_compact():
        table.add_column(
            "Type",
            width=12,
        )

        table.add_column(
            "Asset",
            style="bold white",
            overflow="fold",
        )

        table.add_column(
            "State",
            width=10,
        )

        for asset in assets:
            detail = Text(
                asset.value,
                style="bold white",
            )

            detail.append(
                f"\nsource={asset.source}  seen={asset.seen_count}",
                style="dim",
            )

            table.add_row(
                asset.type.value.upper(),
                detail,
                active_state_text(
                    asset.active
                ),
            )
    else:
        table.add_column(
            "Type",
            width=14,
        )

        table.add_column(
            "Value",
            style="bold white",
        )

        table.add_column(
            "Source",
            width=14,
        )

        table.add_column(
            "State",
            width=12,
        )

        table.add_column(
            "Seen",
            justify="right",
            width=8,
        )

        for asset in assets:
            table.add_row(
                asset.type.value.upper(),
                asset.value,
                asset.source,
                active_state_text(
                    asset.active
                ),
                str(
                    asset.seen_count
                ),
            )

    console.print()
    console.print(table)

# ---------------------------------------------------------
# RELATIONS
# ---------------------------------------------------------



def print_relations_table(
    relations: Iterable[Any],
):
    relations = list(relations)

    if not relations:
        print_empty(
            "No relations found."
        )
        return

    table = Table(
        title="Asset Relations",
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold magenta",
        expand=True,
    )

    if terminal_is_compact():
        table.add_column(
            "Relation",
            overflow="fold",
        )

        table.add_column(
            "State",
            width=10,
        )

        for relation in relations:
            detail = Text()

            detail.append(
                f"{relation.source_type.value.upper()} "
                f"{relation.source_value}",
                style="white",
            )

            detail.append(
                f"\n--{relation.relation.value}--> ",
                style="cyan",
            )

            detail.append(
                f"{relation.target_type.value.upper()} "
                f"{relation.target_value}",
                style="white",
            )

            detail.append(
                f"\nseen={relation.seen_count}",
                style="dim",
            )

            table.add_row(
                detail,
                active_state_text(
                    relation.active
                ),
            )
    else:
        table.add_column(
            "Source",
        )

        table.add_column(
            "Relation",
            justify="center",
            style="cyan",
        )

        table.add_column(
            "Target",
        )

        table.add_column(
            "State",
            width=12,
        )

        table.add_column(
            "Seen",
            justify="right",
            width=8,
        )

        for relation in relations:
            source = (
                f"{relation.source_type.value.upper()} "
                f"{relation.source_value}"
            )

            relation_name = (
                f"--{relation.relation.value}-->"
            )

            target = (
                f"{relation.target_type.value.upper()} "
                f"{relation.target_value}"
            )

            table.add_row(
                source,
                relation_name,
                target,
                active_state_text(
                    relation.active
                ),
                str(
                    relation.seen_count
                ),
            )

    console.print()
    console.print(table)

# ---------------------------------------------------------
# CHANGES
# ---------------------------------------------------------


def change_object_text(
    change: Any,
) -> str:
    if (
        change.asset_type
        is not None
    ):
        return (
            f"{change.asset_type.value.upper()} "
            f"{change.asset_value}"
        )

    if (
        change.relation_type
        is not None
    ):
        source_type = (
            change.source_type.value.upper()
            if change.source_type
            else "UNKNOWN"
        )

        target_type = (
            change.target_type.value.upper()
            if change.target_type
            else "UNKNOWN"
        )

        return (
            f"{source_type} "
            f"{change.source_value} "
            f"--{change.relation_type.value}--> "
            f"{target_type} "
            f"{change.target_value}"
        )

    return "Unknown"



def print_changes_table(
    changes: Iterable[Any],
):
    changes = list(changes)

    if not changes:
        print_empty(
            "No changes found."
        )
        return

    table = Table(
        title="Lifecycle Changes",
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
        expand=True,
    )

    if terminal_is_compact():
        table.add_column(
            "State",
            width=18,
        )

        table.add_column(
            "Change",
            overflow="fold",
        )

        for change in changes:
            detail = Text(
                change_object_text(
                    change
                ),
                style="white",
            )

            detail.append(
                f"\nplugin={change.plugin}  "
                f"detected={change.detected_at.isoformat()}",
                style="dim",
            )

            table.add_row(
                lifecycle_text(
                    change.change_type
                ),
                detail,
            )
    else:
        table.add_column(
            "Detected",
            width=27,
        )

        table.add_column(
            "State",
            width=20,
        )

        table.add_column(
            "Object",
        )

        table.add_column(
            "Plugin",
            width=12,
        )

        for change in changes:
            table.add_row(
                change.detected_at.isoformat(),
                lifecycle_text(
                    change.change_type
                ),
                change_object_text(
                    change
                ),
                change.plugin,
            )

    console.print()
    console.print(table)

# ---------------------------------------------------------
# RESULTS
# ---------------------------------------------------------


def print_results_table(
    paths: Iterable[Path],
):
    paths = list(paths)

    if not paths:
        print_empty(
            "No results found."
        )
        return

    table = Table(
        title="Stored Results",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        expand=True,
    )

    table.add_column(
        "Filename",
        style="white",
    )

    for path in paths:
        table.add_row(
            path.name
        )

    console.print()
    console.print(table)


def print_integrity_table(
    rows: Iterable[
        tuple[str, str]
    ],
):
    rows = list(rows)

    table = Table(
        title="Result Integrity",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        expand=True,
    )

    table.add_column(
        "Result",
    )

    table.add_column(
        "Status",
        width=14,
    )

    for (
        filename,
        status,
    ) in rows:
        table.add_row(
            filename,
            integrity_status_text(
                status
            ),
        )

    console.print()
    console.print(table)


def print_integrity_summary(
    *,
    ok: int,
    baselined: int,
    failed: int,
    unknown: int,
    conflict: int,
):
    table = Table(
        title="Integrity Summary",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=False,
    )

    table.add_column(
        "State",
    )

    table.add_column(
        "Count",
        justify="right",
    )

    table.add_row(
        "OK",
        Text(
            str(ok),
            style="bold green",
        ),
    )

    table.add_row(
        "BASELINED",
        Text(
            str(baselined),
            style="bold green",
        ),
    )

    table.add_row(
        "FAILED",
        Text(
            str(failed),
            style="bold red",
        ),
    )

    table.add_row(
        "UNKNOWN",
        Text(
            str(unknown),
            style="bold yellow",
        ),
    )

    table.add_row(
        "CONFLICT",
        Text(
            str(conflict),
            style="bold red",
        ),
    )

    console.print()
    console.print(table)


# ---------------------------------------------------------
# PLUGIN RUN
# ---------------------------------------------------------


def print_plugin_summary(
    result: Any,
    processing: Any,
    detected_changes: list[Any],
):
    header = Text()

    header.append(
        "ARGUS",
        style="bold magenta",
    )

    header.append(
        "  /  ",
        style="dim",
    )

    header.append(
        result.plugin.upper(),
        style="bold cyan",
    )

    console.print()

    console.print(
        Panel(
            header,
            subtitle=(
                f"plugin version "
                f"{result.version}"
            ),
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    summary = Table(
        show_header=False,
        box=box.ROUNDED,
        border_style="bright_black",
        expand=True,
    )

    summary.add_column(
        "Metric",
        style="dim",
    )

    summary.add_column(
        "Value",
        justify="right",
        style="bold white",
    )

    summary.add_row(
        "Observations",
        str(
            len(
                result.observations
            )
        ),
    )

    summary.add_row(
        "Assets discovered",
        str(
            processing.discovered_count
        ),
    )

    accepted = Text(
        str(
            processing.accepted_count
        ),
        style="bold green",
    )

    summary.add_row(
        "Assets accepted",
        accepted,
    )

    rejected_style = (
        "bold red"
        if processing.rejected_count
        else "bold green"
    )

    rejected = Text(
        str(
            processing.rejected_count
        ),
        style=rejected_style,
    )

    summary.add_row(
        "Assets rejected",
        rejected,
    )

    changes_style = (
        "bold yellow"
        if detected_changes
        else "bold green"
    )

    changes = Text(
        str(
            len(
                detected_changes
            )
        ),
        style=changes_style,
    )

    summary.add_row(
        "Changes detected",
        changes,
    )

    console.print(summary)


def print_rejected_assets(
    rejected: Iterable[Any],
):
    rejected = list(rejected)

    if not rejected:
        return

    print_section(
        "Rejected assets",
        color="red",
    )

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold red",
        expand=True,
    )

    table.add_column(
        "Type",
        width=14,
    )

    table.add_column(
        "Asset",
    )

    table.add_column(
        "Reason",
    )

    for item in rejected:
        table.add_row(
            item.asset.type.value.upper(),
            item.asset.value,
            item.reason.value,
        )

    console.print(table)


def print_plugin_changes(
    changes: Iterable[Any],
):
    changes = list(changes)

    if not changes:
        return

    print_section(
        "Changes",
        color="yellow",
    )

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold yellow",
        expand=True,
    )

    table.add_column(
        "State",
        width=20,
    )

    table.add_column(
        "Object",
    )

    for change in changes:
        table.add_row(
            lifecycle_text(
                change.change_type
            ),
            change_object_text(
                change
            ),
        )

    console.print(table)


def print_plugin_observations(
    observations: Iterable[Any],
):
    observations = list(
        observations
    )

    if not observations:
        return

    print_section(
        "Observations",
        color="cyan",
    )

    for observation in observations:
        if (
            observation.type
            == "dns_resolution"
        ):
            _print_dns_observation(
                observation
            )

        elif (
            observation.type
            == "http_probe"
        ):
            _print_http_observation(
                observation
            )

        elif (
            observation.type
            == "service_open"
        ):
            _print_service_observation(
                observation
            )

        elif (
            observation.type
            == "tls_handshake"
        ):
            _print_tls_observation(
                observation
            )

        else:
            _print_generic_observation(
                observation
            )


def print_plugin_run_output(
    result: Any,
    processing: Any,
    detected_changes: list[Any],
    saved_path: Path,
):
    print_plugin_summary(
        result,
        processing,
        detected_changes,
    )

    print_rejected_assets(
        processing.rejected
    )

    print_plugin_changes(
        detected_changes
    )

    print_plugin_observations(
        result.observations
    )

    print_saved_path(
        saved_path
    )


# ---------------------------------------------------------
# OBSERVATION RENDERERS
# ---------------------------------------------------------


def _observation_panel(
    observation: Any,
    body: Any,
):
    console.print(
        Panel(
            body,
            title=(
                f"[cyan]"
                f"{observation.target}"
                f"[/cyan]"
            ),
            subtitle=(
                observation.type
            ),
            border_style="bright_black",
            box=box.ROUNDED,
        )
    )


def _print_dns_observation(
    observation: Any,
):
    addresses = (
        observation.data.get(
            "addresses",
            [],
        )
    )

    body = Text()

    if addresses:
        for index, address in enumerate(
            addresses
        ):
            body.append(
                f"• {address}",
                style="white",
            )

            if (
                index
                < len(addresses) - 1
            ):
                body.append("\n")

    else:
        body.append(
            "No addresses found.",
            style="dim",
        )

    _observation_panel(
        observation,
        body,
    )


def _print_http_observation(
    observation: Any,
):
    table = Table(
        show_header=False,
        box=None,
    )

    table.add_column(
        style="dim",
    )

    table.add_column(
        style="white",
    )

    table.add_row(
        "URL",
        str(
            observation.data.get(
                "url"
            )
        ),
    )

    table.add_row(
        "Status",
        str(
            observation.data.get(
                "status_code"
            )
        ),
    )

    table.add_row(
        "Server",
        str(
            observation.data.get(
                "server"
            )
        ),
    )

    table.add_row(
        "Content-Type",
        str(
            observation.data.get(
                "content_type"
            )
        ),
    )

    _observation_panel(
        observation,
        table,
    )


def _print_service_observation(
    observation: Any,
):
    table = Table(
        show_header=False,
        box=None,
    )

    table.add_column(
        style="dim",
    )

    table.add_column(
        style="white",
    )

    host = observation.data.get(
        "host"
    )

    port = observation.data.get(
        "port"
    )

    transport = (
        observation.data.get(
            "transport",
            "tcp",
        )
    )

    table.add_row(
        "Service",
        (
            f"{host}:"
            f"{port}/"
            f"{transport}"
        ),
    )

    table.add_row(
        "Name",
        str(
            observation.data.get(
                "service_name",
                "unknown",
            )
        ),
    )

    tls_text = (
        Text(
            "yes",
            style="bold green",
        )
        if observation.data.get(
            "tls",
            False,
        )
        else Text(
            "no",
            style="dim",
        )
    )

    table.add_row(
        "TLS",
        tls_text,
    )

    confidence = (
        observation.data.get(
            "confidence"
        )
    )

    if confidence:
        table.add_row(
            "Confidence",
            confidence,
        )

    fingerprint_source = (
        observation.data.get(
            "fingerprint_source"
        )
    )

    if fingerprint_source:
        table.add_row(
            "Fingerprint",
            fingerprint_source,
        )

    banner = (
        observation.data.get(
            "banner"
        )
    )

    if banner:
        table.add_row(
            "Banner",
            banner,
        )

    product = (
        observation.data.get(
            "product"
        )
    )

    version = (
        observation.data.get(
            "version"
        )
    )

    if product:
        if version:
            product_text = (
                f"{product} {version}"
            )
        else:
            product_text = product

        table.add_row(
            "Product",
            product_text,
        )

    _observation_panel(
        observation,
        table,
    )


def _print_tls_observation(
    observation: Any,
):
    table = Table(
        show_header=False,
        box=None,
    )

    table.add_column(
        style="dim",
    )

    table.add_column(
        style="white",
    )

    host = observation.data.get(
        "host"
    )

    port = observation.data.get(
        "port"
    )

    if host is not None:
        table.add_row(
            "Service",
            (
                f"{host}:"
                f"{port}"
            ),
        )

    tls_version = (
        observation.data.get(
            "tls_version"
        )
    )

    if tls_version:
        table.add_row(
            "TLS version",
            tls_version,
        )

    cipher = (
        observation.data.get(
            "cipher"
        )
    )

    if cipher:
        table.add_row(
            "Cipher",
            cipher,
        )

    certificate = (
        observation.data.get(
            "certificate_sha256"
        )
    )

    if certificate:
        table.add_row(
            "Certificate",
            certificate,
        )

    subject = (
        observation.data.get(
            "subject"
        )
    )

    if subject:
        table.add_row(
            "Subject",
            str(subject),
        )

    issuer = (
        observation.data.get(
            "issuer"
        )
    )

    if issuer:
        table.add_row(
            "Issuer",
            str(issuer),
        )

    sans = (
        observation.data.get(
            "sans",
            [],
        )
    )

    if sans:
        table.add_row(
            "SANs",
            ", ".join(
                str(item)
                for item in sans
            ),
        )

    _observation_panel(
        observation,
        table,
    )


def _print_generic_observation(
    observation: Any,
):
    table = Table(
        show_header=False,
        box=None,
    )

    table.add_column(
        style="dim",
    )

    table.add_column(
        style="white",
    )

    for (
        key,
        value,
    ) in observation.data.items():
        table.add_row(
            str(key),
            str(value),
        )

    _observation_panel(
        observation,
        table,
    )
# ---------------------------------------------------------
# COMMAND REFERENCE
# ---------------------------------------------------------



def print_commands_reference():
    sections = [
        (
            "CAMPAIGN",
            [
                (
                    "aegis init <name>",
                    "Create a new assessment campaign.",
                ),
                (
                    "aegis status",
                    "Show campaign scope, exposure, changes and integrity.",
                ),
                (
                    "aegis status --json",
                    "Output campaign status as JSON.",
                ),
            ],
        ),
        (
            "EXPOSURE",
            [
                (
                    "aegis exposure",
                    "Show the current assessed exposure surface.",
                ),
                (
                    "aegis exposure --json",
                    "Output the exposure surface as JSON.",
                ),
            ],
        ),
        (
            "FINDINGS",
            [
                (
                    "aegis findings list",
                    "List persisted exposure findings.",
                ),
                (
                    "aegis findings list --state active",
                    "Show active findings.",
                ),
                (
                    "aegis findings list --state resolved",
                    "Show resolved findings.",
                ),
                (
                    "aegis findings list --state candidate_missing",
                    "Show findings awaiting missing confirmation.",
                ),
                (
                    "aegis findings list --severity high",
                    "Filter findings by severity.",
                ),
                (
                    "aegis findings list --rule TLS_CERTIFICATE_EXPIRED",
                    "Filter findings by rule.",
                ),
                (
                    "aegis findings list --asset-type service",
                    "Filter findings by asset type.",
                ),
                (
                    "aegis findings list --json",
                    "Output current findings as JSON.",
                ),
                (
                    "aegis findings show <id>",
                    "Show detailed information about a finding.",
                ),
            ],
        ),
        (
            "SCOPE",
            [
                (
                    "aegis scope add example.com",
                    "Add an authorized target.",
                ),
                (
                    "aegis scope list",
                    "List current scope targets.",
                ),
                (
                    "aegis scope remove example.com",
                    "Remove a target from scope.",
                ),
            ],
        ),
        (
            "DISCOVERY",
            [
                (
                    "aegis plugin list",
                    "List installed reconnaissance plugins.",
                ),
                (
                    "aegis plugin run dns",
                    "Resolve in-scope domains.",
                ),
                (
                    "aegis plugin run service",
                    "Discover exposed services.",
                ),
                (
                    "aegis plugin run tls",
                    "Inspect TLS services and certificates.",
                ),
                (
                    "aegis plugin run http",
                    "Probe HTTP endpoints.",
                ),
            ],
        ),
        (
            "ASSETS",
            [
                (
                    "aegis assets list",
                    "List discovered assets.",
                ),
                (
                    "aegis assets list --type service",
                    "Filter assets by type.",
                ),
                (
                    "aegis assets show <filename>",
                    "Inspect a persisted asset record.",
                ),
                (
                    "aegis assets history service example.com:443",
                    "Show lifecycle history for an asset.",
                ),
                (
                    "aegis assets related domain example.com",
                    "Show incoming and outgoing relations.",
                ),
                (
                    "aegis assets graph example.com --type domain",
                    "Walk the asset relation graph.",
                ),
            ],
        ),
        (
            "RELATIONS",
            [
                (
                    "aegis relations list",
                    "List discovered relations.",
                ),
                (
                    "aegis relations show <filename>",
                    "Inspect a persisted relation record.",
                ),
                (
                    "aegis relations from domain example.com",
                    "List relations originating from an asset.",
                ),
                (
                    "aegis relations to service example.com:443",
                    "List relations pointing to an asset.",
                ),
                (
                    "aegis relations history domain example.com "
                    "resolves_to ip 104.20.23.154",
                    "Show relation lifecycle history.",
                ),
            ],
        ),
        (
            "CHANGES",
            [
                (
                    "aegis changes list",
                    "List detected lifecycle changes.",
                ),
                (
                    "aegis changes list --json",
                    "Output lifecycle changes as JSON.",
                ),
                (
                    "aegis changes list --type inactive",
                    "Show inactive transitions.",
                ),
                (
                    "aegis changes list --type reactivated",
                    "Show reactivations.",
                ),
                (
                    "aegis changes list --plugin dns",
                    "Filter changes by plugin.",
                ),
                (
                    "aegis changes list --relation-type resolves_to",
                    "Filter relation changes.",
                ),
                (
                    "aegis changes show <filename>",
                    "Inspect a persisted change record.",
                ),
            ],
        ),
        (
            "RESULTS & INTEGRITY",
            [
                (
                    "aegis results list",
                    "List stored plugin results.",
                ),
                (
                    "aegis results show <filename>",
                    "Inspect a stored result.",
                ),
                (
                    "aegis results verify <filename>",
                    "Verify SHA-256 integrity.",
                ),
                (
                    "aegis results verify-all",
                    "Verify all stored results.",
                ),
                (
                    "aegis results baseline-legacy",
                    "Create retrospective baselines for legacy results.",
                ),
                (
                    "aegis results integrity-summary",
                    "Show integrity manifest summary.",
                ),
                (
                    "aegis results integrity-show <filename>",
                    "Show an integrity manifest record.",
                ),
            ],
        ),
    ]

    console.print()

    console.print(
        Panel(
            "[bold cyan]AEGIS[/bold cyan] / "
            "[bold magenta]ARGUS[/bold magenta]\n"
            "[dim]Common commands and practical examples[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    compact = terminal_is_compact()

    for title, items in sections:
        if compact:
            table = Table(
                box=box.SIMPLE,
                show_header=False,
                expand=True,
                padding=(0, 1),
            )

            table.add_column(
                "Command",
                overflow="fold",
            )

            for command, description in items:
                cell = Text()
                cell.append(
                    command,
                    style="bold cyan",
                )
                cell.append(
                    "\n  ",
                    style="dim",
                )
                cell.append(
                    description,
                    style="white",
                )

                table.add_row(
                    cell
                )
        else:
            table = Table(
                box=box.SIMPLE,
                show_header=False,
                expand=True,
                padding=(0, 1),
            )

            table.add_column(
                "Command",
                style="bold cyan",
                ratio=3,
                overflow="fold",
            )

            table.add_column(
                "Description",
                style="white",
                ratio=2,
                overflow="fold",
            )

            for command, description in items:
                table.add_row(
                    command,
                    description,
                )

        console.print(
            Panel(
                table,
                title=f"[bold]{title}[/bold]",
                title_align="left",
                border_style="bright_black",
                box=box.ROUNDED,
            )
        )

    print_root_tip()

# ---------------------------------------------------------
# DETAIL / HISTORY HELPERS
# ---------------------------------------------------------


def _detail_panel(
    title: str,
    lines: Iterable[str | Text],
    *,
    border_style: str = "cyan",
):
    body = Text()

    items = list(lines)

    for index, item in enumerate(items):
        if isinstance(item, Text):
            body.append_text(item)
        else:
            body.append(str(item))

        if index < len(items) - 1:
            body.append("\n")

    console.print()
    console.print(
        Panel(
            body,
            title=f"[bold]{title}[/bold]",
            title_align="left",
            border_style=border_style,
            box=box.ROUNDED,
        )
    )


def print_result_detail(
    result: Any,
    *,
    filename: str | None = None,
):
    lines: list[str] = []

    if filename:
        lines.append(f"Result: {filename}")

    lines.extend(
        [
            f"Plugin: {result.plugin}",
            f"Version: {result.version}",
            f"Status: {result.status}",
            f"Timestamp: {result.timestamp}",
            f"Observations: {len(result.observations)}",
        ]
    )

    _detail_panel(
        "Stored Result",
        lines,
        border_style="cyan",
    )

    if result.observations:
        print_section(
            "Observations",
            color="cyan",
        )

    for observation in result.observations:
        body = Text()
        body.append(f"Target: {observation.target}\n")
        body.append(f"Type: {observation.type}\n")
        body.append(f"Data: {observation.data}")

        console.print(
            Panel(
                body,
                border_style="bright_black",
                box=box.ROUNDED,
            )
        )


def print_result_integrity_detail(
    *,
    filename: str,
    current: str,
    expected: str | None,
    status: str,
):
    expected_text = (
        expected
        if expected is not None
        else "unavailable"
    )

    body = Text()
    body.append("Result integrity\n", style="bold cyan")
    body.append(f"Result: {filename}\n")
    body.append(f"Current SHA-256: {current}\n")
    body.append(f"Stored SHA-256: {expected_text}\n")
    body.append("Integrity: ")
    body.append_text(
        integrity_status_text(
            status
        )
    )

    console.print()
    console.print(
        Panel(
            body,
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def print_integrity_manifest_summary(
    *,
    total: int,
    original: int,
    retrospective: int,
    verified: int,
    unverified: int,
):
    _detail_panel(
        "Integrity manifest",
        [
            f"Records: {total}",
            f"Original: {original}",
            f"Retrospective: {retrospective}",
            f"Verified: {verified}",
            f"Unverified: {unverified}",
        ],
        border_style="cyan",
    )


def print_integrity_record(
    record: Any,
):
    verified_at = (
        record.verified_at
        if record.verified_at is not None
        else "never"
    )

    _detail_panel(
        "Integrity record",
        [
            f"Result: {record.filename}",
            f"SHA-256: {record.sha256}",
            f"Baseline: {record.baseline_type.value}",
            f"Created at: {record.created_at}",
            f"Verified at: {verified_at}",
        ],
        border_style="cyan",
    )


def print_legacy_baseline_summary(
    *,
    baselined_files: Iterable[str],
    baselined: int,
    skipped: int,
):
    files = list(
        baselined_files
    )

    lines: list[str] = [
        "Legacy result baselines",
    ]

    lines.extend(
        f"{filename} BASELINED"
        for filename in files
    )

    lines.extend(
        [
            "Summary",
            f"Baselined: {baselined}",
            f"Skipped: {skipped}",
        ]
    )

    _detail_panel(
        "Retrospective baselines",
        lines,
        border_style="yellow",
    )


def print_asset_detail(
    asset: Any,
):
    summary = [
        "Asset",
        f"Type: {asset.type.value}",
        f"Value: {asset.value}",
        f"Source: {asset.source}",
    ]

    _detail_panel(
        "Asset",
        summary,
        border_style="cyan",
    )

    if (
        asset.first_seen is not None
        or asset.last_seen is not None
    ):
        _detail_panel(
            "Lifecycle",
            [
                f"First seen: {asset.first_seen}",
                f"Last seen: {asset.last_seen}",
                f"Last confirmed: {asset.last_confirmed}",
                f"Seen count: {asset.seen_count}",
                f"Active: {'yes' if asset.active else 'no'}",
            ],
            border_style=(
                "green"
                if asset.active
                else "red"
            ),
        )

    if asset.metadata:
        _detail_panel(
            "Metadata",
            [
                f"{key}: {value}"
                for key, value
                in asset.metadata.items()
            ],
            border_style="bright_black",
        )

    if asset.provenance:
        for index, item in enumerate(
            asset.provenance,
            start=1,
        ):
            lines = [
                f"Plugin: {item.plugin}",
            ]

            if item.plugin_version:
                lines.append(
                    f"Plugin version: {item.plugin_version}"
                )

            lines.extend(
                [
                    f"Observation type: {item.observation_type}",
                    f"Target: {item.target}",
                    f"Observed at: {item.observed_at}",
                ]
            )

            if item.observation_id:
                lines.append(
                    f"Observation ID: {item.observation_id[:12]}"
                )
            else:
                lines.append(
                    "Observation ID: legacy"
                )

            if item.result_id:
                lines.append(
                    f"Result ID: {item.result_id}"
                )

            if item.result_sha256:
                lines.append(
                    f"Result SHA-256: {item.result_sha256}"
                )

            if item.result_file:
                lines.append(
                    f"Result: {item.result_file}"
                )

            title = (
                f"Provenance #{index}"
                if len(asset.provenance) > 1
                else "Provenance"
            )

            _detail_panel(
                title,
                lines,
                border_style="magenta",
            )


def print_asset_graph(
    graphs: Iterable[
        tuple[Any, Iterable[tuple[int, Any]]]
    ],
    *,
    details: bool = False,
):
    graphs = list(
        graphs
    )

    console.print()
    console.print(
        "[bold cyan]Asset graph[/bold cyan]"
    )

    for root, walked in graphs:
        body = Text()
        body.append(
            f"{root.type.value.upper()} {root.value}",
            style="bold white",
        )

        walked = list(
            walked
        )

        if not walked:
            body.append(
                "\n  No outgoing relations.",
                style="dim",
            )

        for depth, relation in walked:
            indent = "  " * depth

            body.append(
                (
                    f"\n{indent}└── "
                    f"{relation.relation.value.upper()} "
                    f"{relation.target_type.value.upper()} "
                    f"{relation.target_value}"
                )
            )

            if details:
                detail_indent = (
                    "  " * (depth + 1)
                )

                if relation.seen_count > 0:
                    body.append(
                        (
                            f"\n{detail_indent}"
                            f"[active: "
                            f"{'yes' if relation.active else 'no'}, "
                            f"seen: {relation.seen_count}, "
                            f"first: {relation.first_seen}, "
                            f"last: {relation.last_seen}, "
                            f"confirmed: "
                            f"{relation.last_confirmed}]"
                        ),
                        style="dim",
                    )
                else:
                    body.append(
                        (
                            f"\n{detail_indent}"
                            "[lifecycle: legacy/unavailable]"
                        ),
                        style="dim",
                    )

        console.print(
            Panel(
                body,
                border_style="cyan",
                box=box.ROUNDED,
            )
        )


def print_asset_relations(
    *,
    asset_type: Any,
    value: str,
    outgoing: Iterable[Any],
    incoming: Iterable[Any],
):
    outgoing = list(
        outgoing
    )
    incoming = list(
        incoming
    )

    console.print()
    console.print(
        Panel(
            (
                "[bold cyan]Related assets[/bold cyan]\n"
                f"Asset: {asset_type.value.upper()} {value}"
            ),
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    print_section(
        "Outgoing",
        color="magenta",
    )

    if not outgoing:
        print_empty(
            "No outgoing relations."
        )
    else:
        for relation in outgoing:
            console.print(
                (
                    f"  --{relation.relation.value}--> "
                    f"{relation.target_type.value.upper()} "
                    f"{relation.target_value}"
                )
            )
            console.print(
                f"    Seen: {relation.seen_count}",
                style="dim",
            )

    print_section(
        "Incoming",
        color="magenta",
    )

    if not incoming:
        print_empty(
            "No incoming relations."
        )
    else:
        for relation in incoming:
            console.print(
                (
                    f"  {relation.source_type.value.upper()} "
                    f"{relation.source_value} "
                    f"--{relation.relation.value}-->"
                )
            )
            console.print(
                f"    Seen: {relation.seen_count}",
                style="dim",
            )


def print_relation_detail(
    relation: Any,
):
    _detail_panel(
        "Relation",
        [
            "Relation",
            f"Source type: {relation.source_type.value}",
            f"Source: {relation.source_value}",
            f"Relation: {relation.relation.value}",
            f"Target type: {relation.target_type.value}",
            f"Target: {relation.target_value}",
        ],
        border_style="magenta",
    )

    if (
        relation.first_seen is not None
        or relation.last_seen is not None
        or relation.last_confirmed is not None
        or relation.seen_count > 0
    ):
        _detail_panel(
            "Lifecycle",
            [
                f"First seen: {relation.first_seen}",
                f"Last seen: {relation.last_seen}",
                f"Last confirmed: {relation.last_confirmed}",
                f"Seen count: {relation.seen_count}",
                f"Active: {'yes' if relation.active else 'no'}",
            ],
            border_style=(
                "green"
                if relation.active
                else "red"
            ),
        )

    if relation.provenance:
        for index, item in enumerate(
            relation.provenance,
            start=1,
        ):
            lines = [
                f"Plugin: {item.plugin}",
            ]

            if item.plugin_version:
                lines.append(
                    f"Plugin version: {item.plugin_version}"
                )

            lines.extend(
                [
                    f"Observation type: {item.observation_type}",
                    f"Target: {item.target}",
                    f"Observed at: {item.observed_at}",
                ]
            )

            if item.observation_id:
                lines.append(
                    f"Observation ID: {item.observation_id}"
                )

            if item.result_id:
                lines.append(
                    f"Result ID: {item.result_id}"
                )

            if item.result_sha256:
                lines.append(
                    f"Result SHA-256: {item.result_sha256}"
                )

            if item.result_file:
                lines.append(
                    f"Result: {item.result_file}"
                )

            _detail_panel(
                (
                    f"Provenance #{index}"
                    if len(relation.provenance) > 1
                    else "Provenance"
                ),
                lines,
                border_style="magenta",
            )


def print_change_detail(
    change: Any,
):
    lines = [
        "Change",
        f"Type: {change.change_type.value}",
    ]

    if change.asset_type is not None:
        lines.extend(
            [
                "Kind: asset",
                f"Asset type: {change.asset_type.value}",
                f"Asset: {change.asset_value}",
            ]
        )

    elif change.relation_type is not None:
        lines.extend(
            [
                "Kind: relation",
                f"Relation: {change.relation_type.value}",
                f"Source type: {change.source_type.value}",
                f"Source: {change.source_value}",
                f"Target type: {change.target_type.value}",
                f"Target asset: {change.target_value}",
            ]
        )

    lines.extend(
        [
            f"Plugin: {change.plugin}",
            f"Target: {change.target}",
            f"Detected at: {change.detected_at}",
        ]
    )

    if change.previous_result:
        lines.append(
            f"Previous result: {change.previous_result}"
        )

    if change.current_result:
        lines.append(
            f"Current result: {change.current_result}"
        )

    _detail_panel(
        "Change",
        lines,
        border_style=(
            lifecycle_style(
                change.change_type
            )
        ),
    )


def print_asset_history(
    asset: Any,
    events: Iterable[
        tuple[Any, str, str | None]
    ],
):
    events = list(
        events
    )

    lines = [
        "ARGUS",
        "Asset history",
        (
            f"{asset.type.value.upper()} "
            f"{asset.value}"
        ),
        f"Type: {asset.type.value}",
        f"Value: {asset.value}",
        f"Source: {asset.source}",
        f"Active: {'yes' if asset.active else 'no'}",
        f"Seen count: {asset.seen_count}",
    ]

    if asset.first_seen:
        lines.append(
            f"First seen: {asset.first_seen.isoformat()}"
        )

    if asset.last_seen:
        lines.append(
            f"Last seen: {asset.last_seen.isoformat()}"
        )

    if asset.last_confirmed:
        lines.append(
            f"Last confirmed: {asset.last_confirmed.isoformat()}"
        )

    _detail_panel(
        "Asset history",
        lines,
        border_style="cyan",
    )

    if not events:
        _detail_panel(
            "Timeline",
            [
                "No history found.",
            ],
            border_style="bright_black",
        )
        return

    timeline = []

    for timestamp, event_type, result_file in events:
        line = (
            f"{timestamp.isoformat()} "
            f"{event_type.upper()}"
        )

        if result_file:
            line += (
                f" [{result_file}]"
            )

        timeline.append(
            line
        )

    _detail_panel(
        "Timeline",
        timeline,
        border_style="bright_black",
    )


def print_relation_history(
    relation: Any,
    events: Iterable[
        tuple[Any, str, str | None]
    ],
):
    events = list(
        events
    )

    _detail_panel(
        "Relation history",
        [
            "ARGUS",
            "Relation history",
            (
                f"{relation.source_type.value.upper()} "
                f"{relation.source_value}"
            ),
            (
                f"--{relation.relation.value}--> "
                f"{relation.target_type.value.upper()} "
                f"{relation.target_value}"
            ),
            f"First seen: {relation.first_seen}",
            f"Last seen: {relation.last_seen}",
            f"Last confirmed: {relation.last_confirmed}",
            f"Seen count: {relation.seen_count}",
            f"Active: {'yes' if relation.active else 'no'}",
        ],
        border_style="magenta",
    )

    if not events:
        _detail_panel(
            "Timeline",
            [
                "No history found.",
            ],
            border_style="bright_black",
        )
        return

    timeline = []

    for timestamp, event_type, result_file in events:
        line = (
            f"{timestamp.isoformat()} "
            f"{event_type.upper()}"
        )

        if result_file:
            line += (
                f" [{result_file}]"
            )

        timeline.append(
            line
        )

    _detail_panel(
        "Timeline",
        timeline,
        border_style="bright_black",
    )

def print_status_dashboard(
    *,
    campaign_name: str,
    scope_counts: dict[str, int],
    active_assets: int,
    inactive_assets: int,
    active_relations: int,
    inactive_relations: int,
    changes_count: int,
    results_count: int,
    integrity_verification: dict[str, int],
    integrity_baselines: dict[str, int],
    recent_changes: list[Any],
    latest_result: Any | None,
):
    console.print()

    header = Text()

    header.append(
        "AEGIS",
        style="bold cyan",
    )

    header.append(
        " / ",
        style="dim",
    )

    header.append(
        "ARGUS",
        style="bold magenta",
    )

    header.append(
        "\nAssessment status",
        style="bold white",
    )

    console.print(
        Panel(
            header,
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # -------------------------------------------------
    # CAMPAIGN
    # -------------------------------------------------

    campaign = Table(
        show_header=False,
        box=box.ROUNDED,
        border_style="bright_black",
        expand=True,
    )

    campaign.add_column(
        "Field",
        style="dim",
    )

    campaign.add_column(
        "Value",
        style="bold white",
    )

    campaign.add_row(
        "Campaign",
        campaign_name,
    )

    campaign.add_row(
        "Results",
        str(results_count),
    )

    campaign.add_row(
        "Changes",
        str(changes_count),
    )

    console.print(
        Panel(
            campaign,
            title="[bold cyan] CAMPAIGN [/bold cyan]",
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # -------------------------------------------------
    # SCOPE
    # -------------------------------------------------

    scope = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )

    scope.add_column(
        "Type",
    )

    scope.add_column(
        "Count",
        justify="right",
    )

    for (
        target_type,
        count,
    ) in sorted(
        scope_counts.items()
    ):
        scope.add_row(
            target_type.upper(),
            str(count),
        )

    console.print(
        Panel(
            scope,
            title="[bold cyan] SCOPE [/bold cyan]",
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # -------------------------------------------------
    # EXPOSURE
    # -------------------------------------------------

    exposure = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )

    exposure.add_column(
        "Object",
    )

    exposure.add_column(
        "Active",
        justify="right",
    )

    exposure.add_column(
        "Inactive",
        justify="right",
    )

    exposure.add_row(
        "Assets",
        Text(
            str(active_assets),
            style="bold green",
        ),
        Text(
            str(inactive_assets),
            style="bold red",
        ),
    )

    exposure.add_row(
        "Relations",
        Text(
            str(active_relations),
            style="bold green",
        ),
        Text(
            str(inactive_relations),
            style="bold red",
        ),
    )

    console.print(
        Panel(
            exposure,
            title="[bold magenta] EXPOSURE [/bold magenta]",
            title_align="left",
            border_style="magenta",
            box=box.ROUNDED,
        )
    )

     # -------------------------------------------------
    # INTEGRITY
    # -------------------------------------------------

    verification = Table(
        box=box.SIMPLE,
        show_header=False,
        expand=True,
    )

    verification.add_column(
        "Status",
    )

    verification.add_column(
        "Count",
        justify="right",
    )

    for status in [
        "OK",
        "FAILED",
        "UNKNOWN",
        "CONFLICT",
    ]:
        verification.add_row(
            integrity_status_text(
                status
            ),
            str(
                integrity_verification.get(
                    status,
                    0,
                )
            ),
        )

    console.print(
        Panel(
            verification,
            title=(
                "[bold cyan] "
                "INTEGRITY / VERIFICATION "
                "[/bold cyan]"
            ),
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    baselines = Table(
        box=box.SIMPLE,
        show_header=False,
        expand=True,
    )

    baselines.add_column(
        "Baseline",
    )

    baselines.add_column(
        "Count",
        justify="right",
    )

    baselines.add_row(
        Text(
            "ORIGINAL",
            style="bold green",
        ),
        str(
            integrity_baselines.get(
                "ORIGINAL",
                0,
            )
        ),
    )

    baselines.add_row(
        Text(
            "RETROSPECTIVE",
            style="bold yellow",
        ),
        str(
            integrity_baselines.get(
                "RETROSPECTIVE",
                0,
            )
        ),
    )

    console.print(
        Panel(
            baselines,
            title=(
                "[bold magenta] "
                "INTEGRITY / BASELINES "
                "[/bold magenta]"
            ),
            title_align="left",
            border_style="magenta",
            box=box.ROUNDED,
        )
    )

    # -------------------------------------------------
    # RECENT CHANGES
    # -------------------------------------------------

    if recent_changes:
        changes_table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )

        if terminal_is_compact():
            changes_table.add_column(
                "State",
                width=18,
            )

            changes_table.add_column(
                "Change",
                overflow="fold",
            )

            for change in recent_changes:
                detail = Text(
                    change_object_text(
                        change
                    ),
                    style="white",
                )

                detail.append(
                    f"\nplugin={change.plugin}",
                    style="dim",
                )

                changes_table.add_row(
                    lifecycle_text(
                        change.change_type
                    ),
                    detail,
                )
        else:
            changes_table.add_column(
                "State",
                width=20,
            )

            changes_table.add_column(
                "Object",
            )

            changes_table.add_column(
                "Plugin",
                width=12,
            )

            for change in recent_changes:
                changes_table.add_row(
                    lifecycle_text(
                        change.change_type
                    ),
                    change_object_text(
                        change
                    ),
                    change.plugin,
                )

        console.print(
            Panel(
                changes_table,
                title="[bold yellow] RECENT CHANGES [/bold yellow]",
                title_align="left",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    # -------------------------------------------------
    # LATEST RESULT
    # -------------------------------------------------

    if latest_result is not None:
        path, result = latest_result

        latest = Table(
            show_header=False,
            box=box.SIMPLE,
            expand=True,
        )

        latest.add_column(
            "Field",
            style="dim",
        )

        latest.add_column(
            "Value",
            style="white",
        )

        latest.add_row(
            "Plugin",
            result.plugin,
        )

        latest.add_row(
            "Version",
            result.version,
        )

        latest.add_row(
            "Timestamp",
            str(
                result.timestamp
            ),
        )

        latest.add_row(
            "Result",
            path.name,
        )

        console.print(
            Panel(
                latest,
                title="[bold magenta] LATEST EXECUTION [/bold magenta]",
                title_align="left",
                border_style="magenta",
                box=box.ROUNDED,
            )
        )

def print_exposure_dashboard(
    *,
    asset_counts,
    services,
    tls_relations,
    recent_changes,
    findings,
):
    console.print()

    # -------------------------------------------------
    # HEADER
    # -------------------------------------------------

    console.print(
        Panel(
            "[bold cyan]AEGIS[/bold cyan] / "
            "[bold magenta]EXPOSURE[/bold magenta]\n"
            "[dim]Current externally visible assessment surface[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # -------------------------------------------------
    # EXPOSURE SUMMARY
    # -------------------------------------------------

    summary = Table(
        box=box.ROUNDED,
        header_style="bold cyan",
        expand=True,
    )

    summary.add_column(
        "Type",
    )

    summary.add_column(
        "Active",
        justify="right",
    )

    summary.add_column(
        "Inactive",
        justify="right",
    )

    for asset_type, counts in sorted(
        asset_counts.items()
    ):
        summary.add_row(
            asset_type.upper(),
            str(
                counts.get(
                    "active",
                    0,
                )
            ),
            str(
                counts.get(
                    "inactive",
                    0,
                )
            ),
        )

    console.print(
        Panel(
            summary,
            title=(
                "[bold cyan] "
                "EXPOSURE SUMMARY "
                "[/bold cyan]"
            ),
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # -------------------------------------------------
    # SERVICES
    # -------------------------------------------------

    if services:
        service_table = Table(
            box=box.ROUNDED,
            header_style="bold magenta",
            expand=True,
        )

        service_table.add_column(
            "Service",
        )

        service_table.add_column(
            "Source",
        )

        service_table.add_column(
            "TLS",
            width=8,
        )

        service_table.add_column(
            "State",
            width=12,
        )

        for service in services:
            tls_text = Text(
                (
                    "YES"
                    if service.tls
                    else "NO"
                ),
                style=(
                    "bold green"
                    if service.tls
                    else "bold yellow"
                ),
            )

            service_table.add_row(
                service.value,
                service.source or "-",
                tls_text,
                active_state_text(
                    service.active
                ),
            )

        console.print(
            Panel(
                service_table,
                title=(
                    "[bold magenta] "
                    "SERVICES "
                    "[/bold magenta]"
                ),
                title_align="left",
                border_style="magenta",
                box=box.ROUNDED,
            )
        )

    # -------------------------------------------------
    # TLS EXPOSURE
    # -------------------------------------------------

    if tls_relations:
        tls_table = Table(
            box=box.ROUNDED,
            header_style="bold magenta",
            expand=True,
        )

        tls_table.add_column(
            "Service",
        )

        tls_table.add_column(
            "Certificate",
        )

        tls_table.add_column(
            "State",
            width=12,
        )

        for relation in tls_relations:
            tls_table.add_row(
                relation.source_value,
                relation.target_value,
                active_state_text(
                    relation.active
                ),
            )

        console.print(
            Panel(
                tls_table,
                title=(
                    "[bold magenta] "
                    "TLS EXPOSURE "
                    "[/bold magenta]"
                ),
                title_align="left",
                border_style="magenta",
                box=box.ROUNDED,
            )
        )

    # -------------------------------------------------
    # FINDINGS
    # -------------------------------------------------

    if findings:
        if terminal_is_compact():
            print_compact_findings(
                findings
            )
        else:
            print_wide_findings(
                findings
            )

    # -------------------------------------------------
    # RECENT EXPOSURE CHANGES
    # -------------------------------------------------

    if recent_changes:
        change_table = Table(
            box=box.ROUNDED,
            header_style="bold yellow",
            expand=True,
        )

        change_table.add_column(
            "State",
            width=18,
        )

        change_table.add_column(
            "Object",
        )

        change_table.add_column(
            "Plugin",
            width=12,
        )

        for change in recent_changes:
            change_table.add_row(
                lifecycle_text(
                    change.change_type
                ),
                change_object_text(
                    change
                ),
                change.plugin,
            )

        console.print(
            Panel(
                change_table,
                title=(
                    "[bold yellow] "
                    "RECENT EXPOSURE CHANGES "
                    "[/bold yellow]"
                ),
                title_align="left",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

def print_findings_table(
    findings,
):
    findings = list(
        findings
    )

    if not findings:
        print_empty(
            "No findings found."
        )
        return

    if terminal_is_compact():
        print_compact_findings(
            findings
        )
        return

    findings_table = Table(
        title="Persisted Findings",
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
        expand=True,
    )

    findings_table.add_column(
        "ID",
        width=12,
        no_wrap=True,
    )

    findings_table.add_column(
        "Severity",
        width=10,
        no_wrap=True,
    )

    findings_table.add_column(
        "State",
        width=18,
        no_wrap=True,
    )

    findings_table.add_column(
        "Rule",
        width=26,
    )

    findings_table.add_column(
        "Asset",
        ratio=2,
    )

    findings_table.add_column(
        "Affected Service",
        ratio=2,
    )

    findings_table.add_column(
        "Plugin",
        width=10,
    )

    severity_styles = {
        "info": "bold cyan",
        "low": "bold green",
        "medium": "bold yellow",
        "high": "bold red",
        "critical": "bold white on red",
    }

    state_styles = {
        "active": "bold green",
        "candidate_missing": "bold yellow",
        "resolved": "bold red",
    }

    for finding in findings:
        severity = (
            _finding_severity_value(
                finding
            )
        )

        state = (
            _finding_state_value(
                finding
            )
            or "unknown"
        )

        findings_table.add_row(
            finding.finding_id[:12],
            Text(
                severity.upper(),
                style=severity_styles.get(
                    severity,
                    "white",
                ),
            ),
            Text(
                state.upper(),
                style=state_styles.get(
                    state,
                    "white",
                ),
            ),
            finding.rule_id,
            (
                f"{finding.asset_type.value.upper()} "
                f"{finding.asset_value}"
            ),
            (
                finding.affected_service
                or "-"
            ),
            (
                finding.plugin
                or "-"
            ),
        )

    console.print()
    console.print(
        findings_table
    )


def print_finding_detail(
    finding,
):
    console.print()

    severity = (
        _finding_severity_value(
            finding
        )
    )

    state = (
        _finding_state_value(
            finding
        )
        or "unknown"
    )

    severity_styles = {
        "info": "bold cyan",
        "low": "bold green",
        "medium": "bold yellow",
        "high": "bold red",
        "critical": "bold white on red",
    }

    state_styles = {
        "active": "bold green",
        "candidate_missing": "bold yellow",
        "resolved": "bold red",
    }

    table = Table(
        box=None,
        show_header=False,
        expand=True,
        padding=(0, 1),
    )

    table.add_column(
        "Field",
        style="bold cyan",
        width=20,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    table.add_row(
        "ID",
        finding.finding_id,
    )

    table.add_row(
        "Short ID",
        finding.finding_id[:12],
    )

    table.add_row(
        "Severity",
        Text(
            severity.upper(),
            style=severity_styles.get(
                severity,
                "white",
            ),
        ),
    )

    table.add_row(
        "State",
        Text(
            state.upper(),
            style=state_styles.get(
                state,
                "white",
            ),
        ),
    )

    table.add_row(
        "Active",
        Text(
            (
                "YES"
                if finding.active
                else "NO"
            ),
            style=(
                "bold green"
                if finding.active
                else "bold red"
            ),
        ),
    )

    table.add_row(
        "Rule",
        finding.rule_id,
    )

    table.add_row(
        "Title",
        finding.title,
    )

    table.add_row(
        "Asset Type",
        finding.asset_type.value.upper(),
    )

    table.add_row(
        "Asset",
        finding.asset_value,
    )

    table.add_row(
        "Affected Service",
        finding.affected_service
        or "-",
    )

    table.add_row(
        "Plugin",
        finding.plugin
        or "-",
    )

    table.add_row(
        "Coverage Plugins",
        ", ".join(
            finding.coverage_plugins
        )
        or "-",
    )

    table.add_row(
        "First Seen",
        (
            finding.first_seen.isoformat()
            if finding.first_seen
            else "-"
        ),
    )

    table.add_row(
        "Last Seen",
        (
            finding.last_seen.isoformat()
            if finding.last_seen
            else "-"
        ),
    )

    table.add_row(
        "Last Confirmed",
        (
            finding.last_confirmed.isoformat()
            if finding.last_confirmed
            else "-"
        ),
    )

    table.add_row(
        "Seen Count",
        str(
            finding.seen_count
        ),
    )

    table.add_row(
        "Missing Count",
        str(
            finding.missing_count
        ),
    )

    table.add_row(
        "Description",
        finding.description,
    )

    console.print(
        Panel(
            table,
            title=(
                "[bold yellow] "
                "FINDING DETAIL "
                "[/bold yellow]"
            ),
            subtitle=(
                f"[dim]"
                f"{finding.finding_id[:12]}"
                f"[/dim]"
            ),
            title_align="left",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )

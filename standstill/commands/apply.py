from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from standstill import state as _state
from standstill.aws import controltower as ct_api
from standstill.commands._engine import (
    _interactive_picker,
    _plan_from_file,
    _run_apply,
)
from standstill.display.renderer import console

err = Console(stderr=True)


def apply(
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="YAML file declaring controls to enable."),
    ] = None,
    enable_all: Annotated[
        bool,
        typer.Option("--enable-all", help="Enable all controls (all behaviors) on --ou."),
    ] = False,
    enable_preventive: Annotated[
        bool,
        typer.Option("--enable-preventive", help="Enable all Preventive controls on --ou."),
    ] = False,
    enable_detective: Annotated[
        bool,
        typer.Option("--enable-detective", help="Enable all Detective controls on --ou."),
    ] = False,
    enable_proactive: Annotated[
        bool,
        typer.Option("--enable-proactive", help="Enable all Proactive controls on --ou."),
    ] = False,
    category: Annotated[
        bool,
        typer.Option(
            "--category",
            help="Interactively select control behaviors and severities to enable.",
        ),
    ] = False,
    ou: Annotated[
        Optional[str],
        typer.Option("--ou", "-u", help="Target OU ID. Required with --enable-* and --category flags."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print the plan without making any changes."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
    wait: Annotated[
        bool,
        typer.Option("--wait/--no-wait", help="Wait for each async CT operation to finish."),
    ] = True,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Seconds to wait per operation."),
    ] = 1200,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-j", help="Number of controls to submit in parallel."),
    ] = 10,
) -> None:
    """
    Enable controls on OUs.

    \b
    Modes:
      standstill apply --file controls.yaml
      standstill apply --enable-all         --ou ou-xxxx-yyyy
      standstill apply --enable-preventive  --ou ou-xxxx-yyyy
      standstill apply --enable-detective   --ou ou-xxxx-yyyy
      standstill apply --enable-proactive   --ou ou-xxxx-yyyy
      standstill apply --category           --ou ou-xxxx-yyyy
    """
    behavior_flags = {
        "PREVENTIVE": enable_preventive,
        "DETECTIVE":  enable_detective,
        "PROACTIVE":  enable_proactive,
    }
    active_behaviors = [b for b, on in behavior_flags.items() if on]
    catalog_mode = enable_all or bool(active_behaviors) or category

    mode_count = sum([bool(file), enable_all, bool(active_behaviors), category])
    if mode_count > 1:
        err.print(
            "[bold red]Error:[/bold red] "
            "--file, --enable-all, --enable-<behavior>, and --category are mutually exclusive."
        )
        raise typer.Exit(1)
    if mode_count == 0:
        err.print(
            "[bold red]Error:[/bold red] "
            "Provide --file, --enable-all, --enable-<behavior>, or --category."
        )
        raise typer.Exit(1)
    if catalog_mode and not ou:
        err.print("[bold red]Error:[/bold red] --enable-* and --category flags require --ou <OU_ID>.")
        raise typer.Exit(1)

    if not 1 <= concurrency <= 50:
        err.print("[bold red]Error:[/bold red] --concurrency must be between 1 and 50.")
        raise typer.Exit(1)

    region = _state.state.region or "us-east-1"

    # ── Build the operation list ─────────────────────────────────────────────
    if file:
        planned = _plan_from_file(file, region)
    elif category:
        planned = _plan_from_category(ou, region)  # type: ignore[arg-type]
    elif enable_all:
        planned = _plan_from_catalog(ou, behavior=None, region=region)  # type: ignore[arg-type]
    else:
        planned = _plan_from_catalog(ou, behavior=active_behaviors[0], region=region)  # type: ignore[arg-type]

    if planned is None:
        raise typer.Exit(1)

    _run_apply(
        planned=planned,
        dry_run=dry_run,
        wait=wait,
        timeout=timeout,
        concurrency=concurrency,
        region=region,
        action=ct_api.enable_control,
        action_label="enable",
        yes=yes,
    )


# ---------------------------------------------------------------------------
# Plan builders (apply-specific)
# ---------------------------------------------------------------------------

def _plan_from_catalog(
    ou_id: str,
    behavior: str | None,
    region: str,
) -> list[tuple[str, str]]:
    """Load the catalog filtered by behavior and return [(ou_id, ctrl_arn)]."""
    label = behavior.upper() if behavior else "ALL"
    with console.status(f"[bold]Loading catalog ({label})...[/bold]"):
        catalog = ct_api.load_catalog(region, behavior=behavior)
    console.print(
        f"[dim]Catalog: {len(catalog)} controls"
        f"{' (' + behavior.lower() + ')' if behavior else ''} loaded[/dim]"
    )
    return [(ou_id, arn) for arn in catalog]


def _plan_from_category(ou_id: str, region: str) -> list[tuple[str, str]] | None:
    """Interactive picker: loads full catalog, prompts for behaviors + severities."""
    with console.status("[bold]Loading catalog...[/bold]"):
        full_catalog = ct_api.load_catalog(region)

    filtered = _interactive_picker(full_catalog)
    if not filtered:
        console.print("[yellow]No controls matched the selection.[/yellow]")
        return None

    console.print(f"\n[dim]Selected: {len(filtered)} control(s)[/dim]")
    return [(ou_id, arn) for arn in filtered]

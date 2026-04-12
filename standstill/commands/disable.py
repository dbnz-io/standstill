from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from standstill import state as _state
from standstill.aws import controltower as ct_api
from standstill.aws import organizations as org_api
from standstill.commands._engine import (
    _interactive_picker,
    _plan_from_file,
    _run_apply,
)
from standstill.display.renderer import console

err = Console(stderr=True)


def disable(
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="YAML file listing controls to disable."),
    ] = None,
    disable_all: Annotated[
        bool,
        typer.Option("--disable-all", help="Disable all currently enabled controls on --ou."),
    ] = False,
    disable_preventive: Annotated[
        bool,
        typer.Option("--disable-preventive", help="Disable all currently enabled Preventive controls on --ou."),
    ] = False,
    disable_detective: Annotated[
        bool,
        typer.Option("--disable-detective", help="Disable all currently enabled Detective controls on --ou."),
    ] = False,
    disable_proactive: Annotated[
        bool,
        typer.Option("--disable-proactive", help="Disable all currently enabled Proactive controls on --ou."),
    ] = False,
    category: Annotated[
        bool,
        typer.Option(
            "--category",
            help="Interactively select which behaviors and severities to disable.",
        ),
    ] = False,
    ou: Annotated[
        Optional[str],
        typer.Option("--ou", "-u", help="Target OU ID. Required with all flags except --file."),
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
    Disable controls on OUs.

    \b
    Modes:
      standstill disable --file controls.yaml
      standstill disable --disable-all         --ou ou-xxxx-yyyy
      standstill disable --disable-preventive  --ou ou-xxxx-yyyy
      standstill disable --disable-detective   --ou ou-xxxx-yyyy
      standstill disable --disable-proactive   --ou ou-xxxx-yyyy
      standstill disable --category            --ou ou-xxxx-yyyy
    """
    behavior_flags = {
        "PREVENTIVE": disable_preventive,
        "DETECTIVE":  disable_detective,
        "PROACTIVE":  disable_proactive,
    }
    active_behaviors = [b for b, on in behavior_flags.items() if on]
    ou_mode = disable_all or bool(active_behaviors) or category

    mode_count = sum([bool(file), disable_all, bool(active_behaviors), category])
    if mode_count > 1:
        err.print(
            "[bold red]Error:[/bold red] "
            "--file, --disable-all, --disable-<behavior>, and --category are mutually exclusive."
        )
        raise typer.Exit(1)
    if mode_count == 0:
        err.print(
            "[bold red]Error:[/bold red] "
            "Provide --file, --disable-all, --disable-<behavior>, or --category."
        )
        raise typer.Exit(1)
    if ou_mode and not ou:
        err.print("[bold red]Error:[/bold red] --disable-all, --disable-<behavior>, and --category require --ou <OU_ID>.")
        raise typer.Exit(1)

    if not 1 <= concurrency <= 50:
        err.print("[bold red]Error:[/bold red] --concurrency must be between 1 and 50.")
        raise typer.Exit(1)

    region = _state.state.region or "us-east-1"

    # ── Build the operation list ─────────────────────────────────────────────
    if file:
        planned = _plan_from_file(file, region)
    else:
        planned = _plan_from_enabled(
            ou_id=ou,  # type: ignore[arg-type]
            behaviors=active_behaviors if active_behaviors else None,
            filter_all=disable_all,
            use_category=category,
            region=region,
        )

    if planned is None:
        raise typer.Exit(1)

    _run_apply(
        planned=planned,
        dry_run=dry_run,
        wait=wait,
        timeout=timeout,
        concurrency=concurrency,
        region=region,
        action=ct_api.disable_control,
        action_label="disable",
        yes=yes,
    )


# ---------------------------------------------------------------------------
# Plan builder: filter currently enabled controls
# ---------------------------------------------------------------------------

def _plan_from_enabled(
    ou_id: str,
    behaviors: list[str] | None,
    filter_all: bool,
    use_category: bool,
    region: str,
) -> list[tuple[str, str]] | None:
    """
    Resolve the OU ARN, fetch currently enabled controls, filter by behavior/category,
    and return [(ou_id, ctrl_arn)] pairs ready for _run_apply.
    """
    # Resolve ou_id → ou_arn
    with console.status("[bold]Fetching OU structure...[/bold]"):
        nodes = org_api.build_ou_tree()
        flat = org_api.flatten_ous(nodes)
        ou_map = {n.id: n for n in flat}
        ou_arn_map = {n.arn: n for n in flat}

    node = ou_map.get(ou_id) or ou_arn_map.get(ou_id)
    if node is None:
        err.print(f"[bold red]OU not found:[/bold red] {ou_id}")
        return None

    with console.status(f"[bold]Fetching enabled controls for {node.name}...[/bold]"):
        enabled = ct_api.list_enabled_for_ou(node.arn)

    if not enabled:
        console.print(f"[yellow]No controls are currently enabled on {node.name}.[/yellow]")
        return []

    console.print(f"[dim]{len(enabled)} control(s) currently enabled on {node.name}[/dim]")

    if filter_all and not use_category:
        # Disable everything that is enabled
        return [(ou_id, ec.control_arn) for ec in enabled]

    # For behavior-filtered or --category mode we need the catalog for metadata
    with console.status("[bold]Loading catalog...[/bold]"):
        catalog = ct_api.load_catalog(region)

    # Build a dict of only the currently-enabled controls that are in our catalog
    enabled_arns = {ec.control_arn for ec in enabled}
    enabled_catalog: dict[str, ct_api.Control] = {
        arn: ctrl
        for arn, ctrl in catalog.items()
        if arn in enabled_arns
    }

    # Controls enabled on the OU but not in our catalog (e.g. user-added)
    unknown_arns = enabled_arns - set(enabled_catalog)
    if unknown_arns and not use_category:
        console.print(
            f"[dim]{len(unknown_arns)} enabled control(s) not in catalog "
            "(skipped — use --disable-all to include them)[/dim]"
        )

    if use_category:
        if not enabled_catalog:
            console.print("[yellow]None of the enabled controls appear in the catalog.[/yellow]")
            return []
        filtered = _interactive_picker(enabled_catalog)
        if not filtered:
            return []
        return [(ou_id, arn) for arn in filtered]

    # Behavior-filtered mode
    filtered_catalog = {
        arn: ctrl
        for arn, ctrl in enabled_catalog.items()
        if ctrl.behavior in (behaviors or [])
    }
    return [(ou_id, arn) for arn in filtered_catalog]

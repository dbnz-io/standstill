from __future__ import annotations

from typing import Annotated, List, Optional

import typer
from rich.console import Console

from standstill import state as _state
from standstill.aws import config_recorder as rec_api
from standstill.aws import organizations as org_api
from standstill.display import renderer

app = typer.Typer(no_args_is_help=True, help="Manage AWS Config recorders across accounts.")
types_app = typer.Typer(no_args_is_help=True, help="Manage the recorded resource types list.")
app.add_typer(types_app, name="types")
err = Console(stderr=True)

_DEFAULT_CT_ROLE = "AWSControlTowerExecution"


def _resolve_accounts(
    all_accounts: bool,
    account_ids: list[str],
    nodes,
) -> list:
    """Return the list of Account objects to target, or raise if none specified."""
    accounts = org_api.all_accounts(nodes)
    if all_accounts:
        return [a for a in accounts if a.status == "ACTIVE"]
    if account_ids:
        id_set = set(account_ids)
        matched = [a for a in accounts if a.id in id_set]
        missing = id_set - {a.id for a in matched}
        if missing:
            err.print(f"[bold red]Account(s) not found in org:[/bold red] {', '.join(missing)}")
            raise typer.Exit(1)
        return matched
    err.print(
        "[bold red]Error:[/bold red] Provide [cyan]--all[/cyan] or at least one "
        "[cyan]--account <id>[/cyan]."
    )
    raise typer.Exit(1)


@app.command("status")
def status(
    all_accounts: Annotated[
        bool,
        typer.Option("--all", help="Check all active accounts in the organization."),
    ] = False,
    account_ids: Annotated[
        Optional[List[str]],
        typer.Option("--account", "-a", help="Account ID to check (repeatable)."),
    ] = None,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role name to assume in each account."),
    ] = _DEFAULT_CT_ROLE,
) -> None:
    """Show the current AWS Config recorder state for one or more accounts."""
    region = _state.state.region or "us-east-1"

    with renderer.console.status("[bold]Fetching account list...[/bold]"):
        nodes = org_api.build_ou_tree()

    targets = _resolve_accounts(all_accounts, list(account_ids or []), nodes)

    renderer.console.print(
        f"[dim]Fetching recorder status for [bold]{len(targets)}[/bold] account(s)...[/dim]\n"
    )

    with renderer.console.status("[bold]Querying Config recorders...[/bold]"):
        states = rec_api.get_all_recorder_states(targets, role_name, region)

    renderer.render_recorder_status(states)


@app.command("setup")
def setup(
    all_accounts: Annotated[
        bool,
        typer.Option("--all", help="Configure all active accounts in the organization."),
    ] = False,
    account_ids: Annotated[
        Optional[List[str]],
        typer.Option("--account", "-a", help="Account ID to configure (repeatable)."),
    ] = None,
    recording: Annotated[
        str,
        typer.Option(
            "--recording",
            help="Recording frequency: continuous | daily  [default: daily]",
            metavar="FREQ",
        ),
    ] = "daily",
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role name to assume in each account."),
    ] = _DEFAULT_CT_ROLE,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would change without applying anything."),
    ] = False,
) -> None:
    """
    Configure AWS Config recorders for cost-aware Security Hub coverage.

    \b
    Sets up Config in each account to:
      • Record only the resource types required by Security Hub (FSBP + CIS)
      • Exclude types that create evaluation loops or high-volume noise
      • Use the chosen recording frequency (daily is ~60–75% cheaper)

    The recorder role ARN already present in each account is preserved.
    Accounts with no recorder (not enrolled in Control Tower) are skipped.

    \b
    Examples:
      standstill recorder setup --all --recording daily
      standstill recorder setup --account 123456789012 --recording continuous
      standstill recorder setup --all --dry-run
    """
    frequency = recording.upper()
    if frequency not in rec_api.RECORDING_FREQUENCIES:
        err.print(
            f"[bold red]Error:[/bold red] Invalid recording frequency '[cyan]{recording}[/cyan]'. "
            f"Choose: continuous | daily"
        )
        raise typer.Exit(1)

    region = _state.state.region or "us-east-1"
    resource_types = rec_api.load_resource_types()

    with renderer.console.status("[bold]Fetching account list...[/bold]"):
        nodes = org_api.build_ou_tree()

    targets = _resolve_accounts(all_accounts, list(account_ids or []), nodes)

    renderer.console.print(
        f"[dim]Target: [bold]{len(targets)}[/bold] account(s)  "
        f"│  Resource types: [bold]{len(resource_types)}[/bold]  "
        f"│  Frequency: [bold]{frequency.lower()}[/bold][/dim]\n"
    )

    if dry_run:
        with renderer.console.status("[bold]Fetching current recorder states...[/bold]"):
            states = rec_api.get_all_recorder_states(targets, role_name, region)
        renderer.render_recorder_plan(states, resource_types, frequency)
        renderer.console.print("\n[bold yellow]Dry run — no changes applied.[/bold yellow]")
        return

    with renderer.console.status("[bold]Configuring recorders...[/bold]"):
        results = rec_api.configure_all_recorders(
            targets, role_name, region, frequency, resource_types
        )

    renderer.render_recorder_results(results)

    failed = [r for r in results if not r.success and not r.noop]
    if failed:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# recorder types — manage the resource type list
# ---------------------------------------------------------------------------

@types_app.command("list")
def types_list(
    show_removed: Annotated[
        bool,
        typer.Option("--show-removed", help="Also show types removed from the bundled defaults."),
    ] = False,
) -> None:
    """
    Show the active resource types list.

    When a user override is active, additions (types not in the bundled defaults)
    are highlighted. Use --show-removed to also see which bundled types have been
    removed in the override.
    """
    active = rec_api.load_resource_types()
    bundled = rec_api.load_bundled_resource_types()
    renderer.render_resource_types_list(
        active=active,
        bundled=bundled,
        is_user_override=rec_api.is_user_override_active(),
        show_removed=show_removed,
    )


@types_app.command("add")
def types_add(
    resource_type: Annotated[
        str,
        typer.Argument(help="AWS Config resource type to add (e.g. AWS::ECR::Repository)."),
    ],
) -> None:
    """
    Add a resource type to the active list.

    If no user override exists yet, one is created from the bundled defaults
    with the new type appended.
    """
    added, message = rec_api.add_resource_type(resource_type)
    if added:
        renderer.console.print(f"[green]✓[/green] {message}")
        if not rec_api.is_user_override_active():  # was just created
            renderer.console.print(
                f"[dim]User override created: {rec_api._USER_TYPES_PATH}[/dim]"
            )
    else:
        err.print(f"[bold red]Error:[/bold red] {message}")
        raise typer.Exit(1)


@types_app.command("remove")
def types_remove(
    resource_type: Annotated[
        str,
        typer.Argument(help="AWS Config resource type to remove (e.g. AWS::SSM::ManagedInstanceInventory)."),
    ],
) -> None:
    """
    Remove a resource type from the active list.

    If no user override exists yet, one is created from the bundled defaults
    with the type removed.
    """
    removed, message = rec_api.remove_resource_type(resource_type)
    if removed:
        renderer.console.print(f"[green]✓[/green] {message}")
    else:
        err.print(f"[bold red]Error:[/bold red] {message}")
        raise typer.Exit(1)


@types_app.command("reset")
def types_reset(
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """
    Remove the user override and revert to the bundled defaults.
    """
    if not rec_api.is_user_override_active():
        renderer.console.print("[dim]Already using bundled defaults — nothing to reset.[/dim]")
        return
    if not yes:
        typer.confirm(
            f"Delete {rec_api._USER_TYPES_PATH} and revert to bundled defaults?",
            abort=True,
        )
    rec_api.reset_resource_types()
    renderer.console.print("[green]✓[/green] Reverted to bundled defaults.")

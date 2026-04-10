from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console

from standstill.aws import controltower as ct_api
from standstill.aws import organizations as org_api
from standstill.display import renderer

app = typer.Typer(no_args_is_help=True, help="Visualize OUs, accounts, and controls.")
err = Console(stderr=True)


@app.command("ous")
def view_ous() -> None:
    """Display the full OU hierarchy as a tree."""
    with renderer.console.status("[bold]Fetching OU structure...[/bold]"):
        nodes = org_api.build_ou_tree()
    renderer.render_ou_tree(nodes)


@app.command("accounts")
def view_accounts() -> None:
    """List all accounts with OU membership and status."""
    with renderer.console.status("[bold]Fetching accounts...[/bold]"):
        nodes = org_api.build_ou_tree()
        accounts = org_api.all_accounts(nodes)
    renderer.render_accounts_table(accounts)


@app.command("controls")
def view_controls(
    ou: Annotated[
        Optional[str],
        typer.Option("--ou", "-u", help="Limit output to a specific OU ID (e.g. ou-ab12-34cd5678)"),
    ] = None,
) -> None:
    """
    Show enabled controls per OU with status breakdown (Succeeded / Failed / In Progress).
    """
    with renderer.console.status("[bold]Fetching OU structure...[/bold]"):
        nodes = org_api.build_ou_tree()

    # Optional OU filter
    if ou:
        flat = org_api.flatten_ous(nodes)
        matched = [n for n in flat if n.id == ou]
        if not matched:
            err.print(f"[bold red]OU not found:[/bold red] {ou}")
            raise typer.Exit(1)
        nodes = matched

    with renderer.console.status("[bold]Fetching enabled controls for all OUs...[/bold]"):
        enabled_by_ou = ct_api.list_enabled_for_all_ous(nodes)

    renderer.render_controls_summary(nodes, enabled_by_ou)

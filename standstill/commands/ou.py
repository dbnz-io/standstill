from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from standstill.aws import account_factory as af_api
from standstill.display.renderer import console

app = typer.Typer(no_args_is_help=True, help="Organizational unit management.")
err = Console(stderr=True)

_STATUS_COLOR = {"ACTIVE": "green", "SUSPENDED": "red", "PENDING_CLOSURE": "yellow"}


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

@app.command("create")
def create_ou(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="Name for the new OU."),
    ],
    parent: Annotated[
        Optional[str],
        typer.Option(
            "--parent",
            "-p",
            help="Parent OU ID (ou-xxxx-xxxxxxxx) or root ID (r-xxxx). "
                 "Defaults to the organization root.",
        ),
    ] = None,
) -> None:
    """
    Create a new Organizational Unit.

    If --parent is not specified the OU is created directly under the
    organization root. Pass an existing OU ID to nest the new OU inside it.

    \b
    Examples:
      standstill ou create --name "Workloads"
      standstill ou create --name "Production" --parent ou-ab12-34cd5678
      standstill ou create --name "Dev" --parent r-ab12
    """
    try:
        parent_id = parent
        if not parent_id:
            with console.status("[bold]Resolving organization root...[/bold]"):
                parent_id = af_api.get_org_root_id()

        with console.status(f"[bold]Creating OU '{name}'...[/bold]"):
            ou = af_api.create_ou(parent_id=parent_id, name=name)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    console.print(
        f"[bold green]✓ OU created.[/bold green]\n"
        f"  Name:   {ou['Name']}\n"
        f"  ID:     [cyan]{ou['Id']}[/cyan]\n"
        f"  ARN:    [dim]{ou['Arn']}[/dim]\n"
        f"  Parent: [dim]{parent_id}[/dim]"
    )


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

@app.command("delete")
def delete_ou(
    ou: Annotated[
        str,
        typer.Option("--ou", "-u", help="OU ID to delete (ou-xxxx-xxxxxxxx)."),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """
    Delete an Organizational Unit.

    The OU must be empty — it cannot contain any accounts or child OUs.
    This operation is not reversible.

    \b
    Examples:
      standstill ou delete --ou ou-ab12-34cd5678
      standstill ou delete --ou ou-ab12-34cd5678 --yes
    """
    console.print(
        f"[bold]Deleting OU[/bold] [cyan]{ou}[/cyan]\n"
        "[yellow]Warning:[/yellow] This cannot be undone. The OU must be empty.\n"
    )

    if not yes:
        typer.confirm(f"Delete OU {ou}?", abort=True)

    try:
        af_api.delete_ou(ou_id=ou)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    console.print(f"[bold green]✓ OU {ou} deleted.[/bold green]")


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------

@app.command("rename")
def rename_ou(
    ou: Annotated[
        str,
        typer.Option("--ou", "-u", help="OU ID to rename (ou-xxxx-xxxxxxxx)."),
    ],
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="New name for the OU."),
    ],
) -> None:
    """
    Rename an Organizational Unit.

    \b
    Examples:
      standstill ou rename --ou ou-ab12-34cd5678 --name "Production-v2"
    """
    try:
        with console.status(f"[bold]Renaming OU {ou}...[/bold]"):
            updated = af_api.rename_ou(ou_id=ou, new_name=name)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    console.print(
        f"[bold green]✓ OU renamed.[/bold green]\n"
        f"  ID:   [cyan]{updated['Id']}[/cyan]\n"
        f"  Name: {updated['Name']}"
    )


# ---------------------------------------------------------------------------
# describe
# ---------------------------------------------------------------------------

@app.command("describe")
def describe_ou(
    ou: Annotated[
        str,
        typer.Option("--ou", "-u", help="OU ID to describe (ou-xxxx-xxxxxxxx)."),
    ],
) -> None:
    """
    Show details for an Organizational Unit.

    Displays the OU's metadata, direct child OUs, and directly-attached accounts.

    \b
    Examples:
      standstill ou describe --ou ou-ab12-34cd5678
    """
    try:
        with console.status("[bold]Fetching OU details...[/bold]"):
            info = af_api.describe_ou(ou_id=ou)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    _print_ou_detail(info)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _print_ou_detail(info: dict) -> None:
    # Summary panel
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Value")
    t.add_row("OU ID", info.get("Id", "—"))
    t.add_row("Name", info.get("Name", "—"))
    t.add_row("ARN", f"[dim]{info.get('Arn', '—')}[/dim]")
    t.add_row("Parent", info.get("ParentId", "—"))
    t.add_row("Child OUs", str(len(info.get("ChildOUs", []))))
    t.add_row("Direct accounts", str(len(info.get("Accounts", []))))
    console.print(Panel(t, title="[bold]Organizational Unit[/bold]", expand=False))

    # Child OUs table
    child_ous = info.get("ChildOUs", [])
    if child_ous:
        ct = Table(title="Child OUs", box=box.SIMPLE, padding=(0, 2))
        ct.add_column("OU ID", style="cyan")
        ct.add_column("Name")
        ct.add_column("ARN", style="dim")
        for child in child_ous:
            ct.add_row(child.get("Id", "—"), child.get("Name", "—"), child.get("Arn", "—"))
        console.print(ct)
    else:
        console.print("[dim]No child OUs.[/dim]")

    # Accounts table
    accounts = info.get("Accounts", [])
    if accounts:
        at = Table(title="Direct Accounts", box=box.SIMPLE, padding=(0, 2))
        at.add_column("Account ID", style="cyan")
        at.add_column("Name")
        at.add_column("Email", style="dim")
        at.add_column("Status")
        for acct in accounts:
            status = acct.get("Status", "UNKNOWN")
            sc = _STATUS_COLOR.get(status, "dim")
            at.add_row(
                acct.get("Id", "—"),
                acct.get("Name", "—"),
                acct.get("Email", "—"),
                f"[{sc}]{status}[/{sc}]",
            )
        console.print(at)
    else:
        console.print("[dim]No accounts directly attached to this OU.[/dim]")

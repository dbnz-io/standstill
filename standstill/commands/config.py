from __future__ import annotations

import re

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import standstill.config as _config
from standstill.display.renderer import console

app = typer.Typer(no_args_is_help=True, help="Manage standstill configuration.")
err = Console(stderr=True)

_ACCT_RE = re.compile(r"^\d{12}$")


@app.command("set-profile")
def set_profile(
    profile: str = typer.Argument(..., help="AWS profile name to use as the default."),
) -> None:
    """
    Set the default AWS profile for standstill.

    The profile name is persisted to ~/.ct-cli/config.yaml and used for all
    subsequent commands without needing to pass --profile each time.
    The --profile flag still overrides this value when provided.
    """
    _config.set_profile(profile)
    console.print(f"[green]✓[/green] Default profile saved: [cyan]{profile}[/cyan]")


@app.command("unset-profile")
def unset_profile() -> None:
    """Remove the configured default AWS profile."""
    _config.unset_profile()
    console.print("[green]✓[/green] Default profile cleared.")


@app.command("set-delegated-admin")
def set_delegated_admin(
    account_id: str = typer.Argument(..., help="12-digit AWS account ID of the delegated security admin account."),
) -> None:
    """
    Set the delegated security administrator account.

    Persisted to ~/.ct-cli/config.yaml and used automatically by
    'security status' and 'security assess' when no --account or --file is given.
    """
    if not _ACCT_RE.match(account_id):
        err.print(
            f"[bold red]Error:[/bold red] Invalid account ID: [cyan]{account_id}[/cyan]\n"
            "[dim]Expected 12 digits, e.g. 123456789012[/dim]"
        )
        raise typer.Exit(1)
    _config.set_delegated_admin(account_id)
    console.print(f"[green]✓[/green] Delegated admin account saved: [cyan]{account_id}[/cyan]")


@app.command("unset-delegated-admin")
def unset_delegated_admin() -> None:
    """Remove the configured delegated security administrator account."""
    _config.unset_delegated_admin()
    console.print("[green]✓[/green] Delegated admin account cleared.")


@app.command("show")
def show() -> None:
    """Show the current standstill configuration (~/.ct-cli/config.yaml)."""
    data = _config.load()
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    t.add_column("Key", style="bold cyan")
    t.add_column("Value")
    profile = data.get("profile") or "[dim](not set)[/dim]"
    admin = data.get("delegated_admin_account") or "[dim](not set)[/dim]"
    t.add_row("Default Profile", profile)
    t.add_row("Delegated Admin", admin)
    console.print(Panel(t, title="[bold]Standstill Config[/bold]", expand=False))

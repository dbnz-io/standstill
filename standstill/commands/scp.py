from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from standstill.aws import scp as scp_api
from standstill.display import renderer
from standstill.display._scp import render_scp_audit, render_scp_detail, render_scp_list

app = typer.Typer(no_args_is_help=True, help="Service Control Policy management.")
err = Console(stderr=True)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@app.command("list")
def scp_list() -> None:
    """List all SCPs in the organization."""
    with renderer.console.status("[bold]Fetching SCPs...[/bold]"):
        policies = scp_api.list_scps()

    render_scp_list(policies)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

@app.command("show")
def scp_show(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="SCP name or ID (p-xxxxxxxx)."),
    ],
) -> None:
    """Show SCP details including policy content and targets."""
    with renderer.console.status(f"[bold]Looking up SCP '{name}'...[/bold]"):
        policy = scp_api.find_scp(name)

    if not policy:
        err.print(f"[bold red]Error:[/bold red] SCP '{name}' not found.")
        raise typer.Exit(1)

    with renderer.console.status("[bold]Fetching SCP details...[/bold]"):
        try:
            policy, content = scp_api.describe_scp(policy.id)
            targets = scp_api.list_targets(policy.id)
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    render_scp_detail(policy, content, targets)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@app.command("audit")
def scp_audit() -> None:
    """Show SCP coverage across the organization tree."""
    from concurrent.futures import ThreadPoolExecutor
    from standstill.aws.organizations import build_ou_tree

    with renderer.console.status("[bold]Building org tree and SCP map...[/bold]"):
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                tree_future = pool.submit(build_ou_tree)
                map_future = pool.submit(scp_api.build_target_scp_map)
            nodes = tree_future.result()
            target_scp_map = map_future.result()
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    render_scp_audit(nodes, target_scp_map)


# ---------------------------------------------------------------------------
# attach
# ---------------------------------------------------------------------------

@app.command("attach")
def scp_attach(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="SCP name or ID."),
    ],
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Target ID (account ID, OU ID, or root ID)."),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """Attach an SCP to a target (account, OU, or root)."""
    with renderer.console.status(f"[bold]Looking up SCP '{name}'...[/bold]"):
        policy = scp_api.find_scp(name)

    if not policy:
        err.print(f"[bold red]Error:[/bold red] SCP '{name}' not found.")
        raise typer.Exit(1)

    renderer.console.print(
        f"[bold]Attaching SCP[/bold] [cyan]{policy.name}[/cyan] ({policy.id}) "
        f"to target [cyan]{target}[/cyan]"
    )

    if not yes:
        typer.confirm("Proceed?", abort=True)

    try:
        with renderer.console.status("[bold]Attaching SCP...[/bold]"):
            scp_api.attach_scp(policy.id, target)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(
        f"[bold green]✓[/bold green] SCP [cyan]{policy.name}[/cyan] attached to [cyan]{target}[/cyan]"
    )


# ---------------------------------------------------------------------------
# detach
# ---------------------------------------------------------------------------

@app.command("detach")
def scp_detach(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="SCP name or ID."),
    ],
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Target ID (account ID, OU ID, or root ID)."),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """Detach an SCP from a target."""
    with renderer.console.status(f"[bold]Looking up SCP '{name}'...[/bold]"):
        policy = scp_api.find_scp(name)

    if not policy:
        err.print(f"[bold red]Error:[/bold red] SCP '{name}' not found.")
        raise typer.Exit(1)

    renderer.console.print(
        f"[bold]Detaching SCP[/bold] [cyan]{policy.name}[/cyan] ({policy.id}) "
        f"from target [cyan]{target}[/cyan]"
    )

    if not yes:
        typer.confirm("Proceed?", abort=True)

    try:
        with renderer.console.status("[bold]Detaching SCP...[/bold]"):
            scp_api.detach_scp(policy.id, target)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(
        f"[bold green]✓[/bold green] SCP [cyan]{policy.name}[/cyan] detached from [cyan]{target}[/cyan]"
    )


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

@app.command("create")
def scp_create(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="Name for the new SCP."),
    ],
    description: Annotated[
        str,
        typer.Option("--description", "-d", help="Description for the new SCP."),
    ],
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Path to JSON file containing the policy document."),
    ],
) -> None:
    """Create a new SCP from a JSON policy file."""
    try:
        content = file.read_text()
    except (OSError, IOError) as e:
        err.print(f"[bold red]Error:[/bold red] Cannot read file '{file}': {e}")
        raise typer.Exit(1)

    try:
        with renderer.console.status(f"[bold]Creating SCP '{name}'...[/bold]"):
            policy = scp_api.create_scp(name=name, description=description, content=content)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(
        f"[bold green]✓ SCP created.[/bold green]\n"
        f"  Name:        {policy.name}\n"
        f"  ID:          [cyan]{policy.id}[/cyan]\n"
        f"  ARN:         [dim]{policy.arn}[/dim]\n"
        f"  Description: {policy.description}"
    )


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

@app.command("delete")
def scp_delete(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="SCP name or ID."),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """Delete an SCP."""
    with renderer.console.status(f"[bold]Looking up SCP '{name}'...[/bold]"):
        policy = scp_api.find_scp(name)

    if not policy:
        err.print(f"[bold red]Error:[/bold red] SCP '{name}' not found.")
        raise typer.Exit(1)

    renderer.console.print(
        f"[bold]Deleting SCP[/bold] [cyan]{policy.name}[/cyan] ({policy.id})\n"
        "[yellow]Warning:[/yellow] This operation cannot be undone."
    )

    if not yes:
        typer.confirm(f"Delete SCP '{policy.name}'?", abort=True)

    try:
        with renderer.console.status("[bold]Deleting SCP...[/bold]"):
            scp_api.delete_scp(policy.id)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(f"[bold green]✓[/bold green] SCP [cyan]{policy.name}[/cyan] deleted.")

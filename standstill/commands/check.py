from __future__ import annotations

import typer
from rich.console import Console

from standstill import state as _state
from standstill.aws import session as aws_session
from standstill.display.renderer import console, render_identity, render_permissions

err = Console(stderr=True)


def check() -> None:
    """Verify AWS connectivity and Control Tower permissions."""
    # Connectivity
    try:
        with console.status("[bold]Checking AWS connectivity...[/bold]"):
            identity = aws_session.get_caller_identity()
    except RuntimeError as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    render_identity(identity, _state.state.profile, _state.state.region)

    # Permissions
    with console.status("[bold]Probing Control Tower permissions...[/bold]"):
        results = aws_session.check_ct_permissions()

    render_permissions(results)

    # Non-zero exit if any critical permission is denied
    critical = [
        "organizations:DescribeOrganization",
        "organizations:ListRoots",
        "controltower:ListLandingZones",
    ]
    denied = [k for k in critical if results.get(k) is not True]
    if denied:
        err.print(
            f"\n[bold red]Missing critical permissions:[/bold red] {', '.join(denied)}"
        )
        raise typer.Exit(1)

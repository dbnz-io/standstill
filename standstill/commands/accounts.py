from __future__ import annotations

import typer
from rich.console import Console

from standstill.aws import organizations as org_api
from standstill.aws import session as aws_session
from standstill.display import renderer

app = typer.Typer(no_args_is_help=True, help="Account-level operations across the organization.")
err = Console(stderr=True)

_DEFAULT_CT_ROLE = "AWSControlTowerExecution"


@app.command("check-roles")
def check_roles(
    role_name: str = typer.Option(
        _DEFAULT_CT_ROLE,
        "--role-name",
        "-n",
        help="Name of the IAM role to probe in each member account.",
    ),
) -> None:
    """
    Verify that the Control Tower execution role can be assumed in every account.

    Walks the full organization, attempts sts:AssumeRole for the given role name
    in each member account, and reports which accounts are reachable.

    The role defaults to AWSControlTowerExecution — the role Control Tower deploys
    into managed accounts to perform administrative operations.
    """
    with renderer.console.status("[bold]Fetching account list...[/bold]"):
        nodes = org_api.build_ou_tree()
        accounts = org_api.all_accounts(nodes)

    if not accounts:
        renderer.console.print("[dim]No accounts found in the organization.[/dim]")
        return

    renderer.console.print(
        f"[dim]Probing [bold]{len(accounts)}[/bold] account(s) "
        f"for role [cyan]{role_name}[/cyan]...[/dim]\n"
    )

    with renderer.console.status("[bold]Checking roles...[/bold]"):
        results = aws_session.check_all_account_roles(accounts, role_name)

    renderer.render_account_roles_table(accounts, results, role_name)

    unreachable = sum(1 for ok, _ in results.values() if not ok)
    if unreachable:
        raise typer.Exit(1)

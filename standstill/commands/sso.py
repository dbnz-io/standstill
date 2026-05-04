from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console

from standstill.aws import sso as sso_api
from standstill.display import renderer
from standstill.display._sso import (
    render_assignments,
    render_permission_sets,
    render_sso_audit,
    render_sso_status,
)

app = typer.Typer(no_args_is_help=True, help="IAM Identity Center (SSO) management.")
err = Console(stderr=True)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command("status")
def sso_status() -> None:
    """Show SSO instance status and summary."""
    with renderer.console.status("[bold]Fetching SSO status...[/bold]"):
        try:
            instance = sso_api.get_instance()
            if not instance:
                renderer.console.print("[bold yellow]No SSO instance found.[/bold yellow]")
                return

            ps_list = sso_api.list_permission_sets(instance.instance_arn)

            # Build account name map for assignments
            from standstill.aws.organizations import all_accounts, build_ou_tree
            tree = build_ou_tree()
            accts = all_accounts(tree)
            account_name_map = {a.id: a.name for a in accts}

            assignments = sso_api.list_all_assignments(
                instance.instance_arn,
                instance.identity_store_id,
                ps_list,
                account_name_map,
            )
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    render_sso_status(instance, len(ps_list), len(assignments))


# ---------------------------------------------------------------------------
# list-permission-sets
# ---------------------------------------------------------------------------

@app.command("list-permission-sets")
def list_permission_sets() -> None:
    """List all permission sets."""
    with renderer.console.status("[bold]Fetching SSO instance...[/bold]"):
        instance = sso_api.get_instance()

    if not instance:
        err.print("[bold red]Error:[/bold red] No SSO instance found.")
        raise typer.Exit(1)

    with renderer.console.status("[bold]Fetching permission sets...[/bold]"):
        try:
            ps_list = sso_api.list_permission_sets(instance.instance_arn)
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    render_permission_sets(ps_list)


# ---------------------------------------------------------------------------
# list-assignments
# ---------------------------------------------------------------------------

@app.command("list-assignments")
def list_assignments(
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Filter by account ID."),
    ] = None,
) -> None:
    """List account assignments, optionally filtered by account."""
    with renderer.console.status("[bold]Fetching SSO data...[/bold]"):
        try:
            instance = sso_api.get_instance()
            if not instance:
                err.print("[bold red]Error:[/bold red] No SSO instance found.")
                raise typer.Exit(1)

            ps_list = sso_api.list_permission_sets(instance.instance_arn)

            from standstill.aws.organizations import all_accounts, build_ou_tree
            tree = build_ou_tree()
            accts = all_accounts(tree)
            account_name_map = {a.id: a.name for a in accts}

            assignments = sso_api.list_all_assignments(
                instance.instance_arn,
                instance.identity_store_id,
                ps_list,
                account_name_map,
            )
        except typer.Exit:
            raise
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    if account:
        assignments = [a for a in assignments if a.account_id == account]

    render_assignments(assignments)


# ---------------------------------------------------------------------------
# assign
# ---------------------------------------------------------------------------

@app.command("assign")
def sso_assign(
    account: Annotated[
        str,
        typer.Option("--account", "-a", help="Account ID to assign."),
    ],
    permission_set: Annotated[
        str,
        typer.Option("--permission-set", "-p", help="Permission set name."),
    ],
    principal: Annotated[
        str,
        typer.Option("--principal", "-u", help="Principal display name (user or group)."),
    ],
    principal_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Principal type: USER or GROUP."),
    ] = "USER",
) -> None:
    """Assign a permission set to a user or group for an account."""
    with renderer.console.status("[bold]Resolving SSO resources...[/bold]"):
        try:
            instance = sso_api.get_instance()
            if not instance:
                err.print("[bold red]Error:[/bold red] No SSO instance found.")
                raise typer.Exit(1)

            ps = sso_api.find_permission_set_by_name(instance.instance_arn, permission_set)
            if not ps:
                err.print(f"[bold red]Error:[/bold red] Permission set '{permission_set}' not found.")
                raise typer.Exit(1)

            principal_id = sso_api.resolve_principal_id(
                instance.identity_store_id,
                principal,
                principal_type,
            )
            if not principal_id:
                err.print(f"[bold red]Error:[/bold red] Principal '{principal}' ({principal_type}) not found.")
                raise typer.Exit(1)
        except typer.Exit:
            raise
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    renderer.console.print(
        f"[bold]Assigning[/bold] [cyan]{permission_set}[/cyan] "
        f"to {principal_type.lower()} [cyan]{principal}[/cyan] "
        f"in account [cyan]{account}[/cyan]"
    )

    with renderer.console.status("[bold]Creating assignment...[/bold]"):
        try:
            result = sso_api.create_assignment(
                instance_arn=instance.instance_arn,
                account_id=account,
                ps_arn=ps.arn,
                principal_type=principal_type.upper(),
                principal_id=principal_id,
            )
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    request_id = result.get("RequestId", "")
    if request_id:
        renderer.console.print("[dim]Polling for completion...[/dim]")
        with renderer.console.status("[bold]Waiting for assignment...[/bold]"):
            final_status = sso_api.poll_assignment_status(
                instance.instance_arn, request_id, operation="creation"
            )
        if final_status == "SUCCEEDED":
            renderer.console.print("[bold green]✓ Assignment created successfully.[/bold green]")
        elif final_status == "FAILED":
            err.print("[bold red]Error:[/bold red] Assignment creation failed.")
            raise typer.Exit(1)
        else:
            renderer.console.print("[bold yellow]Assignment is still in progress.[/bold yellow]")
    else:
        renderer.console.print("[bold green]✓ Assignment created.[/bold green]")


# ---------------------------------------------------------------------------
# unassign
# ---------------------------------------------------------------------------

@app.command("unassign")
def sso_unassign(
    account: Annotated[
        str,
        typer.Option("--account", "-a", help="Account ID."),
    ],
    permission_set: Annotated[
        str,
        typer.Option("--permission-set", "-p", help="Permission set name."),
    ],
    principal: Annotated[
        str,
        typer.Option("--principal", "-u", help="Principal display name (user or group)."),
    ],
    principal_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Principal type: USER or GROUP."),
    ] = "USER",
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """Remove an account assignment."""
    with renderer.console.status("[bold]Resolving SSO resources...[/bold]"):
        try:
            instance = sso_api.get_instance()
            if not instance:
                err.print("[bold red]Error:[/bold red] No SSO instance found.")
                raise typer.Exit(1)

            ps = sso_api.find_permission_set_by_name(instance.instance_arn, permission_set)
            if not ps:
                err.print(f"[bold red]Error:[/bold red] Permission set '{permission_set}' not found.")
                raise typer.Exit(1)

            principal_id = sso_api.resolve_principal_id(
                instance.identity_store_id,
                principal,
                principal_type,
            )
            if not principal_id:
                err.print(f"[bold red]Error:[/bold red] Principal '{principal}' ({principal_type}) not found.")
                raise typer.Exit(1)
        except typer.Exit:
            raise
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    renderer.console.print(
        f"[bold]Removing[/bold] [cyan]{permission_set}[/cyan] "
        f"from {principal_type.lower()} [cyan]{principal}[/cyan] "
        f"in account [cyan]{account}[/cyan]"
    )

    if not yes:
        typer.confirm("Proceed?", abort=True)

    with renderer.console.status("[bold]Deleting assignment...[/bold]"):
        try:
            result = sso_api.delete_assignment(
                instance_arn=instance.instance_arn,
                account_id=account,
                ps_arn=ps.arn,
                principal_type=principal_type.upper(),
                principal_id=principal_id,
            )
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    request_id = result.get("RequestId", "")
    if request_id:
        renderer.console.print("[dim]Polling for completion...[/dim]")
        with renderer.console.status("[bold]Waiting for deletion...[/bold]"):
            final_status = sso_api.poll_assignment_status(
                instance.instance_arn, request_id, operation="deletion"
            )
        if final_status == "SUCCEEDED":
            renderer.console.print("[bold green]✓ Assignment removed successfully.[/bold green]")
        elif final_status == "FAILED":
            err.print("[bold red]Error:[/bold red] Assignment deletion failed.")
            raise typer.Exit(1)
        else:
            renderer.console.print("[bold yellow]Deletion is still in progress.[/bold yellow]")
    else:
        renderer.console.print("[bold green]✓ Assignment removed.[/bold green]")


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@app.command("audit")
def sso_audit() -> None:
    """Show full SSO assignment audit grouped by account."""
    with renderer.console.status("[bold]Fetching SSO data...[/bold]"):
        try:
            instance = sso_api.get_instance()
            if not instance:
                err.print("[bold red]Error:[/bold red] No SSO instance found.")
                raise typer.Exit(1)

            ps_list = sso_api.list_permission_sets(instance.instance_arn)

            from standstill.aws.organizations import all_accounts, build_ou_tree
            tree = build_ou_tree()
            accts = all_accounts(tree)
            account_name_map = {a.id: a.name for a in accts}

            assignments = sso_api.list_all_assignments(
                instance.instance_arn,
                instance.identity_store_id,
                ps_list,
                account_name_map,
            )
        except typer.Exit:
            raise
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    render_sso_audit(assignments)

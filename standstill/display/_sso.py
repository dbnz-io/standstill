from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from standstill.aws.sso import AccountAssignment, PermissionSet, SSOInstance

console = Console()


def render_sso_status(
    instance: SSOInstance | None,
    ps_count: int,
    assignment_count: int,
) -> None:
    """Render SSO instance status panel."""
    if instance is None:
        console.print("[bold red]No SSO instance found.[/bold red]")
        return

    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    t.add_column("Key", style="bold cyan")
    t.add_column("Value")
    t.add_row("Instance ARN", f"[dim]{instance.instance_arn}[/dim]")
    t.add_row("Identity Store ID", instance.identity_store_id)
    t.add_row("Name", instance.name or "[dim](unnamed)[/dim]")
    t.add_row("Permission Sets", str(ps_count))
    t.add_row("Assignments", str(assignment_count))

    console.print(Panel(t, title="[bold]IAM Identity Center (SSO)[/bold]", expand=False))


def render_permission_sets(ps_list: list[PermissionSet]) -> None:
    """Render permission sets table."""
    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Name", style="bold")
    t.add_column("Session Duration", justify="center", no_wrap=True)
    t.add_column("Managed Policies", justify="right")
    t.add_column("Has Inline Policy", justify="center", no_wrap=True)

    for ps in sorted(ps_list, key=lambda x: x.name):
        mp_count = len(ps.managed_policies)
        mp_names = ", ".join(
            arn.split("/")[-1] for arn in ps.managed_policies[:3]
        )
        if mp_count > 3:
            mp_names += f" (+{mp_count - 3} more)"
        mp_str = f"{mp_count}  [dim]{mp_names}[/dim]" if mp_names else str(mp_count)

        inline_icon = Text("✓", style="bold green") if ps.inline_policy else Text("✗", style="dim")
        t.add_row(ps.name, ps.session_duration or "—", mp_str, inline_icon)

    console.print(t)
    console.print(f"\n[dim]Total: {len(ps_list)} permission set(s)[/dim]")


def render_assignments(
    assignments: list[AccountAssignment],
    group_by: str = "account",
) -> None:
    """Render account assignments table."""
    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Account", style="bold")
    t.add_column("Account ID", style="cyan", no_wrap=True)
    t.add_column("Permission Set", style="yellow")
    t.add_column("Type", justify="center", no_wrap=True)
    t.add_column("Principal", style="dim")

    sorted_assignments = sorted(
        assignments,
        key=lambda a: (a.account_name or a.account_id, a.permission_set_name),
    )

    for a in sorted_assignments:
        type_icon = (
            Text("👤 USER", style="cyan")
            if a.principal_type == "USER"
            else Text("👥 GROUP", style="yellow")
        )
        t.add_row(
            a.account_name or "—",
            a.account_id,
            a.permission_set_name,
            type_icon,
            a.principal_name or a.principal_id,
        )

    console.print(t)
    console.print(f"\n[dim]Total: {len(assignments)} assignment(s)[/dim]")


def render_sso_audit(assignments: list[AccountAssignment]) -> None:
    """Render grouped-by-account SSO audit view."""
    from collections import defaultdict

    by_account: dict[str, list[AccountAssignment]] = defaultdict(list)
    for a in assignments:
        key = a.account_name or a.account_id
        by_account[key].append(a)

    for account_key in sorted(by_account.keys()):
        acct_assignments = by_account[account_key]
        account_id = acct_assignments[0].account_id

        t = Table(
            box=box.SIMPLE,
            show_lines=False,
            title=f"[bold]{account_key}[/bold]  [dim]{account_id}[/dim]",
            title_justify="left",
        )
        t.add_column("Permission Set", style="yellow")
        t.add_column("Type", justify="center", no_wrap=True)
        t.add_column("Principal")

        for a in sorted(acct_assignments, key=lambda x: x.permission_set_name):
            type_icon = (
                Text("USER", style="cyan")
                if a.principal_type == "USER"
                else Text("GROUP", style="yellow")
            )
            t.add_row(
                a.permission_set_name,
                type_icon,
                a.principal_name or a.principal_id,
            )

        console.print(t)

    total_accounts = len(by_account)
    console.print(f"\n[dim]{total_accounts} account(s)  •  {len(assignments)} assignment(s) total[/dim]")

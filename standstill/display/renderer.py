from __future__ import annotations

import json
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from standstill.aws.config_recorder import RecorderResult, RecorderState
from standstill.aws.controltower import EnabledControl
from standstill.aws.organizations import Account, OUNode
from standstill.aws.security_services import (
    AccountAssessment,
    DelegationStatus,
    MemberServiceStatus,
    ServiceApplyResult,
    ServiceStatus,
)

# Re-exports from domain sub-modules — callers import from `renderer` as before
from standstill.display._security import (  # noqa: F401
    render_lake_status,
    render_lake_view_results,
    render_security_assessment,
    render_security_plan,
    render_security_results,
    render_security_status,
)
from standstill.display._cost import (  # noqa: F401
    render_anomalies,
    render_anomalies_csv,
    render_budgets,
    render_budgets_csv,
    render_cost_forecast,
    render_cost_forecast_by_service,
    render_cost_forecast_by_service_csv,
    render_cost_forecast_csv,
    render_cost_report,
    render_cost_report_csv,
    render_cost_services,
    render_cost_services_csv,
    render_ri,
    render_rightsizing,
    render_savings_plans,
    render_scan_csv,
    render_scan_result,
    render_trail_config,
)

console = Console()

_BEHAVIOR_STYLES = {
    "PREVENTIVE": "red",
    "DETECTIVE": "yellow",
    "PROACTIVE": "blue",
}
_SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFORMATIONAL": "dim",
}


# ---------------------------------------------------------------------------
# Identity / permissions
# ---------------------------------------------------------------------------

def render_identity(
    identity: dict,
    profile: Optional[str],
    region: Optional[str],
) -> None:
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    t.add_column("Key", style="bold cyan")
    t.add_column("Value")
    t.add_row("Account", identity.get("Account", "—"))
    t.add_row("ARN", identity.get("Arn", "—"))
    t.add_row("UserID", identity.get("UserId", "—"))
    t.add_row("Region", region or "[dim](default)[/dim]")
    t.add_row("Profile", profile or "[dim](default)[/dim]")
    console.print(Panel(t, title="[bold]AWS Identity[/bold]", expand=False))


def render_permissions(results: dict[str, bool | str]) -> None:
    t = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
    t.add_column("Permission", style="cyan")
    t.add_column("Status", justify="center", no_wrap=True)
    t.add_column("Detail", style="dim")

    for perm, result in results.items():
        if result is True:
            icon = Text("✓", style="bold green")
            detail = ""
        elif isinstance(result, str) and result.startswith("("):
            icon = Text("—", style="dim")
            detail = result
        else:
            icon = Text("✗", style="bold red")
            detail = str(result)
        t.add_row(perm, icon, detail)

    console.print(Panel(t, title="[bold]Control Tower Permissions[/bold]", expand=False))


# ---------------------------------------------------------------------------
# OU tree
# ---------------------------------------------------------------------------

def _attach_ou(node: OUNode, parent: Tree) -> None:
    acct_count = node.account_count
    label = (
        f"[bold]{node.name}[/bold]  "
        f"[dim]{node.id}[/dim]  "
        f"[cyan]{acct_count}[/cyan] acct{'s' if acct_count != 1 else ''}"
    )
    branch = parent.add(label)
    for child in node.children:
        _attach_ou(child, branch)


def render_ou_tree(nodes: list[OUNode]) -> None:
    tree = Tree("[bold yellow]Root[/bold yellow]")
    for node in nodes:
        _attach_ou(node, tree)
    console.print(tree)


# ---------------------------------------------------------------------------
# Accounts table
# ---------------------------------------------------------------------------

def render_accounts_table(accounts: list[Account]) -> None:
    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Name", style="bold")
    t.add_column("Account ID", style="cyan", no_wrap=True)
    t.add_column("OU", style="yellow")
    t.add_column("Status", justify="center", no_wrap=True)
    t.add_column("Email", style="dim")

    for acct in sorted(accounts, key=lambda a: (a.ou_name, a.name)):
        status_style = "bold green" if acct.status == "ACTIVE" else "bold red"
        t.add_row(
            acct.name,
            acct.id,
            acct.ou_name,
            Text(acct.status, style=status_style),
            acct.email,
        )

    console.print(t)
    console.print(f"\n[dim]Total: {len(accounts)} account(s)[/dim]")


# ---------------------------------------------------------------------------
# Controls summary
# ---------------------------------------------------------------------------

def _ou_depth(ou: OUNode, flat: list[OUNode]) -> int:
    """Count how many ancestor OUs exist in `flat` (root-level OUs return 0)."""
    depth = 0
    current_parent = ou.parent_id
    id_set = {n.id for n in flat}
    while current_parent and current_parent in id_set:
        depth += 1
        parent_node = next((n for n in flat if n.id == current_parent), None)
        if parent_node is None:
            break
        current_parent = parent_node.parent_id
    return depth


def render_controls_summary(
    ou_nodes: list[OUNode],
    enabled_by_ou: dict[str, list[EnabledControl]],
) -> None:
    from standstill.aws.organizations import flatten_ous

    t = Table(box=box.ROUNDED, show_lines=True)
    t.add_column("OU", style="bold yellow", no_wrap=True, min_width=20)
    t.add_column("OU ID", style="dim", no_wrap=True)
    t.add_column("Accts", justify="right", style="cyan")
    t.add_column("Total\nEnabled", justify="right", style="bold")
    t.add_column("Succeeded", justify="right", style="green")
    t.add_column("Failed", justify="right", style="red")
    t.add_column("In Progress", justify="right", style="yellow")

    flat = flatten_ous(ou_nodes)
    grand_total = 0
    for ou in flat:
        enabled = enabled_by_ou.get(ou.arn, [])
        status_counts: dict[str, int] = {"SUCCEEDED": 0, "FAILED": 0, "IN_PROGRESS": 0}
        for ec in enabled:
            key = ec.status if ec.status in status_counts else "SUCCEEDED"
            status_counts[key] += 1
        total = len(enabled)
        grand_total += total

        indent = "  " * _ou_depth(ou, flat)
        t.add_row(
            indent + ou.name,
            ou.id,
            str(len(ou.accounts)),
            str(total) if total else "[dim]—[/dim]",
            str(status_counts["SUCCEEDED"]) if status_counts["SUCCEEDED"] else "[dim]—[/dim]",
            str(status_counts["FAILED"]) if status_counts["FAILED"] else "[dim]—[/dim]",
            str(status_counts["IN_PROGRESS"]) if status_counts["IN_PROGRESS"] else "[dim]—[/dim]",
        )

    console.print(t)
    console.print(f"\n[dim]Total enabled controls across all OUs: {grand_total}[/dim]")


# ---------------------------------------------------------------------------
# Config recorder — resource types
# ---------------------------------------------------------------------------

def render_resource_types_list(
    active: list[str],
    bundled: list[str],
    is_user_override: bool,
    show_removed: bool = False,
) -> None:
    bundled_set = set(bundled)
    active_set = set(active)

    source_label = (
        "[green]user override[/green] (~/.standstill/securityhub_resource_types.yaml)"
        if is_user_override
        else "[dim]bundled defaults[/dim]"
    )
    console.print(f"Source: {source_label}\n")

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Resource Type", style="cyan")
    t.add_column("Service", style="yellow", no_wrap=True)
    t.add_column("Status", justify="center", no_wrap=True)

    def _service(rt: str) -> str:
        parts = rt.split("::")
        return parts[1] if len(parts) >= 2 else "—"

    rows: list[tuple[str, str, str]] = []

    for rt in sorted(active):
        if rt in bundled_set:
            status = "[dim]bundled[/dim]"
        else:
            status = "[green]added[/green]"
        rows.append((rt, _service(rt), status))

    if show_removed and is_user_override:
        for rt in sorted(bundled_set - active_set):
            rows.append((rt, _service(rt), "[red]removed[/red]"))

    rows.sort(key=lambda r: (r[1], r[0]))
    for rt, svc, status in rows:
        t.add_row(rt, svc, status)

    console.print(t)

    added = len(active_set - bundled_set)
    removed = len(bundled_set - active_set) if is_user_override else 0
    console.print(
        f"[dim]Total: {len(active)} active type(s)"
        + (f"  •  [green]+{added} added[/green]" if added else "")
        + (f"  •  [red]−{removed} removed[/red]" if removed else "")
        + "[/dim]"
    )
    if removed and not show_removed:
        console.print(
            f"[dim]({removed} bundled type(s) removed from user list — "
            "use --show-removed to display them)[/dim]"
        )


# ---------------------------------------------------------------------------
# Config recorder
# ---------------------------------------------------------------------------

def render_recorder_status(states: list[RecorderState]) -> None:
    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Account", style="bold")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("OU", style="yellow")
    t.add_column("Running", justify="center", no_wrap=True)
    t.add_column("Frequency", justify="center", no_wrap=True)
    t.add_column("Types", justify="right")
    t.add_column("Detail", style="dim")

    for s in states:
        if s.error:
            t.add_row(
                s.account_name, s.account_id, s.ou_name,
                Text("✗", style="bold red"), "—", "—",
                s.error[:60],
            )
            continue
        if not s.exists:
            t.add_row(
                s.account_name, s.account_id, s.ou_name,
                Text("—", style="dim"), "—", "—",
                "[dim]no recorder[/dim]",
            )
            continue
        running_icon = Text("✓", style="bold green") if s.running else Text("✗", style="bold red")
        freq = s.recording_frequency or "—"
        freq_style = "green" if freq == "DAILY" else "yellow"
        type_str = "[dim]all[/dim]" if s.all_supported else str(s.resource_type_count)
        t.add_row(
            s.account_name, s.account_id, s.ou_name,
            running_icon,
            f"[{freq_style}]{freq.lower()}[/{freq_style}]",
            type_str,
            "",
        )

    console.print(t)
    errors = sum(1 for s in states if s.error)
    no_rec = sum(1 for s in states if not s.error and not s.exists)
    if errors:
        console.print(f"[dim]{errors} account(s) could not be reached.[/dim]")
    if no_rec:
        console.print(f"[dim]{no_rec} account(s) have no Config recorder (not enrolled in CT).[/dim]")


def render_recorder_plan(
    states: list[RecorderState],
    desired_types: list[str],
    desired_frequency: str,
) -> None:
    t = Table(box=box.ROUNDED, show_lines=False, title="[bold]Dry-run plan[/bold]")
    t.add_column("Account", style="bold")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("OU", style="yellow")
    t.add_column("Frequency", justify="center")
    t.add_column("Types", justify="right")
    t.add_column("Action", justify="center")

    for s in states:
        if s.error:
            t.add_row(
                s.account_name, s.account_id, s.ou_name,
                "—", "—", Text("error", style="bold red"),
            )
            continue
        if not s.exists:
            t.add_row(
                s.account_name, s.account_id, s.ou_name,
                "—", "—", Text("skip — no recorder", style="dim"),
            )
            continue

        freq_change = s.recording_frequency != desired_frequency or s.all_supported
        type_change = s.all_supported or s.resource_type_count != len(desired_types)

        if not freq_change and not type_change and s.running:
            action = Text("no change", style="dim")
        else:
            action = Text("update", style="bold yellow")

        current_freq = s.recording_frequency or "?"
        current_types = "all" if s.all_supported else str(s.resource_type_count)

        freq_str = (
            f"[dim]{current_freq.lower()}[/dim] → [green]{desired_frequency.lower()}[/green]"
            if freq_change else f"[green]{desired_frequency.lower()}[/green]"
        )
        types_str = (
            f"[dim]{current_types}[/dim] → [green]{len(desired_types)}[/green]"
            if type_change else f"[green]{len(desired_types)}[/green]"
        )
        t.add_row(s.account_name, s.account_id, s.ou_name, freq_str, types_str, action)

    console.print(t)


def render_recorder_results(results: list[RecorderResult]) -> None:
    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Account", style="bold")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("OU", style="yellow")
    t.add_column("Result", justify="center", no_wrap=True)
    t.add_column("Detail", style="dim")

    for r in results:
        if r.noop:
            icon = Text("—", style="dim")
        elif r.success:
            icon = Text("✓", style="bold green")
        else:
            icon = Text("✗", style="bold red")
        t.add_row(r.account_name, r.account_id, r.ou_name, icon, r.message)

    console.print(t)
    succeeded = sum(1 for r in results if r.success and not r.noop)
    noops = sum(1 for r in results if r.noop)
    failed = sum(1 for r in results if not r.success and not r.noop)
    console.print(
        f"\n[green]{succeeded} updated[/green]  "
        f"[dim]{noops} already up to date[/dim]  "
        f"[{'red' if failed else 'dim'}]{failed} failed[/{'red' if failed else 'dim'}]"
    )


# ---------------------------------------------------------------------------
# Account role reachability
# ---------------------------------------------------------------------------

def render_account_roles_table(
    accounts: list[Account],
    results: dict[str, tuple[bool, str]],
    role_name: str,
) -> None:
    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Name", style="bold")
    t.add_column("Account ID", style="cyan", no_wrap=True)
    t.add_column("OU", style="yellow")
    t.add_column(f"Role: {role_name}", justify="center", no_wrap=True)
    t.add_column("Detail", style="dim")

    ok_count = 0
    for acct in sorted(accounts, key=lambda a: (a.ou_name, a.name)):
        reachable, detail = results.get(acct.id, (False, "not checked"))
        if reachable:
            icon = Text("✓", style="bold green")
            detail_str = ""
            ok_count += 1
        else:
            icon = Text("✗", style="bold red")
            detail_str = detail
        t.add_row(acct.name, acct.id, acct.ou_name, icon, detail_str)

    console.print(t)
    fail_count = len(accounts) - ok_count
    console.print(
        f"\n[green]{ok_count} reachable[/green]  "
        f"[{'red' if fail_count else 'dim'}]{fail_count} unreachable[/{'red' if fail_count else 'dim'}]"
        f"  [dim]out of {len(accounts)} account(s)[/dim]"
    )


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

def render_blueprint_stack_results(results: list) -> None:
    """Print a StackResult list from standstill.aws.blueprint."""
    _ACTION_STYLE: dict[str, str] = {
        "created": "green",
        "updated": "cyan",
        "skipped": "dim",
        "dry-run": "yellow",
        "failed": "bold red",
    }
    for r in results:
        style = _ACTION_STYLE.get(r.action, "white")
        label = r.action.upper()
        if r.error:
            console.print(f"  [{style}]{label}[/{style}]  {r.stack_name}  [red]{r.error}[/red]")
        elif r.status:
            console.print(f"  [{style}]{label}[/{style}]  {r.stack_name}  [dim]{r.status}[/dim]")
        else:
            console.print(f"  [{style}]{label}[/{style}]  {r.stack_name}")


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def render_json(data: object) -> None:
    console.print_json(json.dumps(data, default=str))

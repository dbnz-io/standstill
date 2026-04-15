from __future__ import annotations

import csv
import json
import sys
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

    rows.sort(key=lambda r: (r[1], r[0]))  # sort by service then type
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
# Security services
# ---------------------------------------------------------------------------

_SVC_LABELS = {
    "guardduty":       "GuardDuty",
    "security_hub":    "Security Hub",
    "macie":           "Macie",
    "inspector":       "Inspector",
    "access_analyzer": "Access Analyzer",
}

_DELEGATION_ACTION_STYLES = {
    "register": ("register", "bold yellow"),
    "skip":     ("already registered", "dim"),
    "conflict": ("CONFLICT", "bold red"),
    "error":    ("error", "bold red"),
}


def render_security_plan(config, delegation: list[DelegationStatus]) -> None:
    """Show the dry-run plan: what delegation actions will be taken per service."""

    console.print(
        f"[bold]Delegated admin:[/bold] [cyan]{config.delegated_admin_account}[/cyan]\n"
    )

    t = Table(box=box.ROUNDED, title="[bold]Phase 1 — Delegation[/bold]", show_lines=False)
    t.add_column("Service", style="bold")
    t.add_column("Current Admin", style="dim", no_wrap=True)
    t.add_column("Action", justify="center", no_wrap=True)

    for d in delegation:
        label, style = _DELEGATION_ACTION_STYLES.get(d.action, (d.action, "dim"))
        t.add_row(
            _SVC_LABELS.get(d.service, d.service),
            d.current_admin or "—",
            Text(label, style=style),
        )
    console.print(t)

    # Phase 2 summary
    svc_cfg = config.services
    enabled = [
        (_SVC_LABELS[k], getattr(svc_cfg, k).enabled)
        for k in _SVC_LABELS
    ]
    t2 = Table(box=box.ROUNDED, title="[bold]Phase 2 — Configuration[/bold]", show_lines=False)
    t2.add_column("Service", style="bold")
    t2.add_column("Will configure", justify="center")
    for label, is_enabled in enabled:
        icon = Text("✓", style="bold green") if is_enabled else Text("skip", style="dim")
        t2.add_row(label, icon)
    console.print(t2)


def render_security_results(results: list[ServiceApplyResult], phase_label: str) -> None:
    if not results:
        console.print(f"[dim]{phase_label}: nothing to do.[/dim]")
        return

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Service", style="bold")
    t.add_column("Result", justify="center", no_wrap=True)
    t.add_column("Detail", style="dim")

    for r in results:
        icon = Text("✓", style="bold green") if r.success else Text("✗", style="bold red")
        detail = r.message
        if r.details:
            detail += "  [dim](" + "; ".join(r.details) + ")[/dim]"
        t.add_row(_SVC_LABELS.get(r.service, r.service), icon, detail)

    console.print(t)


def render_security_status(statuses: list[ServiceStatus]) -> None:
    t = Table(box=box.ROUNDED, show_lines=True)
    t.add_column("Service", style="bold")
    t.add_column("Delegated Admin", style="cyan", no_wrap=True)
    t.add_column("Enabled", justify="center", no_wrap=True)
    t.add_column("Auto-enable", justify="center", no_wrap=True)
    t.add_column("Details", style="dim")

    for s in statuses:
        if s.error:
            t.add_row(
                _SVC_LABELS.get(s.service, s.service),
                s.delegated_admin or "—",
                Text("—", style="dim"),
                "—",
                s.error[:60],
            )
            continue

        enabled_icon = Text("✓", style="bold green") if s.enabled else Text("✗", style="bold red")
        details = "  ".join(f"{k}={v}" for k, v in s.details.items()) if s.details else ""
        t.add_row(
            _SVC_LABELS.get(s.service, s.service),
            s.delegated_admin or "—",
            enabled_icon,
            str(s.auto_enable) if s.auto_enable not in (None, "", "—") else "—",
            details,
        )

    console.print(t)


# ---------------------------------------------------------------------------
# Security assessment
# ---------------------------------------------------------------------------

# Ordered columns for the assessment table (Access Analyzer last — org-wide)
_ASSESS_SVCS = ["guardduty", "security_hub", "macie", "inspector", "access_analyzer"]
_ASSESS_SHORT = {
    "guardduty":       "GD",
    "security_hub":    "SH",
    "macie":           "Macie",
    "inspector":       "Insp",
    "access_analyzer": "AA",
}

# Sentinels that mean "this account is special — not a regular member"
_SPECIAL_STATUSES = {"delegated_admin", "management_account", "org_wide"}


def _assess_icon(status: MemberServiceStatus, svc: str) -> Text:
    if status.error:
        return Text("!", style="bold yellow")
    if status.member_status in _SPECIAL_STATUSES:
        if status.member_status == "delegated_admin":
            return Text("★", style="bold cyan")   # admin account itself
        if status.member_status == "management_account":
            return Text("M", style="dim")          # management account
        return Text("~", style="dim")              # org_wide (Access Analyzer)
    if status.enabled:
        return Text("✓", style="bold green")
    return Text("✗", style="bold red")


def render_security_assessment(
    results: list[AccountAssessment],
    active_services: list[str],
    show_all: bool = False,
) -> None:
    """
    Render a per-account table showing which security services are enabled.

    By default only accounts with at least one gap are shown.
    Pass show_all=True to display every account.
    """
    displayed = [r for r in results if show_all or not r.healthy]

    if not displayed:
        console.print(
            "[bold green]✓ All accounts are fully covered by every security service.[/bold green]"
        )
        _print_assessment_summary(results, active_services)
        return

    # Determine which services to include as columns
    cols = [s for s in _ASSESS_SVCS if s in active_services]

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Account", style="bold", min_width=20)
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("OU", style="yellow", max_width=18)
    for svc in cols:
        t.add_column(_ASSESS_SHORT[svc], justify="center", no_wrap=True)

    for r in displayed:
        icons = [_assess_icon(r.services.get(svc, MemberServiceStatus(False, "n/a")), svc) for svc in cols]
        t.add_row(r.account_name, r.account_id, r.ou_name, *icons)

    console.print(t)

    if not show_all:
        gap_count = len(displayed)
        total = len(results)
        healthy = total - gap_count
        console.print(
            f"\n[dim]Showing {gap_count} account(s) with gaps  •  "
            f"{healthy}/{total} fully covered  •  use --all to show every account[/dim]"
        )
    else:
        _print_assessment_summary(results, active_services)

    # Legend
    console.print(
        "\n[dim]Legend:  "
        "[bold green]✓[/bold green] enabled  "
        "[bold red]✗[/bold red] not enrolled  "
        "[bold cyan]★[/bold cyan] delegated admin  "
        "M management acct  "
        "~ org-wide  "
        "[bold yellow]![/bold yellow] error[/dim]"
    )

    # Per-service error details
    errors: list[tuple[str, str, str]] = []
    for r in results:
        for svc, s in r.services.items():
            if s.error:
                errors.append((r.account_name, _SVC_LABELS.get(svc, svc), s.error))
    if errors:
        console.print()
        for acct_name, svc_label, err in errors[:5]:
            console.print(f"  [bold yellow]![/bold yellow] {acct_name} / {svc_label}: [dim]{err}[/dim]")
        if len(errors) > 5:
            console.print(f"  [dim]... and {len(errors) - 5} more error(s)[/dim]")


def _print_assessment_summary(results: list[AccountAssessment], active_services: list[str]) -> None:
    total = len(results)
    healthy = sum(1 for r in results if r.healthy)
    console.print(f"\n[bold]{healthy}/{total}[/bold] accounts fully covered")

    cols = [s for s in _ASSESS_SVCS if s in active_services]
    for svc in cols:
        covered = sum(
            1 for r in results
            if r.services.get(svc, MemberServiceStatus(False, "")).enabled
            or r.services.get(svc, MemberServiceStatus(False, "")).member_status in _SPECIAL_STATUSES
        )
        bar_width = 20
        filled = int(bar_width * covered / total) if total else 0
        bar = "█" * filled + "░" * (bar_width - filled)
        pct = int(100 * covered / total) if total else 0
        label = _SVC_LABELS.get(svc, svc)
        style = "green" if covered == total else "yellow" if covered > total * 0.8 else "red"
        console.print(
            f"  {label:<18} [{style}]{bar}[/{style}] {covered}/{total} ({pct}%)"
        )


# ---------------------------------------------------------------------------
# JSON output
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


def render_json(data: object) -> None:
    console.print_json(json.dumps(data, default=str))


# ---------------------------------------------------------------------------
# Cost Explorer
# ---------------------------------------------------------------------------

_COST_GROUP_BY_LABELS: dict[str, str] = {
    "service":    "Service",
    "usage-type": "Usage Type",
    "account":    "Account",
    "region":     "Region",
}

_COST_METRIC_LABELS: dict[str, str] = {
    "unblended":    "Unblended Cost",
    "blended":      "Blended Cost",
    "amortized":    "Amortized Cost",
    "net-amortized": "Net Amortized Cost",
}


def _cost_period_label(start: str) -> str:
    """Short column header for a monthly period, e.g. 'Mar 2024'."""
    from datetime import datetime
    return datetime.strptime(start, "%Y-%m-%d").strftime("%b %Y")


def render_cost_report(
    periods: list,
    group_by: str,
    metric: str,
    granularity: str,
    account_names: dict[str, str] | None = None,
    prior_periods: list | None = None,
) -> None:
    """
    Render a cost report.

    * Single period or daily granularity → aggregated table with a % column.
    * Multiple monthly periods (2–12)    → matrix table (group × month).
    * When prior_periods is provided     → comparison view (current vs prior).
    """
    if not periods:
        console.print("[dim]No cost data found for the specified period and filters.[/dim]")
        return

    # Resolve tag:KEY display label.
    if group_by.startswith("tag:"):
        group_label = f"Tag: {group_by[4:]}"
    else:
        group_label = _COST_GROUP_BY_LABELS.get(group_by, group_by.title())

    metric_label = _COST_METRIC_LABELS.get(metric, metric.title())
    unit         = periods[0].unit
    estimated    = any(p.estimated for p in periods)

    if prior_periods is not None:
        _render_cost_comparison(periods, prior_periods, group_label, metric_label, unit, account_names)
        return

    use_matrix = 2 <= len(periods) <= 12 and granularity == "monthly"

    if use_matrix:
        _render_cost_matrix(periods, group_label, metric_label, unit, estimated, account_names)
    else:
        _render_cost_aggregated(
            periods, group_label, metric_label, unit, estimated,
            granularity, group_by=group_by, account_names=account_names,
        )


def _resolve_key_label(key: str, account_names: dict[str, str] | None) -> str:
    """Display account name if available, otherwise return key as-is."""
    if account_names and key in account_names:
        return f"{account_names[key]} ({key})"
    return key


def _render_cost_matrix(
    periods: list,
    group_label: str,
    metric_label: str,
    unit: str,
    estimated: bool,
    account_names: dict[str, str] | None = None,
) -> None:
    """Matrix layout: rows = groups, columns = months."""
    key_totals: dict[str, float] = {}
    for p in periods:
        for g in p.groups:
            key_totals[g.key] = key_totals.get(g.key, 0.0) + g.amount

    sorted_keys = sorted(key_totals, key=lambda k: key_totals[k], reverse=True)

    t = Table(
        box=box.ROUNDED,
        show_lines=False,
        title=f"[bold]{metric_label} ({unit})[/bold]",
    )
    t.add_column(group_label, style="bold", min_width=28)
    for p in periods:
        t.add_column(_cost_period_label(p.start), justify="right", style="cyan", no_wrap=True)
    t.add_column("Total", justify="right", style="bold", no_wrap=True)

    for key in sorted_keys:
        cells: list[str] = []
        row_total = 0.0
        for p in periods:
            match = next((g for g in p.groups if g.key == key), None)
            if match:
                cells.append(f"${match.amount:,.2f}")
                row_total += match.amount
            else:
                cells.append("[dim]—[/dim]")
        t.add_row(_resolve_key_label(key, account_names), *cells, f"[bold]${row_total:,.2f}[/bold]")

    t.add_section()
    period_totals = [f"${p.total:,.2f}" for p in periods]
    grand_total   = sum(p.total for p in periods)
    t.add_row("[bold]TOTAL[/bold]", *period_totals, f"[bold]${grand_total:,.2f}[/bold]")

    console.print(t)
    if estimated:
        console.print("[dim]* One or more values are estimated (current period not yet closed).[/dim]")


def _render_cost_aggregated(
    periods: list,
    group_label: str,
    metric_label: str,
    unit: str,
    estimated: bool,
    granularity: str,
    group_by: str = "",
    account_names: dict[str, str] | None = None,
) -> None:
    """Single-table view: groups sorted by aggregated cost, with a % column."""
    from standstill.aws.usage_type_map import get_usage_type_info

    aggregated: dict[str, float] = {}
    for p in periods:
        for g in p.groups:
            aggregated[g.key] = aggregated.get(g.key, 0.0) + g.amount

    sorted_groups = sorted(aggregated.items(), key=lambda x: x[1], reverse=True)
    grand_total   = sum(p.total for p in periods)

    enrich = group_by == "usage-type"

    title = (
        f"[bold]{metric_label} ({unit}) — "
        f"{periods[0].start} to {periods[-1].end}[/bold]"
    )
    t = Table(box=box.ROUNDED, show_lines=False, title=title)
    t.add_column(group_label, style="bold", min_width=30)
    if enrich:
        t.add_column("Service",    style="yellow",   no_wrap=True)
        t.add_column("API Calls",  style="dim",      max_width=40)
        t.add_column("Event",      style="magenta",  no_wrap=True)
    t.add_column(f"Cost ({unit})", justify="right", style="cyan", no_wrap=True)
    t.add_column("%", justify="right", style="dim", no_wrap=True)

    for key, amount in sorted_groups:
        pct = (amount / grand_total * 100) if grand_total else 0.0
        display_key = _resolve_key_label(key, account_names)
        if enrich:
            info = get_usage_type_info(key)
            svc       = info.service if info else "[dim]—[/dim]"
            calls_str = ", ".join(info.api_calls) if info and info.api_calls else "[dim]—[/dim]"
            event_str = info.event_type if info and info.event_type else "[dim]—[/dim]"
            t.add_row(display_key, svc, calls_str, event_str, f"${amount:,.2f}", f"{pct:.1f}%")
        else:
            t.add_row(display_key, f"${amount:,.2f}", f"{pct:.1f}%")

    t.add_section()
    if enrich:
        t.add_row("[bold]TOTAL[/bold]", "", "", "", f"[bold]${grand_total:,.2f}[/bold]", "[bold]100.0%[/bold]")
    else:
        t.add_row("[bold]TOTAL[/bold]", f"[bold]${grand_total:,.2f}[/bold]", "[bold]100.0%[/bold]")

    console.print(t)
    if estimated:
        console.print("[dim]* One or more values are estimated (current period not yet closed).[/dim]")
    if granularity == "daily" and len(periods) > 1:
        console.print(f"[dim]Aggregated across {len(periods)} day(s).[/dim]")


def _render_cost_comparison(
    periods: list,
    prior_periods: list,
    group_label: str,
    metric_label: str,
    unit: str,
    account_names: dict[str, str] | None = None,
) -> None:
    """Side-by-side comparison of current vs prior period with delta."""
    current_agg: dict[str, float] = {}
    for p in periods:
        for g in p.groups:
            current_agg[g.key] = current_agg.get(g.key, 0.0) + g.amount

    prior_agg: dict[str, float] = {}
    for p in prior_periods:
        for g in p.groups:
            prior_agg[g.key] = prior_agg.get(g.key, 0.0) + g.amount

    all_keys  = sorted(
        set(current_agg) | set(prior_agg),
        key=lambda k: current_agg.get(k, 0.0),
        reverse=True,
    )

    current_label = f"{periods[0].start[:7]}" if periods else "Current"
    prior_label   = f"{prior_periods[0].start[:7]}" if prior_periods else "Prior"

    t = Table(
        box=box.ROUNDED,
        show_lines=False,
        title=f"[bold]{metric_label} ({unit}) — Period Comparison[/bold]",
    )
    t.add_column(group_label, style="bold", min_width=30)
    t.add_column(current_label, justify="right", style="cyan",   no_wrap=True)
    t.add_column(prior_label,   justify="right", style="dim",    no_wrap=True)
    t.add_column("Δ",           justify="right", no_wrap=True)
    t.add_column("Δ %",         justify="right", no_wrap=True)

    for key in all_keys:
        curr  = current_agg.get(key, 0.0)
        prior = prior_agg.get(key, 0.0)
        delta = curr - prior
        delta_pct = (delta / prior * 100) if prior else 0.0
        if delta > 0:
            delta_str = f"[red]+${delta:,.2f}[/red]"
            pct_str   = f"[red]+{delta_pct:.1f}%[/red]"
        elif delta < 0:
            delta_str = f"[green]-${abs(delta):,.2f}[/green]"
            pct_str   = f"[green]{delta_pct:.1f}%[/green]"
        else:
            delta_str = "[dim]—[/dim]"
            pct_str   = "[dim]—[/dim]"
        t.add_row(
            _resolve_key_label(key, account_names),
            f"${curr:,.2f}" if curr else "[dim]—[/dim]",
            f"${prior:,.2f}" if prior else "[dim]—[/dim]",
            delta_str,
            pct_str,
        )

    t.add_section()
    curr_total  = sum(p.total for p in periods)
    prior_total = sum(p.total for p in prior_periods)
    total_delta = curr_total - prior_total
    total_pct   = (total_delta / prior_total * 100) if prior_total else 0.0
    delta_color = "red" if total_delta > 0 else "green" if total_delta < 0 else "dim"
    t.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]${curr_total:,.2f}[/bold]",
        f"[bold]${prior_total:,.2f}[/bold]",
        f"[{delta_color}]{'+' if total_delta >= 0 else ''}${total_delta:,.2f}[/{delta_color}]",
        f"[{delta_color}]{total_pct:+.1f}%[/{delta_color}]",
    )
    console.print(t)


def render_cost_services(
    services: list[str],
    start: str,
    end: str,
    svc_costs: dict[str, float] | None = None,
) -> None:
    from standstill.aws.cost import service_filter_alias

    if not services:
        console.print("[dim]No services with costs found for the specified period.[/dim]")
        return

    t = Table(
        box=box.ROUNDED,
        show_lines=False,
        title=f"[bold]Services with costs ({start} → {end})[/bold]",
    )
    t.add_column("#", justify="right", style="dim", no_wrap=True)
    t.add_column("Service Name", style="bold")
    t.add_column("--filter alias", style="cyan", no_wrap=True)
    if svc_costs:
        t.add_column("Cost (USD)", justify="right", style="yellow", no_wrap=True)

    for i, svc in enumerate(services, 1):
        alias = service_filter_alias(svc)
        if svc_costs:
            cost = svc_costs.get(svc, 0.0)
            t.add_row(str(i), svc, alias or "[dim]—[/dim]", f"${cost:,.2f}")
        else:
            t.add_row(str(i), svc, alias or "[dim]—[/dim]")

    console.print(t)
    total = sum(svc_costs.values()) if svc_costs else 0.0
    footer = f"[dim]{len(services)} service(s) — ordered by cost (highest first)."
    if svc_costs:
        footer += f"  Total: ${total:,.2f}"
    footer += "[/dim]"
    console.print(f"\n{footer}")


def render_cost_forecast(result: dict, metric: str) -> None:
    from datetime import datetime

    metric_label = _COST_METRIC_LABELS.get(metric, metric.title())
    unit         = result.get("unit", "USD")
    monthly      = result.get("monthly", [])
    total        = result.get("total", 0.0)

    t = Table(
        box=box.ROUNDED,
        show_lines=False,
        title=f"[bold]{metric_label} Forecast ({unit})[/bold]",
    )
    t.add_column("Month",     style="bold",  no_wrap=True)
    t.add_column("Projected", justify="right", style="cyan",  no_wrap=True)
    t.add_column("Low",       justify="right", style="dim",   no_wrap=True)
    t.add_column("High",      justify="right", style="dim",   no_wrap=True)

    for m in monthly:
        label = datetime.strptime(m["start"], "%Y-%m-%d").strftime("%B %Y")
        t.add_row(
            label,
            f"${m['amount']:,.2f}",
            f"${m['lower']:,.2f}",
            f"${m['upper']:,.2f}",
        )

    t.add_section()
    t.add_row("[bold]TOTAL[/bold]", f"[bold]${total:,.2f}[/bold]", "", "")

    console.print(t)
    console.print("[dim]Forecast generated by AWS Cost Explorer ML model.[/dim]")


# ---------------------------------------------------------------------------
# Cost Explorer — CSV output
# ---------------------------------------------------------------------------

def render_cost_report_csv(periods: list, group_by: str) -> None:
    """
    Write cost report rows to stdout as CSV.

    For usage-type group-by, extra columns ``service``, ``api_calls``, and
    ``event_type`` are included.  A ``TOTAL`` row is appended for each period.
    """
    from standstill.aws.usage_type_map import get_usage_type_info

    group_col = _COST_GROUP_BY_LABELS.get(group_by, group_by)
    enrich = group_by == "usage-type"

    writer = csv.writer(sys.stdout)
    header = ["period_start", "period_end", group_col]
    if enrich:
        header += ["service", "api_calls", "event_type"]
    header += ["amount_usd", "estimated"]
    writer.writerow(header)

    for p in periods:
        for g in p.groups:
            row: list = [p.start, p.end, g.key]
            if enrich:
                info = get_usage_type_info(g.key)
                row += [
                    info.service if info else "",
                    "; ".join(info.api_calls) if info and info.api_calls else "",
                    info.event_type if info and info.event_type else "",
                ]
            row += [f"{g.amount:.10g}", p.estimated]
            writer.writerow(row)
        total_row: list = [p.start, p.end, "TOTAL"]
        if enrich:
            total_row += ["", "", ""]
        total_row += [f"{p.total:.10g}", p.estimated]
        writer.writerow(total_row)


def render_cost_services_csv(services: list[str], svc_costs: dict[str, float] | None = None) -> None:
    """Write services list to stdout as CSV."""
    writer = csv.writer(sys.stdout)
    if svc_costs:
        writer.writerow(["rank", "service_name", "cost_usd"])
        for i, svc in enumerate(services, 1):
            writer.writerow([i, svc, f"{svc_costs.get(svc, 0.0):.10g}"])
    else:
        writer.writerow(["rank", "service_name"])
        for i, svc in enumerate(services, 1):
            writer.writerow([i, svc])


def render_trail_config(s3_cfg: dict | None, cloudwatch_log_group: str | None) -> None:
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    t.add_column("k", style="bold cyan")
    t.add_column("v")

    if s3_cfg:
        t.add_row("S3 bucket", s3_cfg.get("bucket", "—"))
        t.add_row("S3 prefix", s3_cfg.get("prefix") or "[dim](none)[/dim]")
    else:
        t.add_row("S3", "[dim]not configured[/dim]")

    if cloudwatch_log_group:
        t.add_row("CloudWatch log group", cloudwatch_log_group)
    else:
        t.add_row("CloudWatch", "[dim]not configured[/dim]")

    from rich.panel import Panel
    console.print(Panel(t, title="[bold]CloudTrail Log Targets[/bold]", expand=False))


def render_scan_result(result, target: str = "event-history") -> None:  # result: cloudtrail_scan.ScanResult
    """Render a CloudTrail scan as three Rich tables: metadata, summary, events."""
    from standstill.aws.usage_type_map import _REGION_PREFIX_RE, get_usage_type_info

    info = get_usage_type_info(_REGION_PREFIX_RE.sub("", result.usage_type))
    event_type_str = (info.event_type or "—") if info else "—"

    # ── header panel ────────────────────────────────────────────────────────
    meta = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    meta.add_column("k", style="bold cyan")
    meta.add_column("v")
    _TARGET_LABELS = {
        "event-history": "CloudTrail Event History API",
        "s3":            "S3",
        "cloudwatch":    "CloudWatch Logs Insights",
    }
    meta.add_row("Usage Type",    result.usage_type)
    meta.add_row("Service",       result.service)
    meta.add_row("Event Source",  result.event_source)
    meta.add_row("Event Type",    event_type_str)
    meta.add_row("API Calls",     ", ".join(result.api_calls_searched) or "(by event source)")
    meta.add_row("Source",        _TARGET_LABELS.get(target, target))
    meta.add_row("Period",        f"{result.start[:10]}  →  {result.end[:10]}")
    meta.add_row("Total Events",  str(len(result.events)))
    from rich.panel import Panel
    console.print(Panel(meta, title="[bold]CloudTrail Scan[/bold]", expand=False))

    if not result.events:
        console.print("[dim]No events found for the specified period.[/dim]")
        return

    # ── identity attribution (who is generating this cost?) ─────────────────
    identity_rows = result.summary_by_identity_attribution()
    if identity_rows:
        t_id = Table(box=box.ROUNDED, show_lines=False, title="[bold]Identity Attribution[/bold]")
        t_id.add_column("Account",       style="dim",    no_wrap=True)
        t_id.add_column("Type",          style="yellow", no_wrap=True)
        t_id.add_column("Identity",      style="bold",   max_width=45)
        t_id.add_column("Calls",         justify="right", style="cyan")
        t_id.add_column("Errors",        justify="right", style="red")
        t_id.add_column("Regions",       style="dim",    max_width=30)
        for row in identity_rows[:15]:
            t_id.add_row(
                row["account_id"] or "—",
                row["identity_type"],
                row["identity_name"],
                str(row["call_count"]),
                str(row["error_count"]) if row["error_count"] else "—",
                ", ".join(row["regions"]),
            )
        console.print(t_id)

    # ── summary by API call ─────────────────────────────────────────────────
    t_sum = Table(box=box.ROUNDED, show_lines=False, title="[bold]Summary by API Call[/bold]")
    t_sum.add_column("Event Name",  style="bold", no_wrap=True)
    t_sum.add_column("Count",       justify="right", style="cyan")
    t_sum.add_column("First Seen",  style="dim",  no_wrap=True)
    t_sum.add_column("Last Seen",   no_wrap=True)
    for row in result.summary_by_event():
        t_sum.add_row(
            row["event_name"],
            str(row["count"]),
            row["first"][:19].replace("T", " "),
            row["last"][:19].replace("T", " "),
        )
    console.print(t_sum)

    # ── top callers ─────────────────────────────────────────────────────────
    callers = result.summary_by_caller()[:10]
    t_cal = Table(box=box.ROUNDED, show_lines=False, title="[bold]Top Callers[/bold]")
    t_cal.add_column("Username / ARN", style="bold")
    t_cal.add_column("Calls", justify="right", style="cyan")
    for row in callers:
        t_cal.add_row(row["username"], str(row["count"]))
    console.print(t_cal)

    # ── recent events (up to 20) ─────────────────────────────────────────────
    recent = sorted(result.events, key=lambda e: e.event_time, reverse=True)[:20]
    t_ev = Table(box=box.ROUNDED, show_lines=False, title="[bold]Recent Events[/bold] (latest 20)")
    t_ev.add_column("Time",        style="dim",    no_wrap=True)
    t_ev.add_column("Event Name",  style="bold",   no_wrap=True)
    t_ev.add_column("Username",    max_width=35)
    t_ev.add_column("Source IP",   style="dim",    no_wrap=True)
    t_ev.add_column("Region",      style="yellow", no_wrap=True)
    t_ev.add_column("Error",       style="red",    no_wrap=True)
    for ev in recent:
        t_ev.add_row(
            ev.event_time.strftime("%Y-%m-%d %H:%M:%S"),
            ev.event_name,
            ev.username,
            ev.source_ip,
            ev.region,
            ev.error_code or "",
        )
    console.print(t_ev)

    if len(result.events) > 20:
        console.print(
            f"[dim]Showing 20 of {len(result.events)} events. "
            "Use [bold]-o json[/bold] or [bold]-o csv[/bold] for the full set.[/dim]"
        )


def render_scan_csv(result) -> None:  # result: cloudtrail_scan.ScanResult
    """Write scan events to stdout as CSV."""
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "event_time", "event_name", "username", "account_id",
        "source_ip", "user_agent", "region", "read_only",
        "resources", "error_code", "error_message",
    ])
    for ev in sorted(result.events, key=lambda e: e.event_time, reverse=True):
        writer.writerow([
            ev.event_time.isoformat(),
            ev.event_name,
            ev.username,
            ev.account_id,
            ev.source_ip,
            ev.user_agent,
            ev.region,
            ev.read_only,
            "; ".join(ev.resources),
            ev.error_code,
            ev.error_message,
        ])


def render_cost_forecast_csv(result: dict) -> None:
    """
    Write forecast rows to stdout as CSV.

    Columns: ``period_start, period_end, projected_usd, low_usd, high_usd``
    A ``TOTAL`` row (low/high blank) is appended at the end.
    """
    writer = csv.writer(sys.stdout)
    writer.writerow(["period_start", "period_end", "projected_usd", "low_usd", "high_usd"])
    for m in result.get("monthly", []):
        writer.writerow([
            m["start"], m["end"],
            f"{m['amount']:.10g}",
            f"{m['lower']:.10g}",
            f"{m['upper']:.10g}",
        ])
    writer.writerow(["", "", f"{result.get('total', 0.0):.10g}", "", ""])


# ---------------------------------------------------------------------------
# Forecast by service
# ---------------------------------------------------------------------------

def render_cost_forecast_by_service(svc_results: list[dict], metric: str) -> None:
    """Render a per-service forecast as a matrix: rows = services, cols = months."""
    if not svc_results:
        console.print("[dim]No forecast data available.[/dim]")
        return

    metric_label = _COST_METRIC_LABELS.get(metric, metric.title())

    # Collect all month labels from the first non-empty result.
    month_labels: list[tuple[str, str]] = []  # (start, label)
    for r in svc_results:
        if r.get("monthly"):
            from datetime import datetime
            month_labels = [
                (m["start"], datetime.strptime(m["start"], "%Y-%m-%d").strftime("%b %Y"))
                for m in r["monthly"]
            ]
            break

    t = Table(
        box=box.ROUNDED,
        show_lines=False,
        title=f"[bold]{metric_label} Forecast by Service (USD)[/bold]",
    )
    t.add_column("Service", style="bold", min_width=30)
    for _, lbl in month_labels:
        t.add_column(lbl, justify="right", style="cyan", no_wrap=True)
    t.add_column("Total", justify="right", style="bold", no_wrap=True)

    for r in svc_results:
        monthly_map = {m["start"]: m["amount"] for m in r.get("monthly", [])}
        cells = [f"${monthly_map.get(start, 0.0):,.2f}" for start, _ in month_labels]
        t.add_row(r["service"], *cells, f"[bold]${r['total']:,.2f}[/bold]")

    console.print(t)
    console.print("[dim]Forecast generated by AWS Cost Explorer ML model (parallel per-service calls).[/dim]")


def render_cost_forecast_by_service_csv(svc_results: list[dict]) -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow(["service", "period_start", "period_end", "projected_usd", "low_usd", "high_usd"])
    for r in svc_results:
        for m in r.get("monthly", []):
            writer.writerow([
                r["service"],
                m["start"], m["end"],
                f"{m['amount']:.10g}",
                f"{m['lower']:.10g}",
                f"{m['upper']:.10g}",
            ])


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

def render_budgets(budget_list: list) -> None:
    if not budget_list:
        console.print("[dim]No budgets configured for this account.[/dim]")
        return

    t = Table(box=box.ROUNDED, show_lines=False, title="[bold]AWS Budgets[/bold]")
    t.add_column("Name",        style="bold",   min_width=24)
    t.add_column("Type",        style="dim",    no_wrap=True)
    t.add_column("Period",      style="dim",    no_wrap=True)
    t.add_column("Budget",      justify="right", style="yellow", no_wrap=True)
    t.add_column("Actual",      justify="right", style="cyan",   no_wrap=True)
    t.add_column("Forecast",    justify="right", style="dim",    no_wrap=True)
    t.add_column("Used %",      justify="right", no_wrap=True)
    t.add_column("Status",      justify="center", no_wrap=True)

    for b in sorted(budget_list, key=lambda x: x.pct_used, reverse=True):
        pct = b.pct_used
        pct_style = "bold red" if pct >= 100 else "yellow" if pct >= 80 else "green"
        status_style = "bold red" if b.status == "EXCEEDED" else "yellow" if b.status == "WARNING" else "green"
        t.add_row(
            b.name,
            b.budget_type,
            b.time_unit,
            f"${b.budgeted:,.2f}",
            f"${b.actual_spend:,.2f}",
            f"${b.forecasted_spend:,.2f}" if b.forecasted_spend else "[dim]—[/dim]",
            Text(f"{pct:.1f}%", style=pct_style),
            Text(b.status, style=status_style),
        )

    console.print(t)
    console.print(f"\n[dim]{len(budget_list)} budget(s) configured.[/dim]")


def render_budgets_csv(budget_list: list) -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "name", "type", "time_unit", "budget_usd",
        "actual_usd", "forecast_usd", "pct_used", "status",
    ])
    for b in budget_list:
        writer.writerow([
            b.name, b.budget_type, b.time_unit,
            f"{b.budgeted:.10g}", f"{b.actual_spend:.10g}",
            f"{b.forecasted_spend:.10g}", f"{b.pct_used:.2f}", b.status,
        ])


# ---------------------------------------------------------------------------
# Anomalies
# ---------------------------------------------------------------------------

def render_anomalies(anomaly_list: list) -> None:
    if not anomaly_list:
        console.print("[dim]No cost anomalies found for the specified period.[/dim]")
        return

    t = Table(box=box.ROUNDED, show_lines=True, title="[bold]Cost Anomalies[/bold]")
    t.add_column("Start",       style="dim",   no_wrap=True)
    t.add_column("End",         style="dim",   no_wrap=True)
    t.add_column("Service",     style="bold",  min_width=20)
    t.add_column("Region",      style="dim",   no_wrap=True)
    t.add_column("Account",     style="dim",   no_wrap=True)
    t.add_column("Total Impact", justify="right", style="red",    no_wrap=True)
    t.add_column("Max Impact",  justify="right", style="dim",    no_wrap=True)
    t.add_column("Expected",    justify="right", style="dim",    no_wrap=True)
    t.add_column("Root Cause",  style="dim",   max_width=40)

    for a in anomaly_list:
        t.add_row(
            a.start_date[:10] if a.start_date else "—",
            a.end_date[:10]   if a.end_date   else "—",
            a.service or "—",
            a.region  or "—",
            a.account_id[:12] + "…" if len(a.account_id) > 12 else (a.account_id or "—"),
            f"[bold red]+${a.impact_total:,.2f}[/bold red]",
            f"${a.impact_max:,.2f}",
            f"${a.expected:,.2f}",
            a.root_cause or "—",
        )

    console.print(t)
    total_impact = sum(a.impact_total for a in anomaly_list)
    label = "anomaly" if len(anomaly_list) == 1 else "anomalies"
    console.print(
        f"\n[dim]{len(anomaly_list)} {label}  •  "
        f"Total impact: [bold red]${total_impact:,.2f}[/bold red][/dim]"
    )


def render_anomalies_csv(anomaly_list: list) -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "anomaly_id", "start_date", "end_date", "service", "region",
        "account_id", "impact_total", "impact_max", "expected", "root_cause",
    ])
    for a in anomaly_list:
        writer.writerow([
            a.anomaly_id, a.start_date, a.end_date, a.service, a.region,
            a.account_id, f"{a.impact_total:.10g}", f"{a.impact_max:.10g}",
            f"{a.expected:.10g}", a.root_cause,
        ])


# ---------------------------------------------------------------------------
# Optimize — Savings Plans
# ---------------------------------------------------------------------------

def render_savings_plans(summary) -> None:
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    t.add_column("k", style="bold cyan")
    t.add_column("v")

    util_style = "green" if summary.utilization_pct >= 80 else "yellow" if summary.utilization_pct >= 60 else "red"
    cov_style  = "green" if summary.coverage_pct >= 80 else "yellow" if summary.coverage_pct >= 60 else "red"

    t.add_row("Period",        f"{summary.period_start} → {summary.period_end}")
    t.add_row("Utilization",   Text(f"{summary.utilization_pct:.1f}%", style=util_style))
    t.add_row("Coverage",      Text(f"{summary.coverage_pct:.1f}%", style=cov_style))
    t.add_row("SP Spend",      f"${summary.sp_spend:,.2f}")
    t.add_row("On-demand Eq.", f"${summary.on_demand_equiv:,.2f}")
    t.add_row("Net Savings",   f"[bold green]${summary.net_savings:,.2f}[/bold green]")

    console.print(Panel(t, title="[bold]Savings Plans[/bold]", expand=False))

    if summary.utilization_pct < 80:
        console.print(
            "[yellow]⚠ Low utilization — you may have over-committed to Savings Plans.[/yellow]"
        )
    if summary.coverage_pct < 70:
        console.print(
            "[yellow]⚠ Low coverage — consider purchasing additional Savings Plans.[/yellow]"
        )


# ---------------------------------------------------------------------------
# Optimize — Reserved Instances
# ---------------------------------------------------------------------------

def render_ri(summaries: list) -> None:
    if not summaries:
        console.print("[dim]No Reserved Instance data found for the specified period.[/dim]")
        return

    t = Table(box=box.ROUNDED, show_lines=False, title="[bold]Reserved Instance Summary[/bold]")
    t.add_column("Service",      style="bold",   min_width=20)
    t.add_column("Utilization",  justify="right", no_wrap=True)
    t.add_column("Coverage",     justify="right", no_wrap=True)
    t.add_column("RI Cost",      justify="right", style="dim",    no_wrap=True)
    t.add_column("On-Demand",    justify="right", style="dim",    no_wrap=True)
    t.add_column("Net Savings",  justify="right", style="green",  no_wrap=True)

    for s in summaries:
        util_style = "green" if s.utilization_pct >= 80 else "yellow" if s.utilization_pct >= 60 else "red"
        cov_style  = "green" if s.coverage_pct >= 80 else "yellow" if s.coverage_pct >= 60 else "red"
        t.add_row(
            s.service,
            Text(f"{s.utilization_pct:.1f}%", style=util_style),
            Text(f"{s.coverage_pct:.1f}%",    style=cov_style),
            f"${s.ri_cost:,.2f}",
            f"${s.on_demand_cost:,.2f}",
            f"${s.net_savings:,.2f}",
        )

    console.print(t)


# ---------------------------------------------------------------------------
# Optimize — Rightsizing
# ---------------------------------------------------------------------------

def render_rightsizing(recs: list) -> None:
    if not recs:
        console.print("[dim]No rightsizing recommendations available.[/dim]")
        console.print(
            "[dim]Note: CE rightsizing requires at least 14 days of CloudWatch metrics "
            "for EC2 instances.[/dim]"
        )
        return

    t = Table(box=box.ROUNDED, show_lines=False, title="[bold]EC2 Rightsizing Recommendations[/bold]")
    t.add_column("Resource ID",    style="dim",   no_wrap=True)
    t.add_column("Region",         style="dim",   no_wrap=True)
    t.add_column("Current Type",   style="bold",  no_wrap=True)
    t.add_column("Action",         style="yellow", no_wrap=True)
    t.add_column("Target Type",    style="cyan",  no_wrap=True)
    t.add_column("Est. Savings",   justify="right", style="green", no_wrap=True)
    t.add_column("Savings %",      justify="right", style="green", no_wrap=True)

    total_savings = 0.0
    for r in recs:
        action_style = "red" if r.recommended_action == "Terminate" else "yellow"
        t.add_row(
            r.resource_id[:20] + "…" if len(r.resource_id) > 20 else r.resource_id,
            r.region or "—",
            r.current_instance,
            Text(r.recommended_action, style=action_style),
            r.target_instance or "—",
            f"${r.estimated_savings:,.2f}/mo",
            f"{r.estimated_savings_pct:.1f}%",
        )
        total_savings += r.estimated_savings

    console.print(t)
    console.print(
        f"\n[dim]{len(recs)} recommendation(s)  •  "
        f"Total estimated savings: [bold green]${total_savings:,.2f}/mo[/bold green][/dim]"
    )

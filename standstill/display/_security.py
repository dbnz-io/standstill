from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from standstill.aws.security_services import (
    AccountAssessment,
    DelegationStatus,
    MemberServiceStatus,
    ServiceApplyResult,
    ServiceStatus,
)

console = Console()

# ---------------------------------------------------------------------------
# Label maps
# ---------------------------------------------------------------------------

_SVC_LABELS = {
    "guardduty":       "GuardDuty",
    "security_hub":    "Security Hub",
    "macie":           "Macie",
    "inspector":       "Inspector",
    "access_analyzer": "Access Analyzer",
    "security_lake":   "Security Lake",
}

_DELEGATION_ACTION_STYLES = {
    "register": ("register", "bold yellow"),
    "skip":     ("already registered", "dim"),
    "conflict": ("CONFLICT", "bold red"),
    "error":    ("error", "bold red"),
}

# Ordered columns for the assessment table (org-wide services last)
_ASSESS_SVCS = ["guardduty", "security_hub", "macie", "inspector", "access_analyzer", "security_lake"]
_ASSESS_SHORT = {
    "guardduty":       "GD",
    "security_hub":    "SH",
    "macie":           "Macie",
    "inspector":       "Insp",
    "access_analyzer": "AA",
    "security_lake":   "Lake",
}

# Sentinels that mean "this account is special — not a regular member"
_SPECIAL_STATUSES = {"delegated_admin", "management_account", "org_wide"}


# ---------------------------------------------------------------------------
# Security services — plan / results / status
# ---------------------------------------------------------------------------

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

def _assess_icon(status: MemberServiceStatus, svc: str) -> Text:
    if status.error:
        return Text("!", style="bold yellow")
    if status.member_status in _SPECIAL_STATUSES:
        if status.member_status == "delegated_admin":
            return Text("★", style="bold cyan")   # admin account itself
        if status.member_status == "management_account":
            return Text("M", style="dim")          # management account
        return Text("~", style="dim")              # org_wide
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
# Security Lake — Athena views
# ---------------------------------------------------------------------------

def render_lake_view_results(results: list, database: str) -> None:
    from standstill.aws.lake import SOURCE_LABELS, SOURCE_VIEW_NAMES

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Source", style="bold")
    t.add_column("View", style="cyan", no_wrap=True)
    t.add_column("Result", justify="center", no_wrap=True)
    t.add_column("Detail", style="dim")

    for r in results:
        label = SOURCE_LABELS.get(r.source, r.source)
        icon = Text("✓", style="bold green") if r.success else Text("✗", style="bold red")
        t.add_row(label, f"{database}.{r.view_name}", icon, r.message)

    console.print(t)

    ok = sum(1 for r in results if r.success)
    fail = len(results) - ok
    console.print(
        f"\n[green]{ok} view(s) created[/green]"
        + (f"  [bold red]{fail} failed[/bold red]" if fail else "")
    )

    if ok:
        console.print(
            "\n[dim]Query example (CloudTrail):\n"
            f"  SELECT event_time, account_id, user_name, api_call, source_ip, error_code\n"
            f"  FROM {database}.cloudtrail\n"
            f"  WHERE eventday = '20260429' AND error_code IS NOT NULL\n"
            f"  ORDER BY event_time DESC\n"
            f"  LIMIT 50[/dim]"
        )


def render_lake_status(wg, tables: list, views: list[str], database: str, region: str) -> None:
    from standstill.aws.lake import SOURCE_LABELS, SOURCE_VIEW_NAMES

    # Workgroup panel
    wg_t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    wg_t.add_column("k", style="bold cyan")
    wg_t.add_column("v")
    wg_t.add_row("Workgroup", wg.name)
    if wg.error:
        wg_t.add_row("Status", Text(f"error: {wg.error}", style="bold red"))
    else:
        wg_t.add_row("State", wg.state)
        wg_t.add_row(
            "Output location",
            wg.output_location or Text("not set", style="bold yellow"),
        )
        wg_t.add_row("Enforce config", str(wg.enforce_config))
    console.print(Panel(wg_t, title="[bold]Athena Workgroup[/bold]", expand=False))

    # Tables + views combined
    t = Table(box=box.ROUNDED, show_lines=False, title="[bold]Security Lake Sources[/bold]")
    t.add_column("Source", style="bold")
    t.add_column("Glue Table", style="dim")
    t.add_column("Table", justify="center", no_wrap=True)
    t.add_column("View", justify="center", no_wrap=True)
    t.add_column(f"View name ({database}.*)", style="cyan")

    table_map = {tbl.source: tbl for tbl in tables}

    for source, label in SOURCE_LABELS.items():
        tbl = table_map.get(source)
        view_name = SOURCE_VIEW_NAMES[source]
        has_table = tbl is not None
        has_view = view_name in views

        table_icon = Text("✓", style="bold green") if has_table else Text("—", style="dim")
        view_icon  = Text("✓", style="bold green") if has_view  else Text("—", style="dim")
        table_name = tbl.table_name if tbl else "[dim]not found[/dim]"
        view_str   = view_name if has_view else "[dim]not created[/dim]"

        t.add_row(label, table_name, table_icon, view_icon, view_str)

    console.print(t)

    if not any(table_map):
        console.print(
            "\n[yellow]No Security Lake tables found for region "
            f"[bold]{region}[/bold].[/yellow]\n"
            "[dim]Ensure Security Lake is enabled and you are using the correct "
            "delegated admin account.[/dim]"
        )
    elif not views:
        console.print(
            f"\n[dim]No views created yet. Run:\n"
            f"  standstill lake create-views[/dim]"
        )

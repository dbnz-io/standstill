from __future__ import annotations

import csv
import sys

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Label maps
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


# ---------------------------------------------------------------------------
# Cost Explorer — tables
# ---------------------------------------------------------------------------

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

    all_keys = sorted(
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


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

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
    console.print(Panel(meta, title="[bold]CloudTrail Scan[/bold]", expand=False))

    if not result.events:
        console.print("[dim]No events found for the specified period.[/dim]")
        return

    # ── identity attribution ─────────────────────────────────────────────────
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


# ---------------------------------------------------------------------------
# Cost forecast CSV + by-service forecast
# ---------------------------------------------------------------------------

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


def render_cost_forecast_by_service(svc_results: list[dict], metric: str) -> None:
    """Render a per-service forecast as a matrix: rows = services, cols = months."""
    if not svc_results:
        console.print("[dim]No forecast data available.[/dim]")
        return

    metric_label = _COST_METRIC_LABELS.get(metric, metric.title())

    month_labels: list[tuple[str, str]] = []
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

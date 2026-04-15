from __future__ import annotations

from datetime import date, timedelta
from enum import Enum
from typing import Annotated, List, Optional

import typer
from rich.console import Console

from standstill import config as _config
from standstill import state as _state
from standstill.aws import cloudtrail_scan
from standstill.aws import cost as cost_api
from standstill.display import renderer

err = Console(stderr=True)

app = typer.Typer(
    no_args_is_help=True,
    help="Review AWS costs via Cost Explorer.",
    rich_markup_mode="rich",
)


# ---------------------------------------------------------------------------
# Option enums
# ---------------------------------------------------------------------------

class Granularity(str, Enum):
    monthly = "monthly"
    daily   = "daily"


class Metric(str, Enum):
    unblended = "unblended"
    blended   = "blended"
    amortized = "amortized"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _first_of_month() -> str:
    return date.today().replace(day=1).isoformat()


def _today() -> str:
    return date.today().isoformat()


def _validate_dates(start: str, end: str) -> None:
    try:
        s = date.fromisoformat(start)
        e = date.fromisoformat(end)
    except ValueError as exc:
        err.print(f"[bold red]Error:[/bold red] Invalid date: {exc}")
        raise typer.Exit(1)
    if s >= e:
        err.print("[bold red]Error:[/bold red] --start must be before --end.")
        raise typer.Exit(1)


def _parse_group_by(value: str) -> str:
    """Validate group-by: fixed dimensions or tag:KEY."""
    valid = {"service", "usage-type", "account", "region"}
    if value in valid or value.startswith("tag:"):
        return value
    raise typer.BadParameter(
        f"Valid options: {', '.join(sorted(valid))}, or tag:KEY (e.g. tag:Environment)"
    )


def _parse_raw_filters(
    raw: list[str],
    service: str | None,
) -> list[tuple[str, str]]:
    """
    Parse ``--filter KEY=VALUE`` strings and the ``--service`` shortcut into
    a list of ``(dimension, raw_value)`` pairs.  Values are not yet resolved
    against the CE service list — call :func:`_resolve_filters` for that.
    """
    parsed: list[tuple[str, str]] = []

    for item in raw:
        if "=" not in item:
            err.print(
                f"[bold red]Error:[/bold red] --filter must be KEY=VALUE, got: '{item}'\n"
                "  Example: --filter service=ec2   or   --filter region=us-east-1"
            )
            raise typer.Exit(1)
        key, _, value = item.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if not key or not value:
            err.print(f"[bold red]Error:[/bold red] Both key and value are required: '{item}'")
            raise typer.Exit(1)
        if value.lower() == "all":
            continue  # explicit "no filter" — skip this dimension
        parsed.append((key, value))

    if service:
        parsed.append(("service", service))

    return parsed


def _resolve_filters(
    ce,
    raw: list[tuple[str, str]],
    start: str,
    end: str,
) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """
    Resolve raw ``(dimension, value)`` pairs into ``(dimension, [exact_values])``.

    For the ``service`` dimension, :func:`cost_api.resolve_service_filter` is
    called to expand short names (e.g. ``"ec2"``) into the actual CE service
    names for the period.

    Returns the resolved filters and a list of human-readable resolution notes
    (printed when a short name expanded to multiple services).
    """
    resolved: list[tuple[str, list[str]]] = []
    notes: list[str] = []

    for dim, value in raw:
        if dim == "service":
            matches = cost_api.resolve_service_filter(ce, value, start, end)
            if len(matches) > 1 or (len(matches) == 1 and matches[0] != value):
                notes.append(
                    f"[dim]service=[/dim][cyan]{value}[/cyan][dim] → "
                    + ", ".join(f'"{m}"' for m in matches)
                    + "[/dim]"
                )
            resolved.append((dim, matches))
        else:
            resolved.append((dim, [value]))

    return resolved, notes


def _ce():
    """Return a CE client pinned to us-east-1 (the only supported endpoint)."""
    return _state.state.get_client("ce", region_name="us-east-1")


# ---------------------------------------------------------------------------
# cost report
# ---------------------------------------------------------------------------

@app.command("report")
def report(
    start: Annotated[
        Optional[str],
        typer.Option("--start", "-s", help="Start date (YYYY-MM-DD). Defaults to first day of current month."),
    ] = None,
    end: Annotated[
        Optional[str],
        typer.Option("--end", "-e", help="End date exclusive (YYYY-MM-DD). Defaults to today."),
    ] = None,
    group_by: Annotated[
        str,
        typer.Option(
            "--group-by", "-g",
            help="Dimension to group by: service | usage-type | account | region | tag:KEY",
            callback=lambda v: _parse_group_by(v),
        ),
    ] = "service",
    service: Annotated[
        Optional[str],
        typer.Option(
            "--service", "-S",
            help="Shortcut for [bold]--filter service=NAME[/bold]. "
                 "Run [bold]standstill cost services[/bold] to list exact names.",
        ),
    ] = None,
    filter_: Annotated[
        Optional[List[str]],
        typer.Option(
            "--filter", "-f",
            help=(
                "Extra dimension filter as KEY=VALUE (repeatable, ANDed together). "
                "Keys: service, region, account, usage-type, az, instance-type, "
                "operation, platform, purchase-type, tag:KEY."
            ),
        ),
    ] = None,
    granularity: Annotated[
        Granularity,
        typer.Option("--granularity", help="Time bucket size."),
    ] = Granularity.monthly,
    top: Annotated[
        Optional[int],
        typer.Option("--top", "-n", help="Show only the top N entries by cost per period."),
    ] = None,
    min_cost: Annotated[
        float,
        typer.Option("--min-cost", help="Exclude entries with cost below this amount (USD)."),
    ] = 0.01,
    metric: Annotated[
        Metric,
        typer.Option("--metric", "-m", help="Cost metric to use."),
    ] = Metric.unblended,
    compare: Annotated[
        bool,
        typer.Option("--compare", help="Include the prior equivalent period for comparison."),
    ] = False,
) -> None:
    """
    Cost report grouped by service, usage type, account, region, or tag.

    \b
    Common patterns:

      # All services this month
      standstill cost report

      # Last 3 months by service
      standstill cost report -s 2024-01-01 -e 2024-04-01

      # Break down EC2 by usage type
      standstill cost report -g usage-type -S ec2

      # Group by tag
      standstill cost report -g tag:Environment

      # Filter by tag value
      standstill cost report --filter tag:Team=platform

      # Multi-account spend, top 10
      standstill cost report -g account --top 10

      # Compare this month to last month
      standstill cost report --compare
    """
    start = start or _first_of_month()
    end = end or _today()
    _validate_dates(start, end)

    raw_filters = _parse_raw_filters(filter_ or [], service)

    ce = _ce()

    with renderer.console.status("[bold]Fetching cost data…[/bold]"):
        try:
            resolved_filters, resolution_notes = _resolve_filters(ce, raw_filters, start, end)
            periods = cost_api.get_cost_and_usage(
                ce,
                start=start,
                end=end,
                granularity=granularity.value.upper(),
                dimension=group_by,
                filters=resolved_filters,
                metric=metric.value,
                top=top,
                min_cost=min_cost,
            )

            # Fetch prior period for comparison if requested.
            prior_periods = None
            if compare:
                prior_start, prior_end = cost_api.compute_prior_period(start, end)
                prior_periods = cost_api.get_cost_and_usage(
                    ce,
                    start=prior_start,
                    end=prior_end,
                    granularity=granularity.value.upper(),
                    dimension=group_by,
                    filters=resolved_filters,
                    metric=metric.value,
                    min_cost=min_cost,
                )

            # Resolve account names when grouped by account.
            account_names: dict[str, str] = {}
            if group_by == "account":
                try:
                    from standstill.aws.organizations import account_id_to_name_map
                    account_names = account_id_to_name_map()
                except Exception:  # noqa: BLE001
                    pass  # non-fatal — IDs will be shown as-is

        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    for note in resolution_notes:
        renderer.console.print(note)

    if _state.state.output == "json":
        renderer.render_json({
            "filters": [
                {"dimension": k, "values": vs} for k, vs in resolved_filters
            ],
            "periods": [
                {
                    "start":     p.start,
                    "end":       p.end,
                    "estimated": p.estimated,
                    "total":     p.total,
                    "unit":      p.unit,
                    "groups": [
                        {"key": g.key, "amount": g.amount, "unit": g.unit}
                        for g in p.groups
                    ],
                }
                for p in periods
            ],
        })
        return

    if _state.state.output == "csv":
        renderer.render_cost_report_csv(periods, group_by=group_by)
        return

    renderer.render_cost_report(
        periods,
        group_by=group_by,
        metric=metric.value,
        granularity=granularity.value,
        account_names=account_names,
        prior_periods=prior_periods,
    )


# ---------------------------------------------------------------------------
# cost services
# ---------------------------------------------------------------------------

@app.command("services")
def services(
    start: Annotated[
        Optional[str],
        typer.Option("--start", "-s", help="Start date (YYYY-MM-DD). Defaults to first day of current month."),
    ] = None,
    end: Annotated[
        Optional[str],
        typer.Option("--end", "-e", help="End date exclusive (YYYY-MM-DD). Defaults to today."),
    ] = None,
    metric: Annotated[
        Metric,
        typer.Option("--metric", "-m", help="Cost metric to use."),
    ] = Metric.unblended,
) -> None:
    """
    List AWS services that incurred costs in the given period.

    Use this to discover exact service names for [bold]cost report --service[/bold].
    Results are ordered by cost (highest first) and include total spend per service.
    """
    start = start or _first_of_month()
    end = end or _today()
    _validate_dates(start, end)

    ce = _ce()
    with renderer.console.status("[bold]Fetching services…[/bold]"):
        try:
            svc_list = cost_api.list_services(ce, start=start, end=end)
            svc_costs = cost_api.get_service_costs(ce, start=start, end=end, metric=metric.value)
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if _state.state.output == "json":
        renderer.render_json([
            {"service": s, "cost_usd": svc_costs.get(s, 0.0)}
            for s in svc_list
        ])
        return

    if _state.state.output == "csv":
        renderer.render_cost_services_csv(svc_list, svc_costs=svc_costs)
        return

    renderer.render_cost_services(svc_list, start=start, end=end, svc_costs=svc_costs)


# ---------------------------------------------------------------------------
# cost forecast
# ---------------------------------------------------------------------------

@app.command("forecast")
def forecast(
    months: Annotated[
        int,
        typer.Option("--months", "-m", help="Number of months ahead to forecast."),
    ] = 3,
    metric: Annotated[
        Metric,
        typer.Option("--metric", help="Cost metric to forecast."),
    ] = Metric.unblended,
    by_service: Annotated[
        bool,
        typer.Option("--by-service", help="Break forecast down by top services (fan-out calls)."),
    ] = False,
    top: Annotated[
        int,
        typer.Option("--top", "-n", help="Number of top services to include when --by-service."),
    ] = 10,
) -> None:
    """
    Forecast future AWS costs based on current usage trends.

    Uses Cost Explorer's ML model to project monthly spend with a
    confidence interval.  Requires at least one full month of billing
    history to produce meaningful results.

    \b
    Examples:

      standstill cost forecast
      standstill cost forecast --by-service --top 5
      standstill cost forecast --months 6 --metric amortized
    """
    today = date.today()
    forecast_start = (today + timedelta(days=1)).isoformat()

    raw_month = today.month + months
    end_year  = today.year + (raw_month - 1) // 12
    end_month = (raw_month - 1) % 12 + 1
    forecast_end = date(end_year, end_month, 1).isoformat()

    with renderer.console.status("[bold]Fetching forecast…[/bold]"):
        try:
            if by_service:
                svc_results = cost_api.get_forecast_by_service(
                    _ce(),
                    start=forecast_start,
                    end=forecast_end,
                    metric=metric.value,
                    top_n=top,
                )
                result = None
            else:
                result = cost_api.get_forecast(
                    _ce(),
                    start=forecast_start,
                    end=forecast_end,
                    metric=metric.value,
                )
                svc_results = None
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if by_service:
        if _state.state.output == "json":
            renderer.render_json(svc_results)
            return
        if _state.state.output == "csv":
            renderer.render_cost_forecast_by_service_csv(svc_results)
            return
        renderer.render_cost_forecast_by_service(svc_results, metric=metric.value)
        return

    if _state.state.output == "json":
        renderer.render_json(result)
        return
    if _state.state.output == "csv":
        renderer.render_cost_forecast_csv(result)
        return
    renderer.render_cost_forecast(result, metric=metric.value)


# ---------------------------------------------------------------------------
# cost budgets
# ---------------------------------------------------------------------------

@app.command("budgets")
def budgets() -> None:
    """
    List AWS Budgets and their current spend status.

    Shows each budget's limit, actual spend, forecast, and alert thresholds.
    Requires [bold]budgets:DescribeBudgets[/bold] permission on the management account.
    """
    from standstill.aws import budgets as budgets_api

    with renderer.console.status("[bold]Fetching budgets…[/bold]"):
        try:
            sts = _state.state.get_client("sts")
            account_id = sts.get_caller_identity()["Account"]
            budgets_client = _state.state.get_client("budgets", region_name="us-east-1")
            budget_list = budgets_api.list_budgets(budgets_client, account_id=account_id)
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if _state.state.output == "json":
        import dataclasses
        renderer.render_json([dataclasses.asdict(b) for b in budget_list])
        return

    if _state.state.output == "csv":
        renderer.render_budgets_csv(budget_list)
        return

    renderer.render_budgets(budget_list)


# ---------------------------------------------------------------------------
# cost anomalies
# ---------------------------------------------------------------------------

@app.command("anomalies")
def anomalies(
    days: Annotated[
        int,
        typer.Option("--days", "-d", help="How many days back to look (max 90)."),
    ] = 30,
    min_impact: Annotated[
        float,
        typer.Option("--min-impact", help="Minimum total impact in USD to include."),
    ] = 0.0,
) -> None:
    """
    Show cost anomalies detected by Cost Explorer Anomaly Detection.

    Anomalies are unexpected cost spikes identified by CE's ML model.
    Results are sorted by total impact descending.

    \b
    Examples:

      standstill cost anomalies
      standstill cost anomalies --days 7 --min-impact 50
    """
    with renderer.console.status("[bold]Fetching anomalies…[/bold]"):
        try:
            result = cost_api.get_anomalies(
                _ce(),
                days_back=days,
                min_impact=min_impact,
            )
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if _state.state.output == "json":
        import dataclasses
        renderer.render_json([dataclasses.asdict(a) for a in result])
        return

    if _state.state.output == "csv":
        renderer.render_anomalies_csv(result)
        return

    renderer.render_anomalies(result)


# ---------------------------------------------------------------------------
# cost trail  (configure CloudTrail log target)
# ---------------------------------------------------------------------------

_trail_app = typer.Typer(
    no_args_is_help=True,
    help="Configure the CloudTrail log target used by [bold]cost scan[/bold].",
    rich_markup_mode="rich",
)
app.add_typer(_trail_app, name="trail")


@_trail_app.command("set")
def trail_set(
    s3_bucket: Annotated[
        Optional[str],
        typer.Option("--s3-bucket", help="S3 bucket containing CloudTrail logs."),
    ] = None,
    s3_prefix: Annotated[
        Optional[str],
        typer.Option(
            "--s3-prefix",
            help=(
                "S3 key prefix up to (not including) the date component, "
                "e.g. AWSLogs/123456789012/CloudTrail/us-east-1"
            ),
        ),
    ] = None,
    log_group: Annotated[
        Optional[str],
        typer.Option("--log-group", help="CloudWatch Logs log group name for CloudTrail."),
    ] = None,
) -> None:
    """
    Save the CloudTrail log target used by [bold]cost scan --target s3|cloudwatch[/bold].

    \b
    Examples:

      # S3 target
      standstill cost trail set --s3-bucket my-ct-bucket \\
          --s3-prefix AWSLogs/123456789012/CloudTrail/us-east-1

      # CloudWatch Logs target
      standstill cost trail set --log-group /aws/cloudtrail/management-events
    """
    if not s3_bucket and not log_group:
        err.print(
            "[bold red]Error:[/bold red] Provide at least one of "
            "[bold]--s3-bucket[/bold] or [bold]--log-group[/bold]."
        )
        raise typer.Exit(1)

    if s3_bucket:
        _config.set_trail_s3(bucket=s3_bucket, prefix=s3_prefix or "")
        renderer.console.print(
            f"[bold green]✓[/bold green] S3 target saved: "
            f"[cyan]{s3_bucket}[/cyan] / [dim]{s3_prefix or '(no prefix)'}[/dim]"
        )

    if log_group:
        _config.set_trail_cloudwatch(log_group=log_group)
        renderer.console.print(
            f"[bold green]✓[/bold green] CloudWatch Logs target saved: [cyan]{log_group}[/cyan]"
        )


@_trail_app.command("show")
def trail_show() -> None:
    """Show the currently configured CloudTrail log target(s)."""
    s3_cfg  = _config.get_trail_s3()
    cw_cfg  = _config.get_trail_cloudwatch()

    if not s3_cfg and not cw_cfg:
        renderer.console.print(
            "[dim]No trail targets configured. "
            "Run [bold]standstill cost trail set --help[/bold] to get started.[/dim]"
        )
        return

    renderer.render_trail_config(s3_cfg=s3_cfg, cloudwatch_log_group=cw_cfg)


@_trail_app.command("clear")
def trail_clear(
    s3: Annotated[bool, typer.Option("--s3",         help="Clear the S3 target.")] = False,
    cloudwatch: Annotated[bool, typer.Option("--cloudwatch", help="Clear the CloudWatch target.")] = False,
) -> None:
    """Remove a saved CloudTrail log target."""
    if not s3 and not cloudwatch:
        err.print("[bold red]Error:[/bold red] Specify [bold]--s3[/bold] or [bold]--cloudwatch[/bold] (or both).")
        raise typer.Exit(1)
    if s3:
        _config.unset_trail_s3()
        renderer.console.print("[dim]S3 target cleared.[/dim]")
    if cloudwatch:
        _config.unset_trail_cloudwatch()
        renderer.console.print("[dim]CloudWatch target cleared.[/dim]")


# ---------------------------------------------------------------------------
# cost scan  (nested sub-app)
# ---------------------------------------------------------------------------

_scan_app = typer.Typer(
    no_args_is_help=True,
    help="Scan CloudTrail event history correlated with a cost usage type.",
    rich_markup_mode="rich",
)
app.add_typer(_scan_app, name="scan")


class ScanTarget(str, Enum):
    event_history = "event-history"
    s3            = "s3"
    cloudwatch    = "cloudwatch"


@_scan_app.command("usage-type")
def scan_usage_type(
    usage_type: Annotated[
        str,
        typer.Argument(help="CE usage type to scan, e.g. CW:Requests or USE1-CW:Requests."),
    ],
    start: Annotated[
        Optional[str],
        typer.Option("--start", "-s", help="Start date (YYYY-MM-DD). Defaults to 7 days ago."),
    ] = None,
    end: Annotated[
        Optional[str],
        typer.Option("--end", "-e", help="End date (YYYY-MM-DD). Defaults to today."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Max total events to retrieve."),
    ] = 200,
    target: Annotated[
        ScanTarget,
        typer.Option(
            "--target", "-t",
            help=(
                "Log source to query. "
                "[bold]event-history[/bold] uses the CloudTrail API (last 90 days, management events). "
                "[bold]s3[/bold] scans logs in the configured S3 bucket. "
                "[bold]cloudwatch[/bold] queries the configured CloudWatch Logs log group."
            ),
        ),
    ] = ScanTarget.event_history,
) -> None:
    """
    Query CloudTrail logs for all API calls linked to a usage type.

    \b
    Examples:

      standstill cost scan usage-type CW:Requests
      standstill cost scan usage-type CW:Requests --target cloudwatch
      standstill cost scan usage-type S3-Requests-Tier1 --target s3 -s 2024-03-01 -e 2024-04-01
      standstill -o json cost scan usage-type Lambda-Requests
      standstill -o csv  cost scan usage-type CloudTrail-DataEvent-S3 --target s3 > events.csv
    """
    from datetime import datetime, timezone

    from standstill.aws.usage_type_map import _REGION_PREFIX_RE, get_event_source, get_usage_type_info

    # Resolve dates.
    today = date.today()
    start_dt = datetime.fromisoformat(start).replace(tzinfo=timezone.utc) if start else \
               datetime(today.year, today.month, today.day, tzinfo=timezone.utc) - timedelta(days=7)
    end_dt   = datetime.fromisoformat(end).replace(tzinfo=timezone.utc) if end else \
               datetime(today.year, today.month, today.day, 23, 59, 59, tzinfo=timezone.utc)

    if start_dt >= end_dt:
        err.print("[bold red]Error:[/bold red] --start must be before --end.")
        raise typer.Exit(1)

    # Look up usage type metadata.
    base = _REGION_PREFIX_RE.sub("", usage_type)
    info = get_usage_type_info(base)

    if info is None:
        err.print(
            f"[bold red]Error:[/bold red] Unknown usage type '[cyan]{usage_type}[/cyan]'.\n"
            "  Run [bold]standstill cost report -g usage-type[/bold] to see active types."
        )
        raise typer.Exit(1)

    event_source = get_event_source(info.service)
    if event_source is None:
        err.print(
            f"[bold red]Error:[/bold red] No CloudTrail event source mapped for service "
            f"'[cyan]{info.service}[/cyan]'."
        )
        raise typer.Exit(1)

    api_calls = info.api_calls

    # ── validate target-specific config ─────────────────────────────────────
    if target == ScanTarget.s3:
        s3_cfg = _config.get_trail_s3()
        if not s3_cfg:
            err.print(
                "[bold red]Error:[/bold red] No S3 target configured.\n"
                "  Run: [bold]standstill cost trail set --s3-bucket BUCKET --s3-prefix PREFIX[/bold]"
            )
            raise typer.Exit(1)

    if target == ScanTarget.cloudwatch:
        cw_cfg = _config.get_trail_cloudwatch()
        if not cw_cfg:
            err.print(
                "[bold red]Error:[/bold red] No CloudWatch Logs target configured.\n"
                "  Run: [bold]standstill cost trail set --log-group LOG_GROUP[/bold]"
            )
            raise typer.Exit(1)

    # ── run the scan ─────────────────────────────────────────────────────────
    _s3_bucket = (_config.get_trail_s3() or {}).get("bucket", "")
    _cw_group  = _config.get_trail_cloudwatch() or ""
    target_label = {
        ScanTarget.event_history: "CloudTrail Event History API",
        ScanTarget.s3:            f"S3 ({_s3_bucket})",
        ScanTarget.cloudwatch:    f"CloudWatch Logs ({_cw_group})",
    }[target]

    with renderer.console.status(
        f"[bold]Scanning [cyan]{usage_type}[/cyan] via {target_label}…[/bold]"
    ):
        try:
            if target == ScanTarget.event_history:
                result = cloudtrail_scan.scan(
                    _state.state.get_client("cloudtrail"),
                    usage_type   = usage_type,
                    event_source = event_source,
                    api_calls    = api_calls,
                    start        = start_dt,
                    end          = end_dt,
                    max_events   = limit,
                )
            elif target == ScanTarget.s3:
                s3_cfg = _config.get_trail_s3()
                result = cloudtrail_scan.scan_s3(
                    _state.state.get_client("s3"),
                    usage_type   = usage_type,
                    event_source = event_source,
                    api_calls    = api_calls,
                    start        = start_dt,
                    end          = end_dt,
                    bucket       = s3_cfg["bucket"],
                    key_prefix   = s3_cfg.get("prefix", ""),
                    max_events   = limit,
                )
            else:  # cloudwatch
                result = cloudtrail_scan.scan_cloudwatch(
                    _state.state.get_client("logs"),
                    usage_type   = usage_type,
                    event_source = event_source,
                    api_calls    = api_calls,
                    start        = start_dt,
                    end          = end_dt,
                    log_group    = _config.get_trail_cloudwatch(),
                    max_events   = limit,
                )
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if _state.state.output == "json":
        renderer.render_json({**result.to_dict(), "target": target.value})
        return

    if _state.state.output == "csv":
        renderer.render_scan_csv(result)
        return

    renderer.render_scan_result(result, target=target.value)


# ---------------------------------------------------------------------------
# cost optimize  (nested sub-app)
# ---------------------------------------------------------------------------

_optimize_app = typer.Typer(
    no_args_is_help=True,
    help="Savings Plans, Reserved Instance, and rightsizing recommendations.",
    rich_markup_mode="rich",
)
app.add_typer(_optimize_app, name="optimize")


@_optimize_app.command("savings-plans")
def optimize_savings_plans(
    start: Annotated[
        Optional[str],
        typer.Option("--start", "-s", help="Start date (YYYY-MM-DD). Defaults to first day of current month."),
    ] = None,
    end: Annotated[
        Optional[str],
        typer.Option("--end", "-e", help="End date exclusive (YYYY-MM-DD). Defaults to today."),
    ] = None,
) -> None:
    """
    Show Savings Plans utilization and coverage for the period.

    Helps identify whether existing SP commitments are being used efficiently
    and how much eligible spend is still not covered.
    """
    from standstill.aws import optimize as optimize_api

    start = start or _first_of_month()
    end = end or _today()
    _validate_dates(start, end)

    with renderer.console.status("[bold]Fetching Savings Plans data…[/bold]"):
        try:
            summary = optimize_api.get_savings_plans_summary(_ce(), start=start, end=end)
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if _state.state.output == "json":
        import dataclasses
        renderer.render_json(dataclasses.asdict(summary))
        return

    renderer.render_savings_plans(summary)


@_optimize_app.command("reserved")
def optimize_reserved(
    start: Annotated[
        Optional[str],
        typer.Option("--start", "-s", help="Start date (YYYY-MM-DD). Defaults to first day of current month."),
    ] = None,
    end: Annotated[
        Optional[str],
        typer.Option("--end", "-e", help="End date exclusive (YYYY-MM-DD). Defaults to today."),
    ] = None,
) -> None:
    """
    Show Reserved Instance utilization and coverage by service.

    Low utilization means you are paying for unused reservations.
    Low coverage means on-demand instances are running that could be reserved.
    """
    from standstill.aws import optimize as optimize_api

    start = start or _first_of_month()
    end = end or _today()
    _validate_dates(start, end)

    with renderer.console.status("[bold]Fetching Reserved Instance data…[/bold]"):
        try:
            summaries = optimize_api.get_ri_summary(_ce(), start=start, end=end)
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if _state.state.output == "json":
        import dataclasses
        renderer.render_json([dataclasses.asdict(s) for s in summaries])
        return

    renderer.render_ri(summaries)


@_optimize_app.command("rightsizing")
def optimize_rightsizing() -> None:
    """
    Show EC2 rightsizing recommendations from Cost Explorer.

    Identifies over-provisioned instances that can be downsized or terminated
    to reduce costs.  Only EC2 is supported by the CE rightsizing API.
    """
    from standstill.aws import optimize as optimize_api

    with renderer.console.status("[bold]Fetching rightsizing recommendations…[/bold]"):
        try:
            recs = optimize_api.get_rightsizing_recommendations(_ce())
        except Exception as exc:  # noqa: BLE001
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if _state.state.output == "json":
        import dataclasses
        renderer.render_json([dataclasses.asdict(r) for r in recs])
        return

    renderer.render_rightsizing(recs)

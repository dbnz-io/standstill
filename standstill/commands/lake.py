from __future__ import annotations

import re
from typing import Annotated, Optional

import typer
from rich.console import Console

import standstill.config as _config
from standstill import state as _state
from standstill.aws import lake as lake_api
from standstill.display import renderer

app = typer.Typer(no_args_is_help=True, help="Manage Security Lake Athena access and OCSF views.")
err = Console(stderr=True)

_DEFAULT_ROLE = "AWSControlTowerExecution"
_ACCT_RE = re.compile(r"^\d{12}$")


def _resolve_admin(account: str | None) -> str | None:
    return account or _config.get_delegated_admin()


def _require_admin(account: str | None) -> str:
    admin = _resolve_admin(account)
    if not admin:
        err.print(
            "[bold red]Error:[/bold red] Delegated admin account not set.\n"
            "[dim]Provide --account <id> or run: standstill config set-delegated-admin <id>[/dim]"
        )
        raise typer.Exit(1)
    if not _ACCT_RE.match(admin):
        err.print(f"[bold red]Error:[/bold red] Invalid account ID: {admin}")
        raise typer.Exit(1)
    return admin


# ---------------------------------------------------------------------------
# setup-athena
# ---------------------------------------------------------------------------

@app.command("setup-athena")
def setup_athena(
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Delegated admin account ID."),
    ] = None,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role in the admin account."),
    ] = _DEFAULT_ROLE,
    workgroup: Annotated[
        str,
        typer.Option("--workgroup", "-w", help="Athena workgroup name."),
    ] = lake_api.DEFAULT_WORKGROUP,
) -> None:
    """
    Configure the Athena output S3 bucket for Security Lake queries.

    \b
    Interactively choose an existing bucket or create a new one, then
    sets it as the output location on the target Athena workgroup.
    Assumes the CT execution role in the delegated admin account.
    """
    console = renderer.console
    admin = _require_admin(account)
    region = _state.state.region or "us-east-1"

    # ── Show current workgroup config ────────────────────────────────────────
    with console.status(f"[bold]Reading workgroup '{workgroup}'...[/bold]"):
        wg = lake_api.get_workgroup(workgroup, admin, role_name, region)

    if wg.error:
        err.print(f"[bold red]Error reading workgroup:[/bold red] {wg.error}")
        raise typer.Exit(1)

    if wg.output_location:
        console.print(
            f"[dim]Current output location:[/dim] [cyan]{wg.output_location}[/cyan]"
        )
    else:
        console.print("[dim]No output location configured on this workgroup.[/dim]")
    console.print()

    # ── Bucket choice ────────────────────────────────────────────────────────
    console.print("[bold cyan]Athena Results Bucket[/bold cyan]")
    create_new = typer.confirm("Create a new S3 bucket?", default=wg.output_location is None)

    if create_new:
        default_name = f"standstill-athena-results-{admin}-{region}"
        bucket_name = typer.prompt("New bucket name", default=default_name)
        prefix = typer.prompt("S3 key prefix", default=lake_api.DEFAULT_OUTPUT_PREFIX)
        output_location = f"s3://{bucket_name}/{prefix.strip('/')}/"

        with console.status(f"[bold]Creating bucket {bucket_name}...[/bold]"):
            try:
                lake_api.create_results_bucket(bucket_name, admin, role_name, region)
            except Exception as exc:
                err.print(f"[bold red]Error creating bucket:[/bold red] {exc}")
                raise typer.Exit(1)
        console.print(f"[green]✓[/green] Bucket created: [cyan]{bucket_name}[/cyan]")
    else:
        current = wg.output_location or ""
        bucket_name = typer.prompt(
            "Existing bucket name",
            default=current.removeprefix("s3://").split("/")[0] if current else ...,
        )
        prefix = typer.prompt("S3 key prefix", default=lake_api.DEFAULT_OUTPUT_PREFIX)
        output_location = f"s3://{bucket_name}/{prefix.strip('/')}/"

        with console.status("[bold]Verifying bucket exists...[/bold]"):
            if not lake_api.bucket_exists(bucket_name, admin, role_name, region):
                err.print(
                    f"[bold red]Error:[/bold red] Bucket [cyan]{bucket_name}[/cyan] "
                    "not found (or not accessible)."
                )
                raise typer.Exit(1)

    # ── Update workgroup ─────────────────────────────────────────────────────
    with console.status(f"[bold]Updating workgroup '{workgroup}'...[/bold]"):
        try:
            lake_api.set_workgroup_output(workgroup, output_location, admin, role_name, region)
        except Exception as exc:
            err.print(f"[bold red]Error updating workgroup:[/bold red] {exc}")
            raise typer.Exit(1)

    console.print(
        f"\n[green]✓[/green] Workgroup [bold]{workgroup}[/bold] output set to "
        f"[cyan]{output_location}[/cyan]"
    )
    console.print(
        "\n[dim]You can now run:\n"
        f"  standstill lake create-views --account {admin}[/dim]"
    )


# ---------------------------------------------------------------------------
# create-views
# ---------------------------------------------------------------------------

@app.command("create-views")
def create_views(
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Delegated admin account ID."),
    ] = None,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role in the admin account."),
    ] = _DEFAULT_ROLE,
    workgroup: Annotated[
        str,
        typer.Option("--workgroup", "-w", help="Athena workgroup to use for DDL execution."),
    ] = lake_api.DEFAULT_WORKGROUP,
    database: Annotated[
        str,
        typer.Option("--database", "-d", help="Glue database to create views in."),
    ] = lake_api.DEFAULT_VIEWS_DATABASE,
    sources: Annotated[
        Optional[str],
        typer.Option(
            "--sources", "-s",
            help="Comma-separated source keys to create views for (default: all detected).",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print view DDL without executing."),
    ] = False,
) -> None:
    """
    Create flattened Athena views over Security Lake OCSF data.

    \b
    Auto-detects existing Security Lake tables in the Glue catalog and creates
    one view per source in a dedicated database (standstill_security_lake by
    default). Each view flattens the nested OCSF structs into readable columns:
    account_id, region, user_name, user_arn, api_call, source_ip, user_agent,
    error_code, event_time, etc.

    \b
    Available sources:
      cloud_trail_mgmt  vpc_flow  route53  sh_findings
      eks_audit  lambda_execution  s3_data  wafv2

    \b
    Examples:
      standstill lake create-views --account 123456789012
      standstill lake create-views --account 123456789012 --dry-run
      standstill lake create-views --sources cloud_trail_mgmt,vpc_flow
    """
    console = renderer.console
    admin = _require_admin(account)
    region = _state.state.region or "us-east-1"

    # ── Discover existing Security Lake tables ───────────────────────────────
    with console.status("[bold]Discovering Security Lake tables in Glue catalog...[/bold]"):
        try:
            all_tables = lake_api.detect_lake_tables(admin, role_name, region)
        except Exception as exc:
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if not all_tables:
        err.print(
            "[bold red]No Security Lake tables found.[/bold red]\n"
            "[dim]Ensure Security Lake is enabled and the delegated admin account "
            "and region are correct.[/dim]"
        )
        raise typer.Exit(1)

    # ── Filter by --sources if provided ─────────────────────────────────────
    if sources:
        requested = {s.strip() for s in sources.split(",")}
        unknown = requested - lake_api.SOURCE_TABLE_SUFFIXES.keys()
        if unknown:
            err.print(
                f"[bold red]Error:[/bold red] Unknown source(s): {', '.join(sorted(unknown))}\n"
                f"[dim]Valid: {', '.join(lake_api.SOURCE_TABLE_SUFFIXES)}[/dim]"
            )
            raise typer.Exit(1)
        tables = [t for t in all_tables if t.source in requested]
        missing = requested - {t.source for t in tables}
        if missing:
            console.print(
                f"[yellow]Warning:[/yellow] Requested source(s) not found in Glue: "
                f"{', '.join(sorted(missing))}"
            )
    else:
        tables = all_tables

    if not tables:
        err.print("[bold red]No matching tables to create views for.[/bold red]")
        raise typer.Exit(1)

    # ── Dry run: just print DDL ──────────────────────────────────────────────
    if dry_run:
        for t in tables:
            sql = lake_api.build_view_sql(t.source, t.database, t.table_name, database)
            label = lake_api.SOURCE_LABELS.get(t.source, t.source)
            console.print(f"\n[bold cyan]-- {label}[/bold cyan]")
            console.print(sql)
        console.print("\n[bold yellow]Dry run — no views created.[/bold yellow]")
        return

    # ── Get workgroup output location ────────────────────────────────────────
    with console.status(f"[bold]Reading workgroup '{workgroup}'...[/bold]"):
        wg = lake_api.get_workgroup(workgroup, admin, role_name, region)

    if not wg.output_location:
        err.print(
            f"[bold red]Error:[/bold red] Workgroup '{workgroup}' has no output location set.\n"
            "[dim]Run: standstill lake setup-athena[/dim]"
        )
        raise typer.Exit(1)

    output_location = wg.output_location

    # ── Ensure views database exists ─────────────────────────────────────────
    with console.status(f"[bold]Ensuring Glue database '{database}' exists...[/bold]"):
        try:
            created = lake_api.ensure_views_database(database, admin, role_name, region)
        except Exception as exc:
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if created:
        console.print(f"[green]✓[/green] Created Glue database: [cyan]{database}[/cyan]")

    # ── Create views ─────────────────────────────────────────────────────────
    console.print(
        f"\n[bold]Creating {len(tables)} view(s) in "
        f"[cyan]{database}[/cyan]...[/bold]"
    )
    results: list[lake_api.ViewResult] = []
    for table in tables:
        label = lake_api.SOURCE_LABELS.get(table.source, table.source)
        with console.status(f"  [dim]{label}...[/dim]"):
            result = lake_api.create_view(
                table, database, output_location, workgroup,
                admin, role_name, region,
            )
        results.append(result)

    renderer.render_lake_view_results(results, database)

    if any(not r.success for r in results):
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command("status")
def status(
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Delegated admin account ID."),
    ] = None,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role in the admin account."),
    ] = _DEFAULT_ROLE,
    workgroup: Annotated[
        str,
        typer.Option("--workgroup", "-w", help="Athena workgroup to check."),
    ] = lake_api.DEFAULT_WORKGROUP,
    database: Annotated[
        str,
        typer.Option("--database", "-d", help="Glue database where views live."),
    ] = lake_api.DEFAULT_VIEWS_DATABASE,
) -> None:
    """
    Show Security Lake Athena setup: workgroup output, available tables, and views.
    """
    console = renderer.console
    admin = _require_admin(account)
    region = _state.state.region or "us-east-1"

    with console.status("[bold]Gathering Security Lake status...[/bold]"):
        wg = lake_api.get_workgroup(workgroup, admin, role_name, region)
        try:
            tables = lake_api.detect_lake_tables(admin, role_name, region)
        except Exception as exc:
            tables = []
            err.print(f"[yellow]Warning — could not read Glue tables:[/yellow] {exc}")
        try:
            views = lake_api.list_views(database, admin, role_name, region)
        except Exception as exc:
            views = []
            err.print(f"[yellow]Warning — could not read views:[/yellow] {exc}")

    renderer.render_lake_status(wg, tables, views, database, region)

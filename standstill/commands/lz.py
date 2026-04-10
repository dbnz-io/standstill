from __future__ import annotations

import time
from typing import Annotated, Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from standstill.aws import landing_zone as lz_api
from standstill.display.renderer import console

app = typer.Typer(no_args_is_help=True, help="Manage the Control Tower landing zone.")
err = Console(stderr=True)

_STATUS_COLOR = {"ACTIVE": "green", "PROCESSING": "yellow", "FAILED": "red"}
_DRIFT_COLOR = {"IN_SYNC": "green", "DRIFTED": "red"}


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command("status")
def status() -> None:
    """
    Show landing zone status, version, drift state, and service settings.

    Flags version upgrades and drift that needs remediation.
    """
    with console.status("[bold]Fetching landing zone...[/bold]"):
        lz = lz_api.get_landing_zone()

    if not lz:
        err.print("[bold red]No landing zone found in this account/region.[/bold red]")
        raise typer.Exit(1)

    _print_lz_summary(lz)
    _print_service_settings(lz.settings)

    if lz.drift_status == "DRIFTED":
        console.print(
            "\n[yellow]⚠ Landing zone has drifted. "
            "Run [bold]standstill lz reset[/bold] to remediate.[/yellow]"
        )
    if lz.version != lz.latest_version:
        console.print(
            f"\n[cyan]→ Version {lz.latest_version} is available. "
            "Run [bold]standstill lz update[/bold] to upgrade.[/cyan]"
        )
    if lz.status == "FAILED":
        console.print(
            "\n[red]✗ Landing zone is in a FAILED state. "
            "Run [bold]standstill lz reset[/bold] to attempt recovery.[/red]"
        )


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

@app.command("reset")
def reset(
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
    wait: Annotated[
        bool,
        typer.Option("--wait/--no-wait", help="Wait for the operation to complete."),
    ] = True,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Max seconds to wait (LZ ops take 30–60 min)."),
    ] = 3600,
) -> None:
    """
    Reset the landing zone to fix drift or recover from a FAILED state.

    Re-applies the current manifest without changing any settings.
    Use when the landing zone shows DRIFTED status or is FAILED.
    """
    with console.status("[bold]Fetching landing zone...[/bold]"):
        lz = lz_api.get_landing_zone()

    if not lz:
        err.print("[bold red]No landing zone found.[/bold red]")
        raise typer.Exit(1)

    _print_lz_summary(lz)

    if lz.status == "PROCESSING":
        err.print(
            "[bold yellow]Warning:[/bold yellow] The landing zone is already processing. "
            "Wait for it to finish before resetting."
        )
        raise typer.Exit(1)

    if not yes:
        typer.confirm("\nReset the landing zone?", abort=True)

    with console.status("[bold]Submitting reset operation...[/bold]"):
        op_id = lz_api.reset_landing_zone(lz.arn)

    console.print(f"[green]✓[/green] Reset submitted — operation [dim]{op_id}[/dim]")

    if not wait:
        console.print("[dim]Use [bold]standstill lz status[/bold] to check progress.[/dim]")
        return

    console.print("[dim]LZ operations take 30–60 minutes. Polling every 30s...[/dim]\n")
    result = _poll_with_progress(op_id, timeout)

    if result["status"] == "SUCCEEDED":
        console.print("\n[bold green]✓ Landing zone reset successfully.[/bold green]")
    else:
        msg = result.get("statusMessage", "unknown error")
        err.print(f"\n[bold red]✗ Reset failed:[/bold red] {msg}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

@app.command("update")
def update(
    version: Annotated[
        Optional[str],
        typer.Option("--version", "-v", help="Target LZ version. Defaults to latest available."),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
    wait: Annotated[
        bool,
        typer.Option("--wait/--no-wait", help="Wait for the operation to complete."),
    ] = True,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Max seconds to wait."),
    ] = 3600,
) -> None:
    """
    Upgrade the landing zone to a newer version.

    Current settings and manifest are preserved.
    To change service settings at the same time, run 'lz settings set' first.
    """
    with console.status("[bold]Fetching landing zone...[/bold]"):
        lz = lz_api.get_landing_zone()

    if not lz:
        err.print("[bold red]No landing zone found.[/bold red]")
        raise typer.Exit(1)

    target = version or lz.latest_version

    if target == lz.version:
        console.print(
            f"[green]Landing zone is already at version {lz.version}. Nothing to do.[/green]"
        )
        return

    console.print(
        f"Current version:  [cyan]{lz.version}[/cyan]\n"
        f"Target version:   [green]{target}[/green]"
    )

    if lz.status == "PROCESSING":
        err.print(
            "[bold yellow]Warning:[/bold yellow] The landing zone is already processing."
        )
        raise typer.Exit(1)

    if not yes:
        typer.confirm("\nUpdate the landing zone?", abort=True)

    with console.status(f"[bold]Submitting update to {target}...[/bold]"):
        op_id = lz_api.update_landing_zone(lz.arn, target, lz.manifest)

    console.print(f"[green]✓[/green] Update submitted — operation [dim]{op_id}[/dim]")

    if not wait:
        console.print("[dim]Use [bold]standstill lz status[/bold] to check progress.[/dim]")
        return

    console.print("[dim]LZ operations take 30–60 minutes. Polling every 30s...[/dim]\n")
    result = _poll_with_progress(op_id, timeout)

    if result["status"] == "SUCCEEDED":
        console.print(f"\n[bold green]✓ Landing zone updated to {target}.[/bold green]")
    else:
        msg = result.get("statusMessage", "unknown error")
        err.print(f"\n[bold red]✗ Update failed:[/bold red] {msg}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------

@app.command("settings")
def settings() -> None:
    """
    Show the current landing zone service settings in detail.

    Displays governed regions, OU structure, and the configuration of
    CloudTrail logging, AWS Config, AWS Backup, and IAM Identity Center.
    To change settings, run 'standstill lz settings set'.
    """
    with console.status("[bold]Fetching landing zone...[/bold]"):
        lz = lz_api.get_landing_zone()

    if not lz:
        err.print("[bold red]No landing zone found.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[dim]Landing zone {lz.arn}  version {lz.version}[/dim]\n")
    _print_service_settings(lz.settings, detailed=True)


@app.command("settings-set")
def settings_set(
    logging_enabled: Annotated[
        Optional[bool],
        typer.Option("--logging/--no-logging", help="Enable or disable centralized CloudTrail logging."),
    ] = None,
    logging_retention: Annotated[
        Optional[int],
        typer.Option("--logging-retention", help="Log bucket retention in days."),
    ] = None,
    logging_access_retention: Annotated[
        Optional[int],
        typer.Option("--logging-access-retention", help="Access log bucket retention in days."),
    ] = None,
    config_enabled: Annotated[
        Optional[bool],
        typer.Option("--config/--no-config", help="Enable or disable AWS Config integration."),
    ] = None,
    config_retention: Annotated[
        Optional[int],
        typer.Option("--config-retention", help="Config log bucket retention in days."),
    ] = None,
    config_access_retention: Annotated[
        Optional[int],
        typer.Option("--config-access-retention", help="Config access log bucket retention in days."),
    ] = None,
    backup_enabled: Annotated[
        Optional[bool],
        typer.Option("--backup/--no-backup", help="Enable or disable AWS Backup integration."),
    ] = None,
    access_management_enabled: Annotated[
        Optional[bool],
        typer.Option("--access-management/--no-access-management", help="Enable or disable IAM Identity Center."),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
    wait: Annotated[
        bool,
        typer.Option("--wait/--no-wait", help="Wait for the operation to complete."),
    ] = True,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Max seconds to wait."),
    ] = 3600,
) -> None:
    """
    Update landing zone service settings.

    \b
    Changes are applied by calling update_landing_zone with the modified manifest.
    The landing zone version is kept as-is; only the specified fields change.

    \b
    Examples:
      standstill lz settings-set --logging-retention 90
      standstill lz settings-set --no-backup
      standstill lz settings-set --config --config-retention 30
    """
    # Build the changes dict from flags that were actually provided
    changes: dict = {}
    if logging_enabled is not None:
        changes["logging_enabled"] = logging_enabled
    if logging_retention is not None:
        changes["logging_log_retention_days"] = logging_retention
    if logging_access_retention is not None:
        changes["logging_access_retention_days"] = logging_access_retention
    if config_enabled is not None:
        changes["config_enabled"] = config_enabled
    if config_retention is not None:
        changes["config_log_retention_days"] = config_retention
    if config_access_retention is not None:
        changes["config_access_retention_days"] = config_access_retention
    if backup_enabled is not None:
        changes["backup_enabled"] = backup_enabled
    if access_management_enabled is not None:
        changes["access_management_enabled"] = access_management_enabled

    if not changes:
        err.print(
            "[bold red]Error:[/bold red] No changes specified. "
            "Provide at least one setting flag, or run [bold]standstill lz settings[/bold] to view current values."
        )
        raise typer.Exit(1)

    with console.status("[bold]Fetching landing zone...[/bold]"):
        lz = lz_api.get_landing_zone()

    if not lz:
        err.print("[bold red]No landing zone found.[/bold red]")
        raise typer.Exit(1)

    if lz.status == "PROCESSING":
        err.print("[bold yellow]Warning:[/bold yellow] The landing zone is already processing.")
        raise typer.Exit(1)

    # Show current settings + planned changes
    console.print("[bold]Current settings:[/bold]")
    _print_service_settings(lz.settings, detailed=False)

    console.print("\n[bold]Planned changes:[/bold]")
    _print_changes(changes)

    if not yes:
        typer.confirm("\nApply these changes?", abort=True)

    new_manifest = lz_api.build_updated_manifest(lz.manifest, changes)

    with console.status("[bold]Submitting settings update...[/bold]"):
        op_id = lz_api.update_landing_zone(lz.arn, lz.version, new_manifest)

    console.print(f"[green]✓[/green] Update submitted — operation [dim]{op_id}[/dim]")

    if not wait:
        console.print("[dim]Use [bold]standstill lz status[/bold] to check progress.[/dim]")
        return

    console.print("[dim]LZ operations take 30–60 minutes. Polling every 30s...[/dim]\n")
    result = _poll_with_progress(op_id, timeout)

    if result["status"] == "SUCCEEDED":
        console.print("\n[bold green]✓ Settings updated successfully.[/bold green]")
    else:
        msg = result.get("statusMessage", "unknown error")
        err.print(f"\n[bold red]✗ Update failed:[/bold red] {msg}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _print_lz_summary(lz: lz_api.LandingZone) -> None:
    sc = _STATUS_COLOR.get(lz.status, "dim")
    dc = _DRIFT_COLOR.get(lz.drift_status, "dim")
    upgrade = (
        f" [yellow]→ {lz.latest_version} available[/yellow]"
        if lz.version != lz.latest_version
        else ""
    )
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Value")
    t.add_row("ARN", f"[dim]{lz.arn}[/dim]")
    t.add_row("Status", f"[{sc}]{lz.status}[/{sc}]")
    t.add_row("Version", f"{lz.version}{upgrade}")
    t.add_row("Drift", f"[{dc}]{lz.drift_status}[/{dc}]")
    if lz.drift_types:
        t.add_row("Remediation types", ", ".join(lz.drift_types))
    console.print(Panel(t, title="[bold]Landing Zone[/bold]", expand=False))


def _print_service_settings(s: lz_api.LzSettings, detailed: bool = False) -> None:
    def _svc_status(enabled: bool) -> str:
        return "[green]✓ enabled[/green]" if enabled else "[dim]✗ disabled[/dim]"

    def _svc_block(title: str, svc: lz_api.LzServiceSettings, extra: list[tuple] | None = None):
        if not detailed:
            return  # inline table handles this
        t = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        t.add_column("", style="dim")
        t.add_column("")
        t.add_row("Status", _svc_status(svc.enabled))
        if svc.account_id:
            t.add_row("Account", svc.account_id)
        if svc.log_retention_days is not None:
            t.add_row("Log retention", f"{svc.log_retention_days} days")
        if svc.access_log_retention_days is not None:
            t.add_row("Access log retention", f"{svc.access_log_retention_days} days")
        if svc.kms_key_arn:
            t.add_row("KMS key", f"[dim]{svc.kms_key_arn}[/dim]")
        if extra:
            for k, v in extra:
                t.add_row(k, v)
        console.print(Panel(t, title=f"[bold]{title}[/bold]", expand=False))

    if detailed:
        # Structure panel
        st = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        st.add_column("", style="dim")
        st.add_column("")
        st.add_row("Governed regions", ", ".join(s.governed_regions) or "—")
        st.add_row("Security OU", s.security_ou)
        st.add_row("Sandbox OU", s.sandbox_ou)
        console.print(Panel(st, title="[bold]Organization Structure[/bold]", expand=False))

        _svc_block("CloudTrail / Centralized Logging", s.logging)
        _svc_block("AWS Config", s.config)
        _svc_block("AWS Backup", s.backup)

        am_t = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        am_t.add_column("", style="dim")
        am_t.add_column("")
        am_t.add_row("Status", _svc_status(s.access_management_enabled))
        console.print(Panel(am_t, title="[bold]IAM Identity Center (Access Management)[/bold]", expand=False))
    else:
        # Compact table for inline status display
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        t.add_column("Service", style="bold")
        t.add_column("Status")
        t.add_column("Account", style="dim")
        t.add_column("Details", style="dim")

        def _log_detail(svc: lz_api.LzServiceSettings) -> str:
            parts = []
            if svc.log_retention_days:
                parts.append(f"logs {svc.log_retention_days}d")
            if svc.access_log_retention_days:
                parts.append(f"access {svc.access_log_retention_days}d")
            return "  ".join(parts)

        t.add_row("CloudTrail / Logging", _svc_status(s.logging.enabled),
                  s.logging.account_id or "—", _log_detail(s.logging))
        t.add_row("Config", _svc_status(s.config.enabled),
                  s.config.account_id or "—", _log_detail(s.config))
        t.add_row("Backup", _svc_status(s.backup.enabled),
                  s.backup.account_id or "—", "")
        t.add_row("IAM Identity Center", _svc_status(s.access_management_enabled), "—", "")
        t.add_row("Governed regions", "", "—", ", ".join(s.governed_regions) or "—")
        t.add_row("Security OU", "", "—", s.security_ou)
        t.add_row("Sandbox OU", "", "—", s.sandbox_ou)
        console.print(t)


_CHANGE_LABELS = {
    "logging_enabled": ("CloudTrail logging", lambda v: "enabled" if v else "disabled"),
    "logging_log_retention_days": ("Log retention", lambda v: f"{v} days"),
    "logging_access_retention_days": ("Access log retention", lambda v: f"{v} days"),
    "logging_kms_key_arn": ("Logging KMS key", lambda v: v or "(removed)"),
    "config_enabled": ("AWS Config", lambda v: "enabled" if v else "disabled"),
    "config_log_retention_days": ("Config log retention", lambda v: f"{v} days"),
    "config_access_retention_days": ("Config access retention", lambda v: f"{v} days"),
    "config_kms_key_arn": ("Config KMS key", lambda v: v or "(removed)"),
    "backup_enabled": ("AWS Backup", lambda v: "enabled" if v else "disabled"),
    "access_management_enabled": ("IAM Identity Center", lambda v: "enabled" if v else "disabled"),
}


def _print_changes(changes: dict) -> None:
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Setting", style="bold")
    t.add_column("New value", style="cyan")
    for key, value in changes.items():
        label, fmt = _CHANGE_LABELS.get(key, (key, str))
        t.add_row(label, fmt(value))
    console.print(t)


def _poll_with_progress(op_id: str, timeout: int) -> dict:
    """Poll a landing zone operation, printing elapsed time each interval."""
    start = time.monotonic()
    deadline = start + timeout
    poll_interval = 30

    time.sleep(min(15, poll_interval))  # initial wait before first poll

    from botocore.exceptions import ClientError

    from standstill import state as _state
    throttle_count = 0

    while time.monotonic() < deadline:
        try:
            ct = _state.state.get_client("controltower")
            resp = ct.get_landing_zone_operation(operationIdentifier=op_id)
            op = resp["operationDetails"]
            throttle_count = 0
            elapsed = int(time.monotonic() - start)
            mins, secs = divmod(elapsed, 60)
            console.print(
                f"  [dim][{mins:02d}:{secs:02d}][/dim]  {op['operationType']} — "
                f"[cyan]{op['status']}[/cyan]"
            )
            if op["status"] in {"SUCCEEDED", "FAILED"}:
                return op
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in {"ThrottlingException", "Throttling", "RequestThrottled"}:
                throttle_count += 1
                time.sleep(min(poll_interval * (2 ** throttle_count), 120))
                continue
            raise
        time.sleep(poll_interval)

    raise TimeoutError(
        f"Operation {op_id} did not complete within {timeout}s. "
        "LZ operations can take 30–60 minutes. "
        "Check status with: standstill lz status"
    )

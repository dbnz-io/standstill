from __future__ import annotations

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from standstill.aws import controltower as ct_api
from standstill.display.renderer import console

app = typer.Typer(no_args_is_help=True, help="Manage pending Control Tower operations.")
err = Console(stderr=True)

_STATUS_STYLES = {
    "SUCCEEDED": "bold green",
    "FAILED": "bold red",
    "IN_PROGRESS": "bold yellow",
    "UNKNOWN": "dim",
}


@app.command("list")
def operations_list() -> None:
    """Show all operations saved in the pending journal (~/.standstill/pending_operations.yaml)."""
    ops = ct_api.load_pending_operations()
    if not ops:
        console.print("[dim]No pending operations.[/dim]")
        return

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Operation ID", style="cyan", no_wrap=True)
    t.add_column("Control", no_wrap=True)
    t.add_column("OU ARN", style="dim")
    t.add_column("Started", style="dim")
    t.add_column("Status", justify="center")

    for op in ops:
        status = op.get("status", "UNKNOWN")
        style = _STATUS_STYLES.get(status, "dim")
        t.add_row(
            op.get("operation_id", "—"),
            op.get("control_arn", "—").split("/")[-1],
            op.get("ou_arn", "—"),
            op.get("started_at", "—"),
            f"[{style}]{status}[/{style}]",
        )

    console.print(t)
    console.print(f"\n[dim]{len(ops)} pending operation(s). Run 'standstill operations check' to refresh.[/dim]")


@app.command("check")
def operations_check(
    clear_completed: bool = typer.Option(
        True,
        "--clear/--no-clear",
        help="Remove SUCCEEDED/FAILED operations from the journal after checking.",
    ),
) -> None:
    """
    Poll the current status of all pending operations from the journal.
    Refreshes statuses live from the CT API.
    """
    ops = ct_api.load_pending_operations()
    if not ops:
        console.print("[dim]No pending operations to check.[/dim]")
        return

    console.print(f"Checking [bold]{len(ops)}[/bold] pending operation(s)…\n")

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Operation ID", style="cyan", no_wrap=True)
    t.add_column("Control")
    t.add_column("OU ARN", style="dim")
    t.add_column("Started", style="dim")
    t.add_column("Status", justify="center")
    t.add_column("Message", style="dim")

    resolved: list[str] = []
    ct = ct_api._state.state.get_client("controltower")

    for op in ops:
        op_id = op.get("operation_id", "")
        try:
            resp = ct.get_control_operation(operationIdentifier=op_id)
            live_op = resp["controlOperation"]
            status = live_op.get("status", "UNKNOWN")
            message = live_op.get("statusMessage", "")
        except Exception as e:
            status = "ERROR"
            message = str(e)

        style = _STATUS_STYLES.get(status, "dim")
        t.add_row(
            op_id,
            op.get("control_arn", "—").split("/")[-1],
            op.get("ou_arn", "—"),
            op.get("started_at", "—"),
            f"[{style}]{status}[/{style}]",
            message[:60],
        )

        if clear_completed and status in ("SUCCEEDED", "FAILED"):
            resolved.append(op_id)

    console.print(t)

    if resolved and clear_completed:
        for op_id in resolved:
            ct_api.remove_pending_operation(op_id)
        console.print(f"\n[dim]Removed {len(resolved)} completed operation(s) from journal.[/dim]")


@app.command("clear")
def operations_clear() -> None:
    """Remove all entries from the pending operations journal."""
    import yaml

    from standstill.aws.controltower import _PENDING_OPS_PATH

    ops = ct_api.load_pending_operations()
    if not ops:
        console.print("[dim]Journal is already empty.[/dim]")
        return

    _PENDING_OPS_PATH.write_text(yaml.dump([], default_flow_style=False))
    console.print(f"[green]Cleared {len(ops)} operation(s) from the journal.[/green]")

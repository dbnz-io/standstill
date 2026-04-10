from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from standstill import state as _state
from standstill.aws import controltower as ct_api
from standstill.display.renderer import console

app = typer.Typer(no_args_is_help=True, help="Manage the local controls catalog.")
err = Console(stderr=True)

_BEHAVIOR_STYLES = {
    "PREVENTIVE": "red",
    "DETECTIVE": "yellow",
    "PROACTIVE": "blue",
}


@app.command("build")
def catalog_build(
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir", "-o",
            help="Directory to write the 3 behavior YAML files. Defaults to current directory.",
        ),
    ] = Path("."),
    update_cache: Annotated[
        bool,
        typer.Option(
            "--update-cache/--no-update-cache",
            help="Save fetched controls to ~/.standstill/catalog.yaml for use by 'ct apply --enable-all'.",
        ),
    ] = True,
) -> None:
    """
    Fetch the full controls catalog from the AWS Control Tower API and write:

    \b
      • {output_dir}/preventive_controls.yaml
      • {output_dir}/detective_controls.yaml
      • {output_dir}/proactive_controls.yaml

    Also updates ~/.standstill/catalog.yaml (used by 'ct apply --enable-all').

    \b
    Note: ListControls is not yet in boto3's service model, so this command
    calls the CT endpoint directly via a signed HTTP request.
    """
    region = _state.state.region or "us-east-1"

    # ── Fetch controls ───────────────────────────────────────────────────────
    with console.status("[bold]Fetching controls catalog...[/bold]"):
        try:
            raw_controls = ct_api.fetch_controls_from_api(region)
        except RuntimeError as e:
            err.print(f"[bold red]Error fetching controls:[/bold red] {e}")
            raise typer.Exit(1)

    if not raw_controls:
        err.print("[bold red]No controls returned from the API.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[green]✓[/green] Fetched [bold]{len(raw_controls)}[/bold] controls.")

    # ── Fetch common control associations ────────────────────────────────────
    with console.status("[bold]Fetching common control associations...[/bold]"):
        try:
            cc_map = ct_api.fetch_common_control_mapping(region)
        except Exception as e:
            err.print(f"[yellow]Warning: could not fetch common controls: {e}[/yellow]")
            cc_map = {}

    # Attach common_controls to each control entry
    for c in raw_controls:
        c["common_controls"] = cc_map.get(c["arn"], [])

    if cc_map:
        cc_names = {name for names in cc_map.values() for name in names}
        console.print(f"[green]✓[/green] Mapped [bold]{len(cc_names)}[/bold] common control categories.")

    # ── Summary tables ───────────────────────────────────────────────────────
    by_behavior: dict[str, list[dict]] = {"PREVENTIVE": [], "DETECTIVE": [], "PROACTIVE": [], "UNKNOWN": []}
    by_service: dict[str, int] = {}
    for c in raw_controls:
        b = c.get("behavior", "UNKNOWN").upper()
        by_behavior.setdefault(b, []).append(c)
        svc = c.get("service")
        if svc:
            by_service[svc] = by_service.get(svc, 0) + 1

    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Behavior", style="bold")
    t.add_column("Count", justify="right")
    for behavior, items in by_behavior.items():
        if not items:
            continue
        style = _BEHAVIOR_STYLES.get(behavior, "dim")
        t.add_row(f"[{style}]{behavior}[/{style}]", str(len(items)))
    console.print(t)

    if by_service:
        svc_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2), title="By Service")
        svc_table.add_column("Service", style="cyan")
        svc_table.add_column("Controls", justify="right")
        for svc, count in sorted(by_service.items(), key=lambda x: -x[1]):
            svc_table.add_row(svc, str(count))
        console.print(svc_table)

    # ── Update user cache ────────────────────────────────────────────────────
    if update_cache:
        cache_path = ct_api.save_user_catalog(raw_controls, region)
        console.print(f"[dim]Catalog cache saved → {cache_path}[/dim]")

    # ── Write YAML files ─────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    written: list[Path] = []
    for behavior in ("PREVENTIVE", "DETECTIVE", "PROACTIVE"):
        controls = by_behavior.get(behavior, [])
        if not controls:
            console.print(f"[dim]No {behavior} controls found — skipping file.[/dim]")
            continue

        filename = f"{behavior.lower()}_controls.yaml"
        path = output_dir / filename
        _write_behavior_yaml(path, controls, behavior, region, timestamp)
        written.append(path)
        console.print(
            f"[green]✓[/green] {behavior}: {len(controls)} controls → [cyan]{path}[/cyan]"
        )

    if not written:
        err.print("[bold red]No YAML files were written.[/bold red]")
        raise typer.Exit(1)

    console.print(
        "\n[bold]Done.[/bold] Edit the OU placeholder in each file, then:\n"
        "  ct apply --file preventive_controls.yaml --dry-run"
    )


@app.command("info")
def catalog_info() -> None:
    """Show which catalog is currently active and its contents summary."""
    from standstill.aws.controltower import _BUNDLED_CATALOG_PATH, _USER_CATALOG_PATH

    region = _state.state.region or "us-east-1"

    if _USER_CATALOG_PATH.exists():
        source = _USER_CATALOG_PATH
        label = "[green]user cache[/green]"
    else:
        source = _BUNDLED_CATALOG_PATH
        label = "[yellow]bundled fallback[/yellow]"

    console.print(f"Active catalog: {label}")
    console.print(f"Path: [dim]{source}[/dim]")

    data = yaml.safe_load(source.read_text())
    meta = data.get("_meta", {})
    if meta:
        console.print(f"Region: {meta.get('region', '—')}  Total: {meta.get('total', '—')}")

    catalog = ct_api.load_catalog(region)
    counts: dict[str, int] = {}
    for ctrl in catalog.values():
        counts[ctrl.behavior] = counts.get(ctrl.behavior, 0) + 1

    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Behavior")
    t.add_column("Count", justify="right")
    for b, n in sorted(counts.items()):
        style = _BEHAVIOR_STYLES.get(b, "dim")
        t.add_row(f"[{style}]{b}[/{style}]", str(n))
    console.print(t)


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _write_behavior_yaml(
    path: Path,
    controls: list[dict],
    behavior: str,
    region: str,
    date: str,
) -> None:
    behavior_descriptions = {
        "PREVENTIVE": (
            "Preventive controls — enforced via Service Control Policies (SCPs).\n"
            "# These block non-compliant API actions before they happen."
        ),
        "DETECTIVE": (
            "Detective controls — implemented via AWS Config rules.\n"
            "# These continuously evaluate resources and flag non-compliant findings.\n"
            "# They do NOT block actions; they detect and report drift."
        ),
        "PROACTIVE": (
            "Proactive controls — implemented via AWS CloudFormation Hooks.\n"
            "# These intercept CloudFormation deployments BEFORE resources are provisioned."
        ),
    }

    header = f"""\
# {behavior_descriptions.get(behavior, behavior + ' controls')}
#
# Generated: {date}
# Region:    {region}
# Controls:  {len(controls)}
#
# Replace REPLACE_WITH_OU_ID with your actual OU ID.
# List available OUs with:  ct view ous
#
# Apply:          ct apply --file {path.name}
# Dry-run first:  ct apply --file {path.name} --dry-run
"""

    # Group controls by severity for readability
    by_severity: dict[str, list[dict]] = {}
    for c in controls:
        sev = c.get("severity", "UNKNOWN").upper()
        by_severity.setdefault(sev, []).append(c)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]

    lines = [header, "version: \"1\"\n", "targets:"]
    lines.append("  - ou_id: REPLACE_WITH_OU_ID\n    controls:\n")

    for sev in severity_order:
        items = by_severity.get(sev, [])
        if not items:
            continue
        lines.append(f"      # ── {sev} ({'─' * (40 - len(sev))})")
        for c in sorted(items, key=lambda x: x.get("fullName", "")):
            arn = c.get("arn", "")
            name = c.get("fullName", c.get("name", ""))
            svc = c.get("service", "")
            comment = f"{name}  [{svc}]" if svc else name
            lines.append(f"      - {arn}  # {comment}")
        lines.append("")

    path.write_text("\n".join(lines))

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import typer
import yaml
from botocore.exceptions import ClientError
from pydantic import ValidationError
from rich import box
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

from standstill.aws import controltower as ct_api
from standstill.aws import organizations as org_api
from standstill.display.renderer import console
from standstill.models.schemas import ApplyConfig

err = Console(stderr=True)

_MAX_FILE_BYTES = 10_000_000  # 10 MB

_BEHAVIOR_LABELS = {
    "PREVENTIVE": "Preventive  [dim](SCP — block actions before they happen)[/dim]",
    "DETECTIVE":  "Detective   [dim](Config rule — flag configuration drift)[/dim]",
    "PROACTIVE":  "Proactive   [dim](CloudFormation hook — intercept deployments)[/dim]",
}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def _plan_from_file(file: Path, region: str) -> list[tuple[str, str]] | None:
    """Parse a YAML file and return [(ou_id, ctrl_arn)] pairs."""
    try:
        if not file.exists():
            err.print(f"[bold red]File not found:[/bold red] {file}")
            return None
        if file.stat().st_size > _MAX_FILE_BYTES:
            err.print("[bold red]Error:[/bold red] Input file exceeds 10 MB limit.")
            return None
        raw = yaml.safe_load(file.read_text())
        config = ApplyConfig.model_validate(raw)
    except yaml.YAMLError as e:
        err.print(f"[bold red]Invalid YAML:[/bold red] {e}")
        return None
    except ValidationError as e:
        err.print(f"[bold red]Schema validation failed:[/bold red]\n{e}")
        return None

    pairs: list[tuple[str, str]] = []
    for target in config.targets:
        for ctrl_arn in target.controls:
            pairs.append((target.ou_id, ctrl_arn))
    return pairs


def _multi_select(
    title: str,
    options: list[tuple[str, str]],
    allow_empty: bool = False,
) -> list[str]:
    """
    Display a numbered list and return selected keys.
    User enters space-separated numbers or presses Enter for all.
    """
    console.print(f"\n[bold]{title}[/bold]")
    for i, (_, label) in enumerate(options, 1):
        console.print(f"  [dim][{i}][/dim]  {label}")
    console.print()

    hint = "Enter numbers (space-separated), or press Enter for all"
    while True:
        raw = typer.prompt(hint, default="")
        raw = raw.strip()

        if not raw:
            return [k for k, _ in options]

        parts = raw.split()
        try:
            indices = [int(x) for x in parts]
            if all(1 <= i <= len(options) for i in indices):
                seen: set[int] = set()
                result = []
                for i in indices:
                    if i not in seen:
                        seen.add(i)
                        result.append(options[i - 1][0])
                return result
        except ValueError:
            pass

        console.print(
            f"[red]Enter numbers between 1 and {len(options)}, space-separated "
            "(or press Enter for all).[/red]"
        )


def _interactive_picker(
    catalog: dict[str, ct_api.Control],
) -> dict[str, ct_api.Control]:
    """
    Interactive multi-step selector mirroring the CT console category tabs:
    pick a primary dimension (behavior / service / common control), then
    optionally narrow by severity.  Returns the filtered subset of `catalog`.
    """
    has_services = any(c.service for c in catalog.values())
    has_cc = any(c.common_controls for c in catalog.values())

    # ── Step 1: choose the primary filter dimension ──────────────────────────
    dim_options: list[tuple[str, str]] = [
        ("behavior", "By behavior       [dim](Preventive / Detective / Proactive)[/dim]"),
    ]
    if has_services:
        dim_options.append(("service", "By service        [dim](S3, EC2, IAM, CloudTrail, ...)[/dim]"))
    if has_cc:
        dim_options.append(("common_control", "By common control [dim](Data retention, Backup, Log generation, ...)[/dim]"))

    if len(dim_options) > 1:
        dims = _multi_select("How would you like to filter controls?", dim_options)
        dimension = dims[0] if dims else "behavior"
    else:
        dimension = "behavior"

    # ── Step 2: pick values for the chosen dimension ─────────────────────────
    if dimension == "behavior":
        behavior_counts: dict[str, int] = {}
        for c in catalog.values():
            behavior_counts[c.behavior] = behavior_counts.get(c.behavior, 0) + 1
        options = [
            (b, f"{_BEHAVIOR_LABELS.get(b, b)}  [cyan]{behavior_counts[b]} controls[/cyan]")
            for b in ("PREVENTIVE", "DETECTIVE", "PROACTIVE")
            if b in behavior_counts
        ]
        if not options:
            console.print("[yellow]No controls in catalog.[/yellow]")
            return {}
        selected_values = _multi_select("Select behaviors:", options)
        pre_filtered = {arn: c for arn, c in catalog.items() if c.behavior in selected_values}

    elif dimension == "service":
        svc_counts: dict[str, int] = {}
        for c in catalog.values():
            if c.service:
                svc_counts[c.service] = svc_counts.get(c.service, 0) + 1
        options = [
            (svc, f"{svc}  [cyan]{cnt} controls[/cyan]")
            for svc, cnt in sorted(svc_counts.items(), key=lambda x: -x[1])
        ]
        if not options:
            console.print("[yellow]No service data — run 'catalog build' first.[/yellow]")
            return {}
        selected_values = _multi_select("Select services:", options)
        pre_filtered = {arn: c for arn, c in catalog.items() if c.service in selected_values}

    else:  # common_control
        cc_counts: dict[str, int] = {}
        for c in catalog.values():
            for cc in c.common_controls:
                cc_counts[cc] = cc_counts.get(cc, 0) + 1
        options = [
            (cc, f"{cc}  [cyan]{cnt} controls[/cyan]")
            for cc, cnt in sorted(cc_counts.items(), key=lambda x: -x[1])
        ]
        if not options:
            console.print("[yellow]No common control data — run 'catalog build' first.[/yellow]")
            return {}
        selected_values = _multi_select("Select common controls:", options)
        pre_filtered = {
            arn: c for arn, c in catalog.items()
            if any(cc in selected_values for cc in c.common_controls)
        }

    # ── Step 3: optional severity filter ────────────────────────────────────
    severity_counts: dict[str, int] = {}
    for c in pre_filtered.values():
        severity_counts[c.severity] = severity_counts.get(c.severity, 0) + 1

    sev_options = [
        (s, f"{s.capitalize()}  [cyan]{severity_counts[s]} controls[/cyan]")
        for s in _SEVERITY_ORDER
        if s in severity_counts
    ]
    selected_severities = _multi_select(
        "Filter by severity (press Enter to include all):", sev_options
    )

    filtered = {
        arn: c
        for arn, c in pre_filtered.items()
        if c.severity in selected_severities
    }

    # ── Summary ──────────────────────────────────────────────────────────────
    console.print("\n[bold]Selection summary:[/bold]")
    console.print(f"  Filter:     [cyan]{dimension}[/cyan]")
    console.print(f"  Selected:   [cyan]{', '.join(selected_values)}[/cyan]")
    console.print(f"  Severities: [cyan]{', '.join(s.capitalize() for s in selected_severities)}[/cyan]")
    console.print(f"  Matched:    [green]{len(filtered)} controls[/green]")

    return filtered


def _run_apply(
    planned: list[tuple[str, str]],
    dry_run: bool,
    wait: bool,
    timeout: int,
    concurrency: int,
    region: str,
    action: Callable[[str, str], str],
    action_label: str,
    yes: bool = False,
) -> None:
    """
    Resolve OUs, baseline-check, diff current state, display plan, and execute.
    `planned` is a list of (ou_id_or_arn, ctrl_arn) pairs.
    `action` is called as action(ctrl_arn, ou_arn) and must return an operation ID.
    `action_label` is 'enable' or 'disable' — used in display only.
    """
    with console.status("[bold]Fetching OU structure...[/bold]"):
        nodes = org_api.build_ou_tree()
        flat = org_api.flatten_ous(nodes)
        ou_map = {n.id: n for n in flat}
        ou_arn_map = {n.arn: n for n in flat}

    resolved: list[tuple[str, str, str, str]] = []  # (ou_id, ou_name, ou_arn, ctrl_arn)
    for ou_id, ctrl_arn in planned:
        node = ou_map.get(ou_id) or ou_arn_map.get(ou_id)
        if node is None:
            err.print(f"[bold red]OU not found:[/bold red] {ou_id}")
            raise typer.Exit(1)
        resolved.append((node.id, node.name, node.arn, ctrl_arn))

    target_ou_arns = list({ou_arn for _, _, ou_arn, _ in resolved})
    with console.status("[bold]Checking CT baselines for target OUs...[/bold]"):
        baseline_results = ct_api.check_baselines_for_ous(target_ou_arns)

    blocked = {
        ou_arn: msg
        for ou_arn, (ok, msg) in baseline_results.items()
        if not ok
    }
    if blocked:
        err.print("\n[bold red]Baseline check failed — cannot apply controls:[/bold red]")
        for ou_arn, msg in blocked.items():
            ou_name = next((n for _, n, a, _ in resolved if a == ou_arn), ou_arn)
            err.print(f"  [yellow]{ou_name}[/yellow] ({ou_arn})\n  [dim]{msg}[/dim]")
        err.print("\n[dim]Enroll the OU in Control Tower before enabling controls.[/dim]")
        raise typer.Exit(1)

    for ou_arn, (_, msg) in baseline_results.items():
        ou_name = next((n for _, n, a, _ in resolved if a == ou_arn), ou_arn)
        console.print(f"[green]✓[/green] [dim]{ou_name}:[/dim] {msg}")

    with console.status("[bold]Checking current control state...[/bold]"):
        enabled_by_ou = ct_api.list_enabled_for_all_ous(nodes)

    enabled_arns_by_ou: dict[str, set[str]] = {
        ou_arn: {ec.control_arn for ec in ecs}
        for ou_arn, ecs in enabled_by_ou.items()
    }

    if action_label == "enable":
        to_act = [
            item for item in resolved
            if item[3] not in enabled_arns_by_ou.get(item[2], set())
        ]
        already_count = len(resolved) - len(to_act)
        skip_label = "already enabled (skipped)"
    else:
        to_act = [
            item for item in resolved
            if item[3] in enabled_arns_by_ou.get(item[2], set())
        ]
        already_count = len(resolved) - len(to_act)
        skip_label = "not enabled (skipped)"

    action_color = "green" if action_label == "enable" else "red"
    console.print(
        f"\n[bold]Plan:[/bold] "
        f"[{action_color}]{len(to_act)} to {action_label}[/{action_color}]  "
        f"[dim]{already_count} {skip_label}[/dim]"
    )

    if not to_act:
        console.print(
            f"[green]Nothing to do — no controls to {action_label}.[/green]"
        )
        return

    plan_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    plan_table.add_column("OU", style="yellow")
    plan_table.add_column("Control ARN", style="cyan")
    plan_table.add_column("Action", justify="center")
    for _, ou_name, _, ctrl_arn in to_act:
        plan_table.add_row(
            ou_name,
            ctrl_arn,
            f"[{action_color}]{action_label}[/{action_color}]",
        )
    console.print(plan_table)

    if dry_run:
        console.print("\n[bold yellow]Dry run — no changes applied.[/bold yellow]")
        return

    if not yes:
        typer.confirm(f"\nProceed with {action_label}?", abort=True)

    _run_operations(to_act, action=action, action_label=action_label, wait=wait, timeout=timeout, concurrency=concurrency)


def _run_operations(
    items: list[tuple[str, str, str, str]],
    action: Callable[[str, str], str],
    action_label: str,
    wait: bool,
    timeout: int,
    concurrency: int,
) -> None:
    failed: list[tuple[str, str, str]] = []
    session_expired_ops: list[tuple[str, str, str]] = []
    submitted: list[tuple[str, str, str, str]] = []  # (op_id, ou_name, ou_arn, ctrl_arn)
    _lock = threading.Lock()

    # ── Phase 1: Submit all operations concurrently ──────────────────────────
    def _submit_one(item: tuple[str, str, str, str]) -> tuple:
        _, ou_name, ou_arn, ctrl_arn = item
        try:
            op_id = action(ctrl_arn, ou_arn)
            ct_api.save_pending_operation(op_id, ctrl_arn, ou_arn)
            return ("ok", op_id, ou_name, ou_arn, ctrl_arn)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            return ("error", ou_name, ctrl_arn, f"AWS error: {code}")

    console.print(
        f"\n[bold]Submitting {len(items)} {action_label} operation(s) "
        f"[dim]({concurrency} concurrent)[/dim]...[/bold]"
    )
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        submit_task = progress.add_task("[bold]Submitting...[/bold]", total=len(items))
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(_submit_one, item): item for item in items}
            for future in as_completed(futures):
                result = future.result()
                progress.advance(submit_task)
                if result[0] == "ok":
                    _, op_id, ou_name, ou_arn, ctrl_arn = result
                    with _lock:
                        submitted.append((op_id, ou_name, ou_arn, ctrl_arn))
                else:
                    _, ou_name, ctrl_arn, msg = result
                    with _lock:
                        failed.append((ou_name, ctrl_arn, msg))

    if not wait or not submitted:
        _print_summary(submitted, failed, session_expired_ops, waited=False, action_label=action_label)
        if failed:
            raise typer.Exit(1)
        return

    # ── Phase 2: Poll all submitted operations concurrently ──────────────────
    poll_workers = min(len(submitted), max(concurrency * 5, 50))

    def _poll_one(item: tuple[str, str, str, str]) -> tuple:
        op_id, ou_name, ou_arn, ctrl_arn = item
        try:
            op = ct_api.poll_operation(op_id, timeout=timeout)
            if op["status"] != "SUCCEEDED":
                return ("failed", ou_name, ctrl_arn, op.get("statusMessage", "unknown"))
            ct_api.remove_pending_operation(op_id)
            return ("ok",)
        except ct_api.SessionExpiredError as e:
            return ("expired", ou_name, ctrl_arn, e.operation_id)
        except TimeoutError as e:
            return ("timeout", ou_name, ctrl_arn, str(e))

    console.print(
        f"\n[bold]Waiting for {len(submitted)} operation(s) to complete "
        f"[dim]({poll_workers} concurrent polls)[/dim]...[/bold]"
    )
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        poll_task = progress.add_task("[bold]Waiting...[/bold]", total=len(submitted))
        with ThreadPoolExecutor(max_workers=poll_workers) as executor:
            futures = {executor.submit(_poll_one, item): item for item in submitted}
            for future in as_completed(futures):
                result = future.result()
                progress.advance(poll_task)
                if result[0] == "failed":
                    with _lock:
                        failed.append((result[1], result[2], result[3]))
                elif result[0] == "expired":
                    with _lock:
                        session_expired_ops.append((result[1], result[2], result[3]))
                elif result[0] == "timeout":
                    with _lock:
                        failed.append((result[1], result[2], result[3]))

    _print_summary(submitted, failed, session_expired_ops, waited=True, action_label=action_label)
    if failed or session_expired_ops:
        raise typer.Exit(1)


def _print_summary(
    submitted: list[tuple[str, str, str, str]],
    failed: list[tuple[str, str, str]],
    session_expired_ops: list[tuple[str, str, str]],
    waited: bool,
    action_label: str = "enable",
) -> None:
    succeeded = len(submitted) - len(failed) - len(session_expired_ops)

    if session_expired_ops:
        err.print(
            f"\n[bold yellow]⚠ Session expired — {len(session_expired_ops)} operation(s) "
            "still running in Control Tower:[/bold yellow]"
        )
        for ou_name, ctrl_arn, op_id in session_expired_ops:
            err.print(f"  [yellow]{ou_name}[/yellow]  {ctrl_arn}")
            err.print(f"  [dim]Operation ID: {op_id}[/dim]")
        err.print(
            "\n[dim]These have been saved to the pending journal. "
            "Check their status once your session is refreshed:\n"
            "  standstill operations check[/dim]"
        )

    if failed:
        err.print(f"\n[bold red]{len(failed)} operation(s) failed:[/bold red]")
        for ou_name, ctrl_arn, msg in failed:
            err.print(f"  [yellow]{ou_name}[/yellow]  {ctrl_arn}\n  [dim]{msg}[/dim]")

    past_tense = "enabled" if action_label == "enable" else "disabled"
    if not waited:
        if submitted:
            console.print(
                f"\n[bold green]✓ {len(submitted)} operation(s) submitted.[/bold green] "
                "[dim]Use [bold]standstill operations check[/bold] to track progress.[/dim]"
            )
    elif succeeded:
        console.print(f"\n[bold green]✓ {succeeded} control(s) {past_tense} successfully.[/bold green]")

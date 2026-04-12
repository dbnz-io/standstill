from __future__ import annotations

from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from standstill import state as _state
from standstill.aws import account_factory as af_api
from standstill.aws import blueprint as bp_api
from standstill.display import renderer
from standstill.models.blueprint_config import load_blueprint

app = typer.Typer(no_args_is_help=True, help="Manage and apply infrastructure blueprints.")
err = Console(stderr=True)

_DEFAULT_CT_ROLE = "AWSControlTowerExecution"
_BLUEPRINTS_DIR = Path.home() / ".standstill" / "blueprints"


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@app.command("list")
def list_blueprints() -> None:
    """
    List all blueprint YAML files in ~/.standstill/blueprints/.

    Shows each blueprint's name, number of stacks, and description.
    Invalid files are shown with an error summary.
    """
    if not _BLUEPRINTS_DIR.exists():
        renderer.console.print(
            f"[dim]No blueprints directory found at {_BLUEPRINTS_DIR}.[/dim]\n"
            "Create it and place your .yaml blueprint files inside."
        )
        return

    files = sorted(_BLUEPRINTS_DIR.glob("*.yaml")) + sorted(_BLUEPRINTS_DIR.glob("*.yml"))
    if not files:
        renderer.console.print(f"[dim]No blueprint files found in {_BLUEPRINTS_DIR}.[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("File", style="cyan")
    t.add_column("Name")
    t.add_column("Stacks", justify="right")
    t.add_column("Description", style="dim")

    for f in files:
        try:
            bp = load_blueprint(f)
            t.add_row(f.name, bp.name, str(len(bp.stacks)), bp.description or "—")
        except (FileNotFoundError, ValueError) as e:
            t.add_row(f.name, "[red](invalid)[/red]", "—", str(e)[:80])

    renderer.console.print(t)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@app.command("validate")
def validate_blueprint(
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Path to blueprint YAML file."),
    ],
) -> None:
    """
    Validate a blueprint YAML file without deploying anything.

    Checks schema correctness, validates all referenced template_file paths exist,
    and verifies that no template exceeds the CloudFormation 51,200-byte inline limit.

    \b
    Examples:
      standstill blueprint validate --file blueprints/networking.yaml
    """
    try:
        bp = load_blueprint(file)
    except (FileNotFoundError, ValueError) as e:
        err.print(f"[bold red]Validation failed:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(
        f"[bold green]✓ Blueprint valid:[/bold green] {bp.name}  "
        f"[dim]({len(bp.stacks)} stack(s))[/dim]"
    )

    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Stack name", style="cyan")
    t.add_column("Region")
    t.add_column("Template")
    t.add_column("Params", justify="right")
    t.add_column("Capabilities", style="dim")
    t.add_column("Term. protect")

    for stack in bp.stacks:
        tpl = stack.template_file if stack.template_file else "[dim](inline)[/dim]"
        region_label = stack.region or "[dim](CLI --region)[/dim]"
        tp = "[green]on[/green]" if stack.termination_protection else "[dim]off[/dim]"
        t.add_row(
            stack.stack_name,
            region_label,
            tpl,
            str(len(stack.parameters)),
            ", ".join(stack.capabilities) or "—",
            tp,
        )

    renderer.console.print(t)


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------

@app.command("apply")
def apply_blueprint(
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Path to blueprint YAML file."),
    ],
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Target account ID (12-digit)."),
    ] = None,
    ou: Annotated[
        Optional[str],
        typer.Option("--ou", "-u", help="Apply to all active accounts directly in this OU."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would be deployed without deploying."),
    ] = False,
    role_name: Annotated[
        str,
        typer.Option("--role-name", help="IAM role to assume in each account."),
    ] = _DEFAULT_CT_ROLE,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
    params: Annotated[
        Optional[List[str]],
        typer.Option("--param", "-p", help="Parameter override KEY=VALUE (repeatable)."),
    ] = None,
) -> None:
    """
    Apply a blueprint to one account or all accounts directly in an OU.

    CloudFormation stacks are deployed using the CT execution role assumed in each
    account. Stacks are created with termination protection enabled by default and
    tagged with ManagedBy: standstill so application-layer Terraform never manages them.

    \b
    Examples:
      standstill blueprint apply --file net.yaml --account 123456789012
      standstill blueprint apply --file net.yaml --ou ou-ab12-34cd5678 --dry-run
      standstill blueprint apply --file net.yaml --account 123456789012 --param VpcCidr=10.1.0.0/16
      standstill blueprint apply --file net.yaml --ou ou-ab12-34cd5678 --yes
    """
    if account is None and ou is None:
        err.print("[bold red]Error:[/bold red] Provide --account or --ou.")
        raise typer.Exit(1)
    if account is not None and ou is not None:
        err.print("[bold red]Error:[/bold red] --account and --ou are mutually exclusive.")
        raise typer.Exit(1)

    try:
        bp = load_blueprint(file)
    except (FileNotFoundError, ValueError) as e:
        err.print(f"[bold red]Blueprint error:[/bold red] {e}")
        raise typer.Exit(1)

    param_overrides: dict[str, str] = {}
    for p in (params or []):
        if "=" not in p:
            err.print(
                f"[bold red]Invalid --param format:[/bold red] '{p}' (expected KEY=VALUE)"
            )
            raise typer.Exit(1)
        k, _, v = p.partition("=")
        param_overrides[k.strip()] = v.strip()

    region = _state.state.region or "us-east-1"

    if account:
        target_ids = [account]
    else:
        try:
            with renderer.console.status("[bold]Fetching accounts in OU...[/bold]"):
                ou_detail = af_api.describe_ou(ou)
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)
        target_ids = [
            a["Id"] for a in ou_detail.get("Accounts", []) if a.get("Status") == "ACTIVE"
        ]
        if not target_ids:
            renderer.console.print(f"[dim]No active accounts found in OU {ou}.[/dim]")
            return

    action_word = "Would deploy" if dry_run else "Will deploy"
    renderer.console.print(
        f"[bold]{action_word}[/bold] blueprint [cyan]{bp.name}[/cyan] "
        f"({len(bp.stacks)} stack(s)) to {len(target_ids)} account(s).\n"
    )

    if not dry_run and not yes:
        typer.confirm(
            f"Apply blueprint '{bp.name}' to {len(target_ids)} account(s)?", abort=True
        )

    all_success = True
    for acct_id in target_ids:
        renderer.console.print(f"\n[bold]Account:[/bold] [cyan]{acct_id}[/cyan]")
        results = bp_api.apply_blueprint_to_account(
            blueprint=bp,
            blueprint_path=file,
            account_id=acct_id,
            role_name=role_name,
            region=region,
            param_overrides=param_overrides,
            dry_run=dry_run,
        )
        renderer.render_blueprint_stack_results(results)
        if any(r.action == "failed" for r in results):
            all_success = False

    if not all_success:
        raise typer.Exit(1)

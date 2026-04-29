from __future__ import annotations

import configparser
import re
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from botocore.exceptions import ClientError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from standstill import state as _state
from standstill.aws import account_factory as af_api
from standstill.aws import blueprint as bp_api
from standstill.aws import organizations as org_api
from standstill.aws import session as aws_session
from standstill.display import renderer
from standstill.models.blueprint_config import load_blueprint

app = typer.Typer(no_args_is_help=True, help="Account-level operations across the organization.")
err = Console(stderr=True)

_DEFAULT_CT_ROLE = "AWSControlTowerExecution"
_STATUS_COLOR = {"ACTIVE": "green", "SUSPENDED": "red", "PENDING_CLOSURE": "yellow"}


# ---------------------------------------------------------------------------
# check-roles
# ---------------------------------------------------------------------------

@app.command("check-roles")
def check_roles(
    role_name: str = typer.Option(
        _DEFAULT_CT_ROLE,
        "--role-name",
        "-n",
        help="Name of the IAM role to probe in each member account.",
    ),
) -> None:
    """
    Verify that the Control Tower execution role can be assumed in every account.

    Walks the full organization, attempts sts:AssumeRole for the given role name
    in each member account, and reports which accounts are reachable.

    The role defaults to AWSControlTowerExecution — the role Control Tower deploys
    into managed accounts to perform administrative operations.
    """
    with renderer.console.status("[bold]Fetching account list...[/bold]"):
        nodes = org_api.build_ou_tree()
        accounts = org_api.all_accounts(nodes)

    if not accounts:
        renderer.console.print("[dim]No accounts found in the organization.[/dim]")
        return

    renderer.console.print(
        f"[dim]Probing [bold]{len(accounts)}[/bold] account(s) "
        f"for role [cyan]{role_name}[/cyan]...[/dim]\n"
    )

    with renderer.console.status("[bold]Checking roles...[/bold]"):
        results = aws_session.check_all_account_roles(accounts, role_name)

    renderer.render_account_roles_table(accounts, results, role_name)

    unreachable = sum(1 for ok, _ in results.values() if not ok)
    if unreachable:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

@app.command("create")
def create_account(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="Account name."),
    ],
    email: Annotated[
        str,
        typer.Option("--email", "-e", help="Root email address for the new account."),
    ],
    ou: Annotated[
        str,
        typer.Option("--ou", "-u", help="Target OU ID (ou-xxxx-xxxxxxxx)."),
    ],
    wait: Annotated[
        bool,
        typer.Option("--wait/--no-wait", help="Wait for the operation to complete."),
    ] = True,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Max seconds to wait (default 1800 = 30 min)."),
    ] = 1800,
    blueprint: Annotated[
        Optional[Path],
        typer.Option("--blueprint", "-b", help="Blueprint YAML to apply after account creation."),
    ] = None,
) -> None:
    """
    Create a new account via the Control Tower Account Factory.

    Provisions the account, applies the CT baseline, and places it in the
    target OU. Requires Control Tower 3.0+ and management-account credentials.
    Account creation typically takes 10–30 minutes.

    If --blueprint is specified, standstill will apply the blueprint's
    CloudFormation stacks to the new account once it is ready.

    \b
    Examples:
      standstill accounts create --name "Staging" --email stage@example.com --ou ou-ab12-34cd5678
      standstill accounts create --name "Dev" --email dev@example.com --ou ou-ab12-34cd5678 --blueprint blueprints/net.yaml
    """
    if blueprint and not wait:
        renderer.console.print(
            "[yellow]Warning:[/yellow] --blueprint is ignored with --no-wait. "
            "Run [bold]standstill blueprint apply[/bold] manually after the account is ready."
        )
        blueprint = None

    renderer.console.print(
        f"[bold]Creating account:[/bold] {name}  [dim]{email}[/dim]  → OU [cyan]{ou}[/cyan]\n"
    )

    try:
        with renderer.console.status("[bold]Submitting account creation...[/bold]"):
            op_id = af_api.create_managed_account(name=name, email=email, ou_id=ou)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(f"[green]✓[/green] Submitted — operation [dim]{op_id}[/dim]")

    if not wait:
        renderer.console.print("[dim]Use [bold]standstill view accounts[/bold] to check when the account appears.[/dim]")
        return

    renderer.console.print("[dim]Account creation takes 10–30 minutes. Polling every 15s...[/dim]\n")
    try:
        result = _poll_with_progress(op_id, timeout, poll_interval=15)
    except TimeoutError as e:
        err.print(f"[bold yellow]Timeout:[/bold yellow] {e}")
        raise typer.Exit(1)
    except Exception as e:
        err.print(f"[bold red]Error during polling:[/bold red] {e}")
        raise typer.Exit(1)

    if result.get("status") == "SUCCEEDED":
        renderer.console.print(f"\n[bold green]✓ Account '{name}' created successfully.[/bold green]")
        if blueprint:
            _apply_blueprint_post_create(
                blueprint_path=blueprint,
                email=email,
                ou=ou,
                region=_state.state.region or "us-east-1",
            )
    else:
        msg = result.get("statusMessage", "unknown error")
        err.print(f"\n[bold red]✗ Account creation failed:[/bold red] {msg}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# enroll
# ---------------------------------------------------------------------------

@app.command("enroll")
def enroll_account(
    account: Annotated[
        str,
        typer.Option("--account", "-a", help="Account ID to enroll (12-digit)."),
    ],
    ou: Annotated[
        str,
        typer.Option("--ou", "-u", help="Target OU ID (ou-xxxx-xxxxxxxx)."),
    ],
    wait: Annotated[
        bool,
        typer.Option("--wait/--no-wait", help="Wait for the operation to complete."),
    ] = True,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Max seconds to wait (default 1800 = 30 min)."),
    ] = 1800,
    blueprint: Annotated[
        Optional[Path],
        typer.Option("--blueprint", "-b", help="Blueprint YAML to apply after enrollment."),
    ] = None,
) -> None:
    """
    Enroll an existing AWS account into Control Tower.

    The account must already be a member of the organization and must not
    currently be enrolled in Control Tower. CT applies the baseline and
    installs the execution role. Enrollment typically takes 10–30 minutes.

    If --blueprint is specified, standstill will apply the blueprint's
    CloudFormation stacks to the account once enrollment completes.

    \b
    Examples:
      standstill accounts enroll --account 123456789012 --ou ou-ab12-34cd5678
      standstill accounts enroll --account 123456789012 --ou ou-ab12-34cd5678 --blueprint blueprints/net.yaml
    """
    if blueprint and not wait:
        renderer.console.print(
            "[yellow]Warning:[/yellow] --blueprint is ignored with --no-wait. "
            "Run [bold]standstill blueprint apply[/bold] manually after enrollment completes."
        )
        blueprint = None

    renderer.console.print(
        f"[bold]Enrolling account[/bold] [cyan]{account}[/cyan] → OU [cyan]{ou}[/cyan]\n"
    )

    try:
        with renderer.console.status("[bold]Submitting enrollment...[/bold]"):
            op_id = af_api.register_managed_account(account_id=account, ou_id=ou)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(f"[green]✓[/green] Submitted — operation [dim]{op_id}[/dim]")

    if not wait:
        renderer.console.print("[dim]Use [bold]standstill view accounts[/bold] to monitor enrollment.[/dim]")
        return

    renderer.console.print("[dim]Enrollment takes 10–30 minutes. Polling every 15s...[/dim]\n")
    try:
        result = _poll_with_progress(op_id, timeout, poll_interval=15)
    except TimeoutError as e:
        err.print(f"[bold yellow]Timeout:[/bold yellow] {e}")
        raise typer.Exit(1)
    except Exception as e:
        err.print(f"[bold red]Error during polling:[/bold red] {e}")
        raise typer.Exit(1)

    if result.get("status") == "SUCCEEDED":
        renderer.console.print(f"\n[bold green]✓ Account {account} enrolled successfully.[/bold green]")
        if blueprint:
            _run_blueprint_on_account(
                blueprint_path=blueprint,
                account_id=account,
                region=_state.state.region or "us-east-1",
            )
    else:
        msg = result.get("statusMessage", "unknown error")
        err.print(f"\n[bold red]✗ Enrollment failed:[/bold red] {msg}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# deregister
# ---------------------------------------------------------------------------

@app.command("deregister")
def deregister_account(
    account: Annotated[
        str,
        typer.Option("--account", "-a", help="Account ID to deregister (12-digit)."),
    ],
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
        typer.Option("--timeout", help="Max seconds to wait (default 1800 = 30 min)."),
    ] = 1800,
) -> None:
    """
    Deregister an account from Control Tower management.

    The account remains in the AWS organization but is no longer CT-governed.
    All enrolled controls are removed and the CT execution role is deleted
    from the account.

    \b
    Examples:
      standstill accounts deregister --account 123456789012
      standstill accounts deregister --account 123456789012 --yes
    """
    renderer.console.print(
        f"[bold]Deregistering account[/bold] [cyan]{account}[/cyan] from Control Tower.\n"
        "[yellow]Warning:[/yellow] This removes all CT controls and the execution role from the account.\n"
    )

    if not yes:
        typer.confirm(f"Deregister account {account}?", abort=True)

    try:
        with renderer.console.status("[bold]Submitting deregistration...[/bold]"):
            op_id = af_api.deregister_managed_account(account_id=account)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(f"[green]✓[/green] Submitted — operation [dim]{op_id}[/dim]")

    if not wait:
        renderer.console.print("[dim]Use [bold]standstill view accounts[/bold] to monitor progress.[/dim]")
        return

    renderer.console.print("[dim]Deregistration takes 10–30 minutes. Polling every 15s...[/dim]\n")
    try:
        result = _poll_with_progress(op_id, timeout, poll_interval=15)
    except TimeoutError as e:
        err.print(f"[bold yellow]Timeout:[/bold yellow] {e}")
        raise typer.Exit(1)
    except Exception as e:
        err.print(f"[bold red]Error during polling:[/bold red] {e}")
        raise typer.Exit(1)

    if result.get("status") == "SUCCEEDED":
        renderer.console.print(f"\n[bold green]✓ Account {account} deregistered successfully.[/bold green]")
    else:
        msg = result.get("statusMessage", "unknown error")
        err.print(f"\n[bold red]✗ Deregistration failed:[/bold red] {msg}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# move
# ---------------------------------------------------------------------------

@app.command("move")
def move_account(
    account: Annotated[
        str,
        typer.Option("--account", "-a", help="Account ID to move (12-digit)."),
    ],
    ou: Annotated[
        str,
        typer.Option("--ou", "-u", help="Destination OU ID (ou-xxxx-xxxxxxxx) or root ID (r-xxxx)."),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """
    Move an account to a different OU within the organization.

    This is a synchronous Organizations operation. If the destination OU is
    governed by Control Tower, CT will automatically re-baseline the account
    in the background.

    \b
    Examples:
      standstill accounts move --account 123456789012 --ou ou-cd34-56ef7890
      standstill accounts move --account 123456789012 --ou ou-cd34-56ef7890 --yes
    """
    try:
        with renderer.console.status("[bold]Resolving current location...[/bold]"):
            info = af_api.describe_account(account)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    current_ou = info.get("ParentId", "unknown")
    name = info.get("Name", account)

    renderer.console.print(
        f"[bold]Moving account:[/bold] {name} ([cyan]{account}[/cyan])\n"
        f"  From: [dim]{current_ou}[/dim]\n"
        f"  To:   [cyan]{ou}[/cyan]\n"
    )

    if not yes:
        typer.confirm("Proceed with move?", abort=True)

    try:
        af_api.move_account(account_id=account, dest_ou_id=ou)
    except ValueError as e:
        err.print(f"[bold yellow]Nothing to do:[/bold yellow] {e}")
        return
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    renderer.console.print(f"[bold green]✓ Account {account} moved to {ou}.[/bold green]")


# ---------------------------------------------------------------------------
# describe
# ---------------------------------------------------------------------------

@app.command("describe")
def describe_account(
    account: Annotated[
        str,
        typer.Option("--account", "-a", help="Account ID (12-digit)."),
    ],
) -> None:
    """
    Show details for a specific account.

    Fetches account metadata from the Organizations API: name, email,
    status, join date, and current OU placement.

    \b
    Examples:
      standstill accounts describe --account 123456789012
    """
    try:
        with renderer.console.status("[bold]Fetching account details...[/bold]"):
            info = af_api.describe_account(account)
    except Exception as e:
        err.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    _print_account_detail(info)


# ---------------------------------------------------------------------------
# set-profile
# ---------------------------------------------------------------------------

@app.command("set-profile")
def set_profile(
    account: Annotated[
        str,
        typer.Option("--account", "-a",
                     help="Account ID (12-digit) or account name."),
    ],
    profile: Annotated[
        str,
        typer.Option("--profile", "-p",
                     help="Profile suffix. Credentials are written as 'ss-{name}'."),
    ],
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n",
                     help="IAM role to assume in the target account."),
    ] = _DEFAULT_CT_ROLE,
    region: Annotated[
        Optional[str],
        typer.Option("--region", "-r",
                     help="AWS region stored in the profile (default: current region)."),
    ] = None,
    duration: Annotated[
        int,
        typer.Option("--duration", "-d",
                     help="Session duration in seconds (900–43200, default 3600)."),
    ] = 3600,
) -> None:
    """
    Assume the Control Tower execution role in a member account and write
    the resulting temporary credentials as a named AWS CLI profile.

    The profile is stored as [bold cyan]ss-{profile}[/bold cyan] in
    ~/.aws/credentials and ~/.aws/config so you can immediately target
    the account with any AWS tool or standstill itself.

    Accepts either a 12-digit account ID or the account name as registered
    in the organization — standstill resolves the name automatically.

    \b
    Examples:
      standstill accounts set-profile --account 123456789012 --profile prod
      standstill accounts set-profile --account "Production" --profile prod
      standstill accounts set-profile --account 123456789012 --profile prod --region eu-west-1
      # Then use it:
      standstill --profile ss-prod cost report
      aws s3 ls --profile ss-prod
    """
    # ── Resolve account ID ──────────────────────────────────────────────────
    with renderer.console.status("[bold]Resolving account...[/bold]"):
        account_id = _resolve_account_id(account)

    if not account_id:
        err.print(
            f"[bold red]Error:[/bold red] Could not resolve '{account}' to an account ID.\n"
            "[dim]Provide a 12-digit account ID or the exact account name from Organizations.[/dim]"
        )
        raise typer.Exit(1)

    profile_name    = f"ss-{profile}"
    role_arn        = f"arn:aws:iam::{account_id}:role/{role_name}"
    effective_region = region or _state.state.region or "us-east-1"
    duration_clamped = max(900, min(duration, 43200))

    renderer.console.print(
        f"[bold]Account:[/bold]  [cyan]{account_id}[/cyan]"
        + (f"  [dim]({account})[/dim]" if account != account_id else "")
    )
    renderer.console.print(f"[bold]Role:[/bold]     [dim]{role_arn}[/dim]")
    renderer.console.print(f"[bold]Profile:[/bold]  [bold cyan]{profile_name}[/bold cyan]\n")

    # ── Assume role ─────────────────────────────────────────────────────────
    try:
        with renderer.console.status("[bold]Assuming role...[/bold]"):
            sts  = _state.state.get_client("sts")
            resp = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"standstill-{profile}",
                DurationSeconds=duration_clamped,
            )
    except ClientError as e:
        err.print(f"[bold red]Error:[/bold red] {e.response['Error']['Message']}")
        raise typer.Exit(1)

    creds  = resp["Credentials"]
    expiry = creds["Expiration"]

    # ── Write ~/.aws/credentials ─────────────────────────────────────────────
    creds_path = Path.home() / ".aws" / "credentials"
    existed    = _profile_exists(creds_path, profile_name)
    _write_credentials(creds_path, profile_name, creds)

    # ── Write ~/.aws/config ──────────────────────────────────────────────────
    config_path = Path.home() / ".aws" / "config"
    _write_config(config_path, profile_name, effective_region)

    # ── Summary ──────────────────────────────────────────────────────────────
    overwrite_note = " [yellow](updated existing profile)[/yellow]" if existed else ""
    renderer.console.print(
        f"[bold green]✓[/bold green] Profile [bold cyan]{profile_name}[/bold cyan] "
        f"written to ~/.aws/credentials{overwrite_note}"
    )

    if hasattr(expiry, "strftime"):
        expiry_str = expiry.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        expiry_str = str(expiry)

    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    t.add_column(style="bold dim")
    t.add_column()
    t.add_row("Region",  effective_region)
    t.add_row("Expires", f"[yellow]{expiry_str}[/yellow]")
    t.add_row("Session", f"standstill-{profile}")
    renderer.console.print(t)

    renderer.console.print(
        "\n[bold]Use it with:[/bold]\n"
        f"  [cyan]standstill --profile {profile_name} cost report[/cyan]\n"
        f"  [cyan]aws sts get-caller-identity --profile {profile_name}[/cyan]"
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_account_id(account: str) -> str | None:
    """
    Return a 12-digit account ID.
    Accepts either a raw ID or an account name (case-insensitive lookup via Organizations).
    """
    if re.fullmatch(r"\d{12}", account):
        return account
    try:
        nodes    = org_api.build_ou_tree()
        accounts = org_api.all_accounts(nodes)
        for acct in accounts:
            if acct.name.lower() == account.lower():
                return acct.id
    except Exception:
        pass
    return None


def _profile_exists(path: Path, profile_name: str) -> bool:
    if not path.exists():
        return False
    cfg = configparser.RawConfigParser()
    cfg.read(path)
    return cfg.has_section(profile_name)


def _write_credentials(path: Path, profile_name: str, creds: dict) -> None:
    """
    Upsert [profile_name] in ~/.aws/credentials with temporary STS credentials.
    Uses RawConfigParser to avoid % interpolation issues in session tokens.
    """
    cfg = configparser.RawConfigParser()
    if path.exists():
        cfg.read(path)
    if not cfg.has_section(profile_name):
        cfg.add_section(profile_name)
    cfg.set(profile_name, "aws_access_key_id",     creds["AccessKeyId"])
    cfg.set(profile_name, "aws_secret_access_key", creds["SecretAccessKey"])
    cfg.set(profile_name, "aws_session_token",     creds["SessionToken"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        cfg.write(fh)


def _write_config(path: Path, profile_name: str, region: str) -> None:
    """
    Upsert [profile {profile_name}] in ~/.aws/config with region and output format.
    """
    cfg     = configparser.RawConfigParser()
    section = f"profile {profile_name}"
    if path.exists():
        cfg.read(path)
    if not cfg.has_section(section):
        cfg.add_section(section)
    cfg.set(section, "region", region)
    cfg.set(section, "output", "json")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        cfg.write(fh)

def _run_blueprint_on_account(blueprint_path: Path, account_id: str, region: str) -> None:
    """Load a blueprint and apply it to a known account ID. Prints results inline."""
    try:
        bp = load_blueprint(blueprint_path)
    except (FileNotFoundError, ValueError) as e:
        err.print(f"[bold yellow]Blueprint load failed:[/bold yellow] {e}")
        err.print("[dim]Apply it manually with: standstill blueprint apply[/dim]")
        return

    renderer.console.print(f"\n[dim]Applying blueprint [bold]{bp.name}[/bold]...[/dim]")
    results = bp_api.apply_blueprint_to_account(
        blueprint=bp,
        blueprint_path=blueprint_path,
        account_id=account_id,
        role_name=_DEFAULT_CT_ROLE,
        region=region,
        param_overrides={},
        dry_run=False,
    )
    renderer.render_blueprint_stack_results(results)


def _apply_blueprint_post_create(
    blueprint_path: Path,
    email: str,
    ou: str,
    region: str,
) -> None:
    """
    Find the newly created account by email (with retries) then apply the blueprint.
    Falls back gracefully if the account cannot be located.
    """
    renderer.console.print(
        f"\n[dim]Locating new account by email ({email})...[/dim]"
    )
    account_id: str | None = None
    for attempt in range(3):
        account_id = af_api.find_account_by_email(email=email, ou_id=ou)
        if account_id:
            break
        if attempt < 2:
            renderer.console.print(
                "[dim]Account not yet visible in Organizations. Retrying in 5s...[/dim]"
            )
            time.sleep(5)

    if not account_id:
        err.print(
            f"[bold yellow]Warning:[/bold yellow] Could not find account with email '{email}' "
            f"in OU {ou}. Apply blueprint manually with:\n"
            f"  standstill blueprint apply --file {blueprint_path} --account <ACCOUNT_ID>"
        )
        return

    renderer.console.print(f"[dim]Found account [bold]{account_id}[/bold].[/dim]")
    _run_blueprint_on_account(
        blueprint_path=blueprint_path,
        account_id=account_id,
        region=region,
    )


def _print_account_detail(info: dict) -> None:
    status = info.get("Status", "UNKNOWN")
    sc = _STATUS_COLOR.get(status, "dim")
    joined = info.get("JoinedTimestamp", "")
    if hasattr(joined, "strftime"):
        joined = joined.strftime("%Y-%m-%d")

    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Value")
    t.add_row("Account ID", info.get("Id", "—"))
    t.add_row("Name", info.get("Name", "—"))
    t.add_row("Email", info.get("Email", "—"))
    t.add_row("Status", f"[{sc}]{status}[/{sc}]")
    t.add_row("ARN", f"[dim]{info.get('Arn', '—')}[/dim]")
    t.add_row("Parent OU / Root", info.get("ParentId", "—"))
    t.add_row("Joined", str(joined) if joined else "—")
    t.add_row("Join method", info.get("JoinedMethod", "—"))
    renderer.console.print(Panel(t, title="[bold]Account[/bold]", expand=False))


def _poll_with_progress(op_id: str, timeout: int, poll_interval: int = 15) -> dict:
    """Poll an account factory operation, printing elapsed time at each interval."""
    from botocore.exceptions import ClientError as _ClientError

    from standstill import state as _state

    start = time.monotonic()
    deadline = start + timeout
    throttle_count = 0

    time.sleep(min(10, poll_interval))

    while time.monotonic() < deadline:
        try:
            ct = _state.state.get_client("controltower")
            resp = ct.get_landing_zone_operation(operationIdentifier=op_id)
            op = resp.get("operationDetails", {})
            throttle_count = 0
            elapsed = int(time.monotonic() - start)
            mins, secs = divmod(elapsed, 60)
            op_type = op.get("operationType", "ACCOUNT_OPERATION")
            renderer.console.print(
                f"  [dim][{mins:02d}:{secs:02d}][/dim]  {op_type} — [cyan]{op.get('status', '...')}[/cyan]"
            )
            if op.get("status") in {"SUCCEEDED", "FAILED"}:
                return op
        except _ClientError as e:
            code = e.response["Error"]["Code"]
            if code in {"ThrottlingException", "Throttling", "RequestThrottled"}:
                throttle_count += 1
                time.sleep(min(poll_interval * (2 ** throttle_count), 120))
                continue
            raise
        time.sleep(poll_interval)

    raise TimeoutError(
        f"Operation {op_id} did not complete within {timeout}s. "
        "Account factory operations can take 10–30 minutes."
    )

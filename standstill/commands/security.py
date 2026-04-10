from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Optional

import click
import typer
import yaml
from rich.console import Console
from rich.panel import Panel

import standstill.config as _config
from standstill import state as _state
from standstill.aws import security_services as sec_api
from standstill.display import renderer
from standstill.models.security_config import load_config

app = typer.Typer(no_args_is_help=True, help="Manage delegated security services across the org.")
err = Console(stderr=True)

_DEFAULT_FILE = Path("security_services.yaml")
_DEFAULT_ROLE = "AWSControlTowerExecution"
_ACCT_RE = re.compile(r"^\d{12}$")

_DEFAULT_TEMPLATE = (
    Path(__file__).parent.parent / "data" / "security_services_default.yaml"
)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@app.command("init")
def init(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Path for the generated config file."),
    ] = _DEFAULT_FILE,
) -> None:
    """
    Interactively generate a security services configuration file.

    Walks through each service with cost notes so you can make informed
    decisions before committing to any spend.
    """
    console = renderer.console

    console.print(Panel(
        "[bold]Standstill — Security Services Setup[/bold]\n\n"
        "This wizard creates a YAML configuration file for managing\n"
        "GuardDuty, Security Hub, Macie, Inspector, and Access Analyzer\n"
        "at the AWS Organizations level via a delegated administrator account.",
        expand=False,
    ))
    console.print()

    # ── Delegated admin account ─────────────────────────────────────────────
    console.print("[bold cyan]Delegated Administrator Account[/bold cyan]")
    console.print(
        "[dim]All security services will be managed from this account.\n"
        "It should be a dedicated security tooling account, not the management account.[/dim]"
    )
    while True:
        delegated_admin = typer.prompt("\nDelegated admin account ID")
        if _ACCT_RE.match(delegated_admin):
            break
        err.print("[bold red]Invalid account ID.[/bold red] Expected 12 digits.")

    cfg: dict = {"version": "1", "delegated_admin_account": delegated_admin, "services": {}}
    services = cfg["services"]

    # ── GuardDuty ────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]GuardDuty[/bold cyan]")
    console.print("[dim]Threat detection across all org accounts.[/dim]")
    gd_enabled = typer.confirm("Enable GuardDuty?", default=True)
    services["guardduty"] = {"enabled": gd_enabled}
    if gd_enabled:
        console.print(
            "[dim]Finding publishing frequency: SIX_HOURS is sufficient for compliance "
            "and most cost-effective.[/dim]"
        )
        freq = typer.prompt(
            "Finding publishing frequency",
            default="SIX_HOURS",
            type=click.Choice(["SIX_HOURS", "ONE_HOUR", "FIFTEEN_MINUTES"], case_sensitive=False),
        )
        auto = typer.prompt(
            "Auto-enable in org accounts",
            default="ALL",
            type=click.Choice(["ALL", "NEW", "NONE"], case_sensitive=False),
        )
        console.print("[dim]Protection plans — each adds incremental cost.[/dim]")
        s3 = typer.confirm("  Enable S3 data event detection?", default=True)
        rds = typer.confirm("  Enable RDS login anomaly detection?", default=True)
        eks = typer.confirm("  Enable EKS audit logs?", default=False)
        console.print("[dim]  ⚠  Malware scanning is charged per GB scanned.[/dim]")
        malware = typer.confirm("  Enable EC2 malware scanning?", default=False)
        lambda_net = typer.confirm("  Enable Lambda network logs?", default=False)
        services["guardduty"].update({
            "detector": {"finding_publishing_frequency": freq.upper()},
            "organization": {"auto_enable": auto.upper()},
            "protection_plans": {
                "s3_logs": s3, "rds_login_events": rds, "eks_audit_logs": eks,
                "ec2_malware_scan": malware, "lambda_network_logs": lambda_net,
                "eks_runtime": False, "ecs_runtime": False,
            },
        })

    # ── Security Hub ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Security Hub[/bold cyan]")
    console.print(
        "[dim]Aggregated security findings. Cost: ~$0.001/check/account/month.\n"
        "Enable only standards you actively monitor and remediate.[/dim]"
    )
    sh_enabled = typer.confirm("Enable Security Hub?", default=True)
    services["security_hub"] = {"enabled": sh_enabled}
    if sh_enabled:
        auto = typer.prompt(
            "Auto-enable in org accounts",
            default="ALL",
            type=click.Choice(["ALL", "NEW", "NONE"], case_sensitive=False),
        )
        fsbp = typer.confirm("  Enable FSBP standard? (recommended)", default=True)
        cis14 = typer.confirm("  Enable CIS 1.4 benchmark?", default=False)
        cis30 = typer.confirm("  Enable CIS 3.0 benchmark?", default=False)
        pci = typer.confirm("  Enable PCI DSS?", default=False)
        nist = typer.confirm("  Enable NIST 800-53?", default=False)
        console.print("[dim]  ⚠  Cross-region aggregation bills findings twice.[/dim]")
        cross_region = typer.confirm("  Enable cross-region aggregation?", default=False)
        services["security_hub"].update({
            "organization": {"auto_enable": auto.upper()},
            "standards": {
                "fsbp": fsbp, "cis_1_4": cis14, "cis_3_0": cis30,
                "pci_dss": pci, "nist": nist,
            },
            "cross_region_aggregation": cross_region,
        })

    # ── Macie ────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Macie[/bold cyan]")
    console.print("[dim]Sensitive data discovery. Cost: $1/S3 bucket/month for evaluation.[/dim]")
    mc_enabled = typer.confirm("Enable Macie?", default=True)
    services["macie"] = {"enabled": mc_enabled}
    if mc_enabled:
        freq = typer.prompt(
            "Finding publishing frequency",
            default="SIX_HOURS",
            type=click.Choice(["SIX_HOURS", "ONE_HOUR", "FIFTEEN_MINUTES"], case_sensitive=False),
        )
        console.print(
            "[bold yellow]  ⚠  Automated sensitive data discovery scans ALL S3 object content.\n"
            "     Can be very expensive in accounts with large data lakes.[/bold yellow]"
        )
        discovery = typer.confirm("  Enable automated sensitive data discovery?", default=False)
        sampling = 100
        if discovery:
            console.print("[dim]  Sampling depth (1–100%). Lower = cheaper but less coverage.[/dim]")
            sampling = typer.prompt("  Sampling depth %", default=100, type=int)
        services["macie"].update({
            "organization": {"auto_enable": True},
            "session": {"finding_publishing_frequency": freq.upper()},
            "automated_discovery": {
                "enabled": discovery,
                "sampling_depth": max(1, min(100, sampling)),
                "managed_identifiers": "RECOMMENDED",
            },
        })

    # ── Inspector ────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Inspector[/bold cyan]")
    console.print(
        "[dim]Vulnerability scanning. Cost: per EC2 instance, per ECR image push, "
        "per Lambda function/month.[/dim]"
    )
    ins_enabled = typer.confirm("Enable Inspector?", default=True)
    services["inspector"] = {"enabled": ins_enabled}
    if ins_enabled:
        ec2 = typer.confirm("  Enable EC2 scanning?", default=True)
        ecr = typer.confirm("  Enable ECR image scanning?", default=True)
        console.print("[dim]  ⚠  Lambda scanning adds cost per function per month.[/dim]")
        lam = typer.confirm("  Enable Lambda scanning?", default=False)
        lam_code = typer.confirm("  Enable Lambda code scanning?", default=False) if lam else False
        services["inspector"].update({
            "organization": {"auto_enable": True},
            "scan_types": {"ec2": ec2, "ecr": ecr, "lambda": lam, "lambda_code": lam_code},
        })

    # ── Access Analyzer ──────────────────────────────────────────────────────
    console.print("\n[bold cyan]Access Analyzer[/bold cyan]")
    console.print("[dim]Identifies unintended external access to org resources.[/dim]")
    aa_enabled = typer.confirm("Enable Access Analyzer?", default=True)
    services["access_analyzer"] = {"enabled": aa_enabled}
    if aa_enabled:
        analyzers = [{"name": "standstill-org-analyzer", "type": "ORGANIZATION"}]
        console.print(
            "[bold yellow]  ⚠  Unused access analyzer costs ~$1.20/IAM role/month.[/bold yellow]"
        )
        unused = typer.confirm("  Enable unused access analyzer?", default=False)
        if unused:
            analyzers.append(
                {"name": "standstill-unused-access-analyzer", "type": "ORGANIZATION_UNUSED_ACCESS"}
            )
        services["access_analyzer"]["analyzers"] = analyzers

    # ── Write file ───────────────────────────────────────────────────────────
    header = (
        "# Standstill — Security Services Configuration\n"
        "# Generated by: standstill security init\n"
        "# Apply:   standstill security apply --file security_services.yaml\n"
        "# Dry run: standstill security apply --file security_services.yaml --dry-run\n"
        "# Status:  standstill security status --file security_services.yaml\n\n"
    )
    output.write_text(header + yaml.dump(cfg, default_flow_style=False, sort_keys=False))
    console.print(f"\n[green]✓[/green] Config written to [cyan]{output}[/cyan]")
    console.print(
        f"\n[dim]Review the file, then apply:\n"
        f"  standstill security apply --file {output} --dry-run[/dim]"
    )


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------

@app.command("apply")
def apply(
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Security services YAML config file."),
    ] = _DEFAULT_FILE,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role to assume in the delegated admin account."),
    ] = _DEFAULT_ROLE,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show the plan without making changes."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """
    Enable and configure security services at AWS Organizations level.

    \b
    Two-phase execution:
      Phase 1 — Register the delegated administrator for each enabled service
                (called from the management account)
      Phase 2 — Configure each service's org settings from the delegated admin
                (called by assuming the CT execution role there)

    \b
    Examples:
      standstill security apply --file security_services.yaml --dry-run
      standstill security apply --file security_services.yaml --yes
    """
    try:
        config = load_config(file)
    except (FileNotFoundError, ValueError) as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)

    region = _state.state.region or "us-east-1"

    # ── Plan ─────────────────────────────────────────────────────────────────
    with renderer.console.status("[bold]Checking current delegation status...[/bold]"):
        delegation = sec_api.check_delegated_admins(config.delegated_admin_account, region)

    renderer.render_security_plan(config, delegation)

    if dry_run:
        renderer.console.print("\n[bold yellow]Dry run — no changes applied.[/bold yellow]")
        return

    if not yes:
        typer.confirm("\nProceed with apply?", abort=True)

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    renderer.console.print("\n[bold]Phase 1 — Delegated Admin Registration[/bold]")
    with renderer.console.status("[bold]Registering delegated administrators...[/bold]"):
        phase1, phase2 = sec_api.apply_services(config, role_name, region)

    renderer.render_security_results(phase1, "Phase 1")

    failed_p1 = [r for r in phase1 if not r.success]
    if failed_p1:
        err.print(
            f"\n[bold red]{len(failed_p1)} delegation(s) failed — "
            "Phase 2 skipped for affected services.[/bold red]"
        )

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    renderer.console.print("\n[bold]Phase 2 — Service Configuration[/bold]")
    renderer.render_security_results(phase2, "Phase 2")

    if any(not r.success for r in phase1 + phase2):
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command("status")
def status(
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="Security services YAML (used for delegated admin account ID)."),
    ] = None,
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Delegated admin account ID (overrides --file)."),
    ] = None,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role to assume in the delegated admin account."),
    ] = _DEFAULT_ROLE,
) -> None:
    """
    Show the current state of security services across the org.

    Reads Phase 1 info (delegation) from the management account and
    Phase 2 info (service config) from the delegated admin account.
    """
    # Resolve delegated admin account: explicit flag → file → stored config
    delegated_admin: str | None = account
    if not delegated_admin and file:
        try:
            delegated_admin = load_config(file).delegated_admin_account
        except (FileNotFoundError, ValueError) as exc:
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)
    if not delegated_admin:
        delegated_admin = _config.get_delegated_admin()

    if not delegated_admin:
        err.print(
            "[bold red]Error:[/bold red] Delegated admin account not set.\n"
            "[dim]Provide --account <id>, --file <config.yaml>, or run:\n"
            "  standstill config set-delegated-admin <account-id>[/dim]"
        )
        raise typer.Exit(1)

    if not _ACCT_RE.match(delegated_admin):
        err.print(f"[bold red]Error:[/bold red] Invalid account ID: {delegated_admin}")
        raise typer.Exit(1)

    region = _state.state.region or "us-east-1"

    with renderer.console.status("[bold]Fetching security service status...[/bold]"):
        statuses = sec_api.get_service_statuses(delegated_admin, role_name, region)

    renderer.render_security_status(statuses)


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------

@app.command("assess")
def assess(
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="Security services YAML (resolves delegated admin + which services to check)."),
    ] = None,
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Delegated admin account ID (overrides --file)."),
    ] = None,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role to assume in the delegated admin account."),
    ] = _DEFAULT_ROLE,
    all_accounts: Annotated[
        bool,
        typer.Option("--all", help="Show every account, not just those with gaps."),
    ] = False,
) -> None:
    """
    Check every org account for security service coverage.

    For each account reports whether it is an active member of GuardDuty,
    Security Hub, Macie, and Inspector in the delegated admin account, which
    means findings are flowing centrally.  Access Analyzer is org-wide so it
    is marked as covered automatically when the org analyzer exists.

    \b
    Examples:
      standstill security assess --file security_services.yaml
      standstill security assess --account 123456789012 --all
    """
    # Resolve config
    config = None
    delegated_admin: str | None = account

    if file:
        try:
            config = load_config(file)
            if not delegated_admin:
                delegated_admin = config.delegated_admin_account
        except (FileNotFoundError, ValueError) as exc:
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if not delegated_admin:
        delegated_admin = _config.get_delegated_admin()

    if not delegated_admin:
        err.print(
            "[bold red]Error:[/bold red] Delegated admin account not set.\n"
            "[dim]Provide --account <id>, --file <config.yaml>, or run:\n"
            "  standstill config set-delegated-admin <account-id>[/dim]"
        )
        raise typer.Exit(1)

    if not _ACCT_RE.match(delegated_admin):
        err.print(f"[bold red]Error:[/bold red] Invalid account ID: {delegated_admin}")
        raise typer.Exit(1)

    # When no YAML is provided, build a default all-enabled config so we check every service.
    if config is None:
        from standstill.models.security_config import (
            SecurityServicesConfig,
            ServicesConfig,
        )
        config = SecurityServicesConfig(
            delegated_admin_account=delegated_admin,
            services=ServicesConfig(),
        )

    region = _state.state.region or "us-east-1"

    # Which services are enabled according to the config
    svc_cfg = config.services
    active_services = [
        svc for svc, enabled in [
            ("guardduty",       svc_cfg.guardduty.enabled),
            ("security_hub",    svc_cfg.security_hub.enabled),
            ("macie",           svc_cfg.macie.enabled),
            ("inspector",       svc_cfg.inspector.enabled),
            ("access_analyzer", svc_cfg.access_analyzer.enabled),
        ]
        if enabled
    ]

    with renderer.console.status(
        "[bold]Querying org accounts and member lists from the delegated admin...[/bold]"
    ):
        try:
            results = sec_api.assess_member_accounts(config, role_name, region)
        except Exception as exc:
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    renderer.render_security_assessment(results, active_services, show_all=all_accounts)

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Optional

import click
import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import standstill.config as _config
from standstill import state as _state
from standstill.aws import security_services as sec_api
from standstill.display import renderer
from standstill.models.security_config import SecurityServicesConfig, load_config

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
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="Existing config file to use as defaults."),
    ] = None,
) -> None:
    """
    Interactively generate a security services configuration file.

    Walks through each service with cost notes so you can make informed
    decisions before committing to any spend.

    If an existing config file is found (via --file or the default location),
    its values are used as defaults and you can choose which services to reconfigure.
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

    # ── Load existing config ─────────────────────────────────────────────────
    existing: SecurityServicesConfig | None = None
    existing_raw: dict = {}
    input_path = file or (_DEFAULT_FILE if _DEFAULT_FILE.exists() else None)
    if input_path:
        try:
            existing = load_config(input_path)
            existing_raw = yaml.safe_load(input_path.read_text()) or {}
            console.print(
                f"[dim]Loaded existing config from [cyan]{input_path}[/cyan] — "
                "existing values shown as defaults.[/dim]\n"
            )
        except (FileNotFoundError, ValueError) as exc:
            if file:
                err.print(f"[bold red]Error:[/bold red] {exc}")
                raise typer.Exit(1)

    # ── Delegated admin account ─────────────────────────────────────────────
    console.print("[bold cyan]Delegated Administrator Account[/bold cyan]")
    console.print(
        "[dim]All security services will be managed from this account.\n"
        "It should be a dedicated security tooling account, not the management account.[/dim]"
    )
    _stored_admin = (
        existing.delegated_admin_account if existing else None
    ) or _config.get_delegated_admin()
    while True:
        delegated_admin = typer.prompt(
            "\nDelegated admin account ID",
            default=_stored_admin if _stored_admin else ...,
        )
        if _ACCT_RE.match(delegated_admin):
            break
        err.print("[bold red]Invalid account ID.[/bold red] Expected 12 digits.")

    # ── Service selection ────────────────────────────────────────────────────
    console.print("\n[bold cyan]Services to Configure[/bold cyan]")
    if existing:
        console.print("[dim]Select which services to reconfigure. Others keep their current settings.[/dim]")
    else:
        console.print("[dim]Select which services to configure.[/dim]")

    configure_gd  = typer.confirm("  Configure GuardDuty?",       default=True)
    configure_sh  = typer.confirm("  Configure Security Hub?",     default=True)
    configure_mc  = typer.confirm("  Configure Macie?",            default=True)
    configure_ins = typer.confirm("  Configure Inspector?",        default=True)
    configure_aa  = typer.confirm("  Configure Access Analyzer?",  default=True)

    # ── Start from existing raw config or blank ──────────────────────────────
    cfg: dict = dict(existing_raw) if existing_raw else {"version": "1", "services": {}}
    cfg["delegated_admin_account"] = delegated_admin
    if "services" not in cfg:
        cfg["services"] = {}
    services = cfg["services"]

    # ── GuardDuty ────────────────────────────────────────────────────────────
    if configure_gd:
        ex = existing.services.guardduty if existing else None
        console.print("\n[bold cyan]GuardDuty[/bold cyan]")
        console.print("[dim]Threat detection across all org accounts.[/dim]")
        gd_enabled = typer.confirm("Enable GuardDuty?", default=ex.enabled if ex else True)
        services["guardduty"] = {"enabled": gd_enabled}
        if gd_enabled:
            console.print(
                "[dim]Finding publishing frequency: SIX_HOURS is sufficient for compliance "
                "and most cost-effective.[/dim]"
            )
            freq = typer.prompt(
                "Finding publishing frequency",
                default=ex.detector.finding_publishing_frequency if ex else "SIX_HOURS",
                type=click.Choice(["SIX_HOURS", "ONE_HOUR", "FIFTEEN_MINUTES"], case_sensitive=False),
            )
            auto = typer.prompt(
                "Auto-enable in org accounts",
                default=ex.organization.auto_enable if ex else "ALL",
                type=click.Choice(["ALL", "NEW", "NONE"], case_sensitive=False),
            )
            pp = ex.protection_plans if ex else None
            console.print("[dim]Protection plans — each adds incremental cost.[/dim]")
            s3        = typer.confirm("  Enable S3 data event detection?",      default=pp.s3_logs            if pp else True)
            rds       = typer.confirm("  Enable RDS login anomaly detection?",  default=pp.rds_login_events   if pp else True)
            eks       = typer.confirm("  Enable EKS audit logs?",               default=pp.eks_audit_logs     if pp else False)
            console.print("[dim]  ⚠  Malware scanning is charged per GB scanned.[/dim]")
            malware   = typer.confirm("  Enable EC2 malware scanning?",         default=pp.ec2_malware_scan   if pp else False)
            lambda_net = typer.confirm("  Enable Lambda network logs?",         default=pp.lambda_network_logs if pp else False)
            services["guardduty"].update({
                "detector": {"finding_publishing_frequency": freq.upper()},
                "organization": {"auto_enable": auto.upper()},
                "protection_plans": {
                    "s3_logs": s3, "rds_login_events": rds, "eks_audit_logs": eks,
                    "ec2_malware_scan": malware, "lambda_network_logs": lambda_net,
                    "eks_runtime": pp.eks_runtime if pp else False,
                    "ecs_runtime": pp.ecs_runtime if pp else False,
                },
            })

    # ── Security Hub ─────────────────────────────────────────────────────────
    if configure_sh:
        ex = existing.services.security_hub if existing else None
        console.print("\n[bold cyan]Security Hub[/bold cyan]")
        console.print(
            "[dim]Aggregated security findings. Cost: ~$0.001/check/account/month.\n"
            "Enable only standards you actively monitor and remediate.[/dim]"
        )
        sh_enabled = typer.confirm("Enable Security Hub?", default=ex.enabled if ex else True)
        services["security_hub"] = {"enabled": sh_enabled}
        if sh_enabled:
            auto = typer.prompt(
                "Auto-enable in org accounts",
                default=ex.organization.auto_enable if ex else "ALL",
                type=click.Choice(["ALL", "NEW", "NONE"], case_sensitive=False),
            )
            st = ex.standards if ex else None
            fsbp       = typer.confirm("  Enable FSBP standard? (recommended)", default=st.fsbp    if st else True)
            cis14      = typer.confirm("  Enable CIS 1.4 benchmark?",           default=st.cis_1_4 if st else False)
            cis30      = typer.confirm("  Enable CIS 3.0 benchmark?",           default=st.cis_3_0 if st else False)
            pci        = typer.confirm("  Enable PCI DSS?",                     default=st.pci_dss if st else False)
            nist       = typer.confirm("  Enable NIST 800-53?",                 default=st.nist    if st else False)
            console.print("[dim]  ⚠  Cross-region aggregation bills findings twice.[/dim]")
            cross_region = typer.confirm(
                "  Enable cross-region aggregation?",
                default=ex.cross_region_aggregation if ex else False,
            )
            services["security_hub"].update({
                "organization": {"auto_enable": auto.upper()},
                "standards": {
                    "fsbp": fsbp, "cis_1_4": cis14, "cis_3_0": cis30,
                    "pci_dss": pci, "nist": nist,
                },
                "cross_region_aggregation": cross_region,
            })

    # ── Macie ────────────────────────────────────────────────────────────────
    if configure_mc:
        ex = existing.services.macie if existing else None
        console.print("\n[bold cyan]Macie[/bold cyan]")
        console.print("[dim]Sensitive data discovery. Cost: $1/S3 bucket/month for evaluation.[/dim]")
        mc_enabled = typer.confirm("Enable Macie?", default=ex.enabled if ex else True)
        services["macie"] = {"enabled": mc_enabled}
        if mc_enabled:
            freq = typer.prompt(
                "Finding publishing frequency",
                default=ex.session.finding_publishing_frequency if ex else "SIX_HOURS",
                type=click.Choice(["SIX_HOURS", "ONE_HOUR", "FIFTEEN_MINUTES"], case_sensitive=False),
            )
            console.print(
                "[bold yellow]  ⚠  Automated sensitive data discovery scans ALL S3 object content.\n"
                "     Can be very expensive in accounts with large data lakes.[/bold yellow]"
            )
            ad = ex.automated_discovery if ex else None
            discovery = typer.confirm(
                "  Enable automated sensitive data discovery?",
                default=ad.enabled if ad else False,
            )
            sampling = 100
            if discovery:
                console.print("[dim]  Sampling depth (1–100%). Lower = cheaper but less coverage.[/dim]")
                sampling = typer.prompt(
                    "  Sampling depth %",
                    default=ad.sampling_depth if ad else 100,
                    type=int,
                )
            services["macie"].update({
                "organization": {"auto_enable": True},
                "session": {"finding_publishing_frequency": freq.upper()},
                "automated_discovery": {
                    "enabled": discovery,
                    "sampling_depth": max(1, min(100, sampling)),
                    "managed_identifiers": ad.managed_identifiers if ad else "RECOMMENDED",
                },
            })

    # ── Inspector ────────────────────────────────────────────────────────────
    if configure_ins:
        ex = existing.services.inspector if existing else None
        console.print("\n[bold cyan]Inspector[/bold cyan]")
        console.print(
            "[dim]Vulnerability scanning. Cost: per EC2 instance, per ECR image push, "
            "per Lambda function/month.[/dim]"
        )
        ins_enabled = typer.confirm("Enable Inspector?", default=ex.enabled if ex else True)
        services["inspector"] = {"enabled": ins_enabled}
        if ins_enabled:
            sc = ex.scan_types if ex else None
            ec2 = typer.confirm("  Enable EC2 scanning?",   default=sc.ec2             if sc else True)
            ecr = typer.confirm("  Enable ECR image scanning?", default=sc.ecr          if sc else True)
            console.print("[dim]  ⚠  Lambda scanning adds cost per function per month.[/dim]")
            lam      = typer.confirm("  Enable Lambda scanning?",      default=sc.lambda_functions if sc else False)
            lam_code = typer.confirm("  Enable Lambda code scanning?", default=sc.lambda_code      if sc else False) if lam else False
            services["inspector"].update({
                "organization": {"auto_enable": True},
                "scan_types": {"ec2": ec2, "ecr": ecr, "lambda": lam, "lambda_code": lam_code},
            })

    # ── Access Analyzer ──────────────────────────────────────────────────────
    if configure_aa:
        ex = existing.services.access_analyzer if existing else None
        console.print("\n[bold cyan]Access Analyzer[/bold cyan]")
        console.print("[dim]Identifies unintended external access to org resources.[/dim]")
        aa_enabled = typer.confirm("Enable Access Analyzer?", default=ex.enabled if ex else True)
        services["access_analyzer"] = {"enabled": aa_enabled}
        if aa_enabled:
            ex_types = {a.type for a in ex.analyzers} if ex else set()
            analyzers = [{"name": "standstill-org-analyzer", "type": "ORGANIZATION"}]
            console.print(
                "[bold yellow]  ⚠  Unused access analyzer costs ~$1.20/IAM role/month.[/bold yellow]"
            )
            unused = typer.confirm(
                "  Enable unused access analyzer?",
                default="ORGANIZATION_UNUSED_ACCESS" in ex_types,
            )
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
# import
# ---------------------------------------------------------------------------

_SVC_LABELS_IMPORT = {
    "guardduty":       "GuardDuty",
    "security_hub":    "Security Hub",
    "macie":           "Macie",
    "inspector":       "Inspector",
    "access_analyzer": "Access Analyzer",
}


@app.command("pull")
def pull_cmd(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Path for the generated config file."),
    ] = _DEFAULT_FILE,
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Delegated admin account ID."),
    ] = None,
    role_name: Annotated[
        str,
        typer.Option("--role-name", "-n", help="CT execution role to assume in the delegated admin account."),
    ] = _DEFAULT_ROLE,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Overwrite output file without prompting."),
    ] = False,
) -> None:
    """
    Snapshot live security service config into a local YAML file.

    Reads the current configuration of each service from the delegated admin
    account and writes it as a YAML file ready for use with 'security apply'.

    \b
    Use this to bring an existing deployment under standstill management:
      standstill security pull --account 123456789012
      standstill security apply --file security_services.yaml --dry-run
    """
    console = renderer.console

    # ── Resolve delegated admin ──────────────────────────────────────────────
    delegated_admin = account or _config.get_delegated_admin()
    if not delegated_admin:
        err.print(
            "[bold red]Error:[/bold red] Delegated admin account not set.\n"
            "[dim]Provide --account <id> or run: standstill config set-delegated-admin <id>[/dim]"
        )
        raise typer.Exit(1)
    if not _ACCT_RE.match(delegated_admin):
        err.print(f"[bold red]Error:[/bold red] Invalid account ID: {delegated_admin}")
        raise typer.Exit(1)

    region = _state.state.region or "us-east-1"

    # ── Confirm overwrite ────────────────────────────────────────────────────
    if output.exists() and not yes:
        console.print(f"\n[yellow]{output}[/yellow] already exists.")
        if not typer.confirm("Overwrite?", default=False):
            raise typer.Exit(0)

    # ── Fetch live config ────────────────────────────────────────────────────
    with console.status(
        f"[bold]Reading live service configurations from {delegated_admin}...[/bold]"
    ):
        config_dict, errors = sec_api.read_service_configs(delegated_admin, role_name, region)

    # ── Summary table ────────────────────────────────────────────────────────
    t = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    t.add_column("Service", style="bold")
    t.add_column("Status", justify="center")
    t.add_column("Notes", style="dim")

    for svc, label in _SVC_LABELS_IMPORT.items():
        svc_cfg = config_dict["services"].get(svc, {})
        if svc in errors:
            status_text = Text("error", style="bold red")
            notes = errors[svc][:80]
        elif svc_cfg.get("enabled"):
            status_text = Text("imported", style="bold green")
            notes = ""
        else:
            status_text = Text("disabled", style="dim")
            notes = ""
        t.add_row(label, status_text, notes)

    console.print()
    console.print(t)

    if errors:
        console.print(
            "\n[yellow]Some services could not be read and will be written as disabled.[/yellow]"
        )

    # ── Write file ───────────────────────────────────────────────────────────
    header = (
        "# Standstill — Security Services Configuration\n"
        f"# Pulled from account {delegated_admin} (region {region})\n"
        "# Apply:   standstill security apply --file security_services.yaml\n"
        "# Dry run: standstill security apply --file security_services.yaml --dry-run\n"
        "# Status:  standstill security status --file security_services.yaml\n\n"
    )
    output.write_text(header + yaml.dump(config_dict, default_flow_style=False, sort_keys=False))
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

    \b
    Delegated admin account is resolved in this order:
      1. --account flag
      2. --file (reads delegated_admin_account from the YAML)
      3. Stored config (standstill config set-delegated-admin)
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

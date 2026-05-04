from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console

from standstill import state as _state
from standstill.aws import notifications as notify_api
from standstill.display import renderer
from standstill.display._notifications import (
    render_event_rules,
    render_notification_status,
)

app = typer.Typer(no_args_is_help=True, help="Security finding notification routing.")
err = Console(stderr=True)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command("status")
def notify_status() -> None:
    """Show security notification rules and SNS topics."""
    region = _state.state.region or "us-east-1"

    with renderer.console.status("[bold]Fetching notification resources...[/bold]"):
        try:
            rules = notify_api.list_security_event_rules(region)
            topics = notify_api.list_security_sns_topics(region)
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    render_notification_status(rules, topics)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@app.command("list")
def notify_list() -> None:
    """List security-related EventBridge rules."""
    region = _state.state.region or "us-east-1"

    with renderer.console.status("[bold]Fetching EventBridge rules...[/bold]"):
        try:
            rules = notify_api.list_security_event_rules(region)
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    if not rules:
        renderer.console.print("[dim]No security-related EventBridge rules found.[/dim]")
        return

    render_event_rules(rules)


# ---------------------------------------------------------------------------
# setup (interactive wizard)
# ---------------------------------------------------------------------------

@app.command("setup")
def notify_setup() -> None:
    """
    Interactive wizard to set up security finding notifications.

    Guides you through:
    1. Choosing security event sources
    2. Choosing severity levels
    3. Creating/selecting an SNS topic
    4. Adding email subscriptions
    5. Creating an EventBridge rule
    """
    region = _state.state.region or "us-east-1"
    console = renderer.console

    console.print(
        "[bold]Security Finding Notification Setup[/bold]\n"
        "[dim]This wizard creates an EventBridge rule to route security "
        "findings to an SNS topic.[/dim]\n"
    )

    # Step 1: Choose sources
    console.print("[bold cyan]Step 1: Choose Security Sources[/bold cyan]")
    source_options = [
        ("aws.securityhub", "Security Hub"),
        ("aws.guardduty", "GuardDuty"),
        ("aws.macie2", "Macie"),
        ("aws.inspector2", "Inspector"),
        ("aws.access-analyzer", "Access Analyzer"),
    ]
    selected_sources: list[str] = []
    for source_id, source_name in source_options:
        if typer.confirm(f"  Include {source_name}?", default=True):
            selected_sources.append(source_id)

    if not selected_sources:
        err.print("[bold red]Error:[/bold red] At least one source must be selected.")
        raise typer.Exit(1)

    console.print(f"[green]Selected:[/green] {', '.join(s.replace('aws.', '') for s in selected_sources)}\n")

    # Step 2: Choose severity levels (relevant for Security Hub)
    severity_labels: list[str] | None = None
    if "aws.securityhub" in selected_sources:
        console.print("[bold cyan]Step 2: Choose Severity Levels (Security Hub)[/bold cyan]")
        console.print("[dim]Filter findings by severity. Leave all unchecked to include all severities.[/dim]")
        all_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        chosen: list[str] = []
        for sev in all_severities:
            default = sev in ("CRITICAL", "HIGH")
            if typer.confirm(f"  Include {sev}?", default=default):
                chosen.append(sev)
        severity_labels = chosen if chosen else None
    else:
        console.print("[dim]Step 2: Skipped (no Security Hub sources selected)[/dim]")

    console.print()

    # Step 3: Create or use existing SNS topic
    console.print("[bold cyan]Step 3: SNS Topic[/bold cyan]")
    create_new = typer.confirm("  Create a new SNS topic?", default=True)
    topic_arn: str

    if create_new:
        topic_name = typer.prompt("  Topic name", default="security-findings-notifications")
        with console.status(f"[bold]Creating SNS topic '{topic_name}'...[/bold]"):
            try:
                topic_arn = notify_api.create_sns_topic(name=topic_name, region=region)
            except Exception as e:
                err.print(f"[bold red]Error:[/bold red] {e}")
                raise typer.Exit(1)
        console.print(f"[green]✓[/green] Topic created: [cyan]{topic_arn}[/cyan]")
    else:
        topic_arn = typer.prompt("  Existing topic ARN")

    console.print()

    # Step 4: Add email subscription
    console.print("[bold cyan]Step 4: Email Subscription (optional)[/bold cyan]")
    if typer.confirm("  Add an email subscription?", default=True):
        email = typer.prompt("  Email address")
        with console.status("[bold]Subscribing email...[/bold]"):
            try:
                sub_arn = notify_api.subscribe_email(topic_arn=topic_arn, email=email)
                console.print(
                    f"[green]✓[/green] Subscription created. "
                    f"[dim]A confirmation email will be sent to {email}.[/dim]"
                )
            except Exception as e:
                err.print(f"[bold yellow]Warning:[/bold yellow] Could not subscribe email: {e}")

    console.print()

    # Step 5: Create EventBridge rule
    console.print("[bold cyan]Step 5: Creating EventBridge Rule[/bold cyan]")
    rule_name = typer.prompt("  Rule name", default="security-findings-rule")

    with console.status("[bold]Creating EventBridge rule...[/bold]"):
        try:
            rule = notify_api.create_finding_rule(
                name=rule_name,
                sources=selected_sources,
                topic_arn=topic_arn,
                severity_labels=severity_labels,
                region=region,
            )
        except Exception as e:
            err.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    console.print(f"[green]✓[/green] Rule created: [cyan]{rule.name}[/cyan]")
    console.print(f"  ARN: [dim]{rule.arn}[/dim]")
    console.print()

    # Step 6: SNS topic policy reminder
    console.print("[bold yellow]Important: SNS Topic Policy Required[/bold yellow]")
    console.print(
        "[dim]EventBridge needs permission to publish to your SNS topic.\n"
        "Add the following statement to your SNS topic policy:[/dim]\n"
    )

    import json
    policy_statement = {
        "Sid": "AllowEventBridgePublish",
        "Effect": "Allow",
        "Principal": {
            "Service": "events.amazonaws.com"
        },
        "Action": "sns:Publish",
        "Resource": topic_arn,
        "Condition": {
            "ArnEquals": {
                "aws:SourceArn": rule.arn
            }
        }
    }
    console.print_json(json.dumps(policy_statement, indent=2))
    console.print()
    console.print(
        "[dim]Add this to the SNS topic policy via:\n"
        f"  aws sns set-topic-attributes --topic-arn {topic_arn} "
        "--attribute-name Policy --attribute-value '<POLICY_JSON>'[/dim]"
    )

    console.print(
        "\n[bold green]✓ Setup complete![/bold green]\n"
        f"[dim]Rule [cyan]{rule.name}[/cyan] will route findings from "
        f"{', '.join(s.replace('aws.', '') for s in selected_sources)} "
        f"to [cyan]{topic_arn.split(':')[-1]}[/cyan][/dim]"
    )

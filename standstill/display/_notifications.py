from __future__ import annotations

import json

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from standstill.aws.notifications import EventRule, SNSTopic

console = Console()


def _parse_sources(pattern_str: str) -> str:
    """Parse source services from an event pattern JSON string."""
    if not pattern_str:
        return "—"
    try:
        pattern = json.loads(pattern_str)
        sources = pattern.get("source", [])
        # Strip the "aws." prefix for display
        short = [s.replace("aws.", "") for s in sources]
        return ", ".join(short) if short else "—"
    except (json.JSONDecodeError, ValueError):
        return "—"


def render_notification_status(rules: list[EventRule], topics: list[SNSTopic]) -> None:
    """Render two panels: one for EventBridge rules, one for SNS topics."""
    # EventBridge rules panel
    if rules:
        render_event_rules(rules)
    else:
        console.print(Panel(
            "[dim]No security-related EventBridge rules found.[/dim]",
            title="[bold]EventBridge Security Rules[/bold]",
            expand=False,
        ))

    # SNS topics panel
    if topics:
        render_sns_topics(topics)
    else:
        console.print(Panel(
            "[dim]No security-related SNS topics found.[/dim]",
            title="[bold]Security SNS Topics[/bold]",
            expand=False,
        ))


def render_event_rules(rules: list[EventRule]) -> None:
    """Render EventBridge rules table."""
    t = Table(box=box.ROUNDED, show_lines=False, title="[bold]EventBridge Security Rules[/bold]")
    t.add_column("Name", style="bold")
    t.add_column("State", justify="center", no_wrap=True)
    t.add_column("Sources", style="yellow")
    t.add_column("Targets", justify="right")

    for rule in sorted(rules, key=lambda r: r.name):
        state_icon = (
            Text("✓ ENABLED", style="bold green")
            if rule.state == "ENABLED"
            else Text("✗ DISABLED", style="bold red")
        )
        sources = _parse_sources(rule.event_pattern)
        target_count = len(rule.target_arns)
        targets_str = (
            f"{target_count}  [dim]{rule.target_arns[0].split(':')[-1]}[/dim]"
            if target_count == 1 else str(target_count)
        )
        t.add_row(rule.name, state_icon, sources, targets_str)

    console.print(t)
    console.print(f"\n[dim]Total: {len(rules)} rule(s)[/dim]")


def render_sns_topics(topics: list[SNSTopic]) -> None:
    """Render SNS topics table."""
    t = Table(box=box.ROUNDED, show_lines=False, title="[bold]Security SNS Topics[/bold]")
    t.add_column("Name", style="bold")
    t.add_column("ARN", style="dim")
    t.add_column("Subscriptions", justify="right")

    for topic in sorted(topics, key=lambda x: x.name):
        sub_count = len(topic.subscriptions)
        if sub_count > 0:
            # Summarize: email x, sqs y, etc.
            protocol_counts: dict[str, int] = {}
            for sub in topic.subscriptions:
                p = sub.get("Protocol", "unknown")
                protocol_counts[p] = protocol_counts.get(p, 0) + 1
            summary = ", ".join(f"{p}:{n}" for p, n in protocol_counts.items())
            sub_str = f"{sub_count}  [dim]{summary}[/dim]"
        else:
            sub_str = "[dim]0[/dim]"

        t.add_row(topic.name, topic.arn, sub_str)

    console.print(t)
    console.print(f"\n[dim]Total: {len(topics)} topic(s)[/dim]")

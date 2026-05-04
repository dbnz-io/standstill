from __future__ import annotations

import json

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from standstill.aws.scp import SCPPolicy, SCPTarget

console = Console()


def render_scp_list(policies: list[SCPPolicy]) -> None:
    """Render a table of SCPs."""
    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Name", style="bold")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("AWS Managed", justify="center", no_wrap=True)
    t.add_column("Description", style="dim")

    for p in sorted(policies, key=lambda x: (x.aws_managed, x.name)):
        managed_icon = Text("✓", style="bold green") if p.aws_managed else Text("✗", style="dim")
        t.add_row(p.name, p.id, managed_icon, p.description or "—")

    console.print(t)
    console.print(f"\n[dim]Total: {len(policies)} SCP(s)[/dim]")


def render_scp_detail(policy: SCPPolicy, content: str, targets: list[SCPTarget]) -> None:
    """Render SCP details including policy content and targets."""
    # Metadata table
    meta = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    meta.add_column("Key", style="bold cyan")
    meta.add_column("Value")
    meta.add_row("Name", policy.name)
    meta.add_row("ID", policy.id)
    meta.add_row("ARN", f"[dim]{policy.arn}[/dim]")
    meta.add_row("Description", policy.description or "—")
    managed_text = Text("Yes (AWS-managed)", style="bold green") if policy.aws_managed else Text("No (custom)", style="dim")
    meta.add_row("AWS Managed", managed_text)
    console.print(Panel(meta, title=f"[bold]SCP: {policy.name}[/bold]", expand=False))

    # Policy content
    console.print("\n[bold]Policy Content:[/bold]")
    try:
        parsed = json.loads(content)
        console.print_json(json.dumps(parsed, indent=2))
    except (json.JSONDecodeError, ValueError):
        console.print(f"[dim]{content}[/dim]")

    # Targets table
    console.print(f"\n[bold]Targets ({len(targets)}):[/bold]")
    if targets:
        t = Table(box=box.ROUNDED, show_lines=False)
        t.add_column("Name", style="bold")
        t.add_column("Target ID", style="cyan", no_wrap=True)
        t.add_column("Type", style="yellow", no_wrap=True)
        t.add_column("ARN", style="dim")
        for tgt in sorted(targets, key=lambda x: (x.type, x.name)):
            t.add_row(tgt.name, tgt.target_id, tgt.type, tgt.arn)
        console.print(t)
    else:
        console.print("[dim]No targets attached.[/dim]")


def render_scp_audit(nodes: list, target_scp_map: dict[str, list[SCPPolicy]]) -> None:
    """
    Render a tree view showing OUs and accounts with their attached SCPs.
    Skips nodes that only have FullAWSAccess.
    """
    def _is_custom(scps: list[SCPPolicy]) -> bool:
        return any(not p.aws_managed for p in scps)

    def _scp_names(scps: list[SCPPolicy]) -> str:
        custom = [p.name for p in scps if not p.aws_managed]
        return ", ".join(custom) if custom else ""

    def _attach_node(ou_node, parent_branch: Tree) -> None:
        ou_scps = target_scp_map.get(ou_node.id, [])
        scp_label = _scp_names(ou_scps)
        ou_has_custom = _is_custom(ou_scps)

        ou_label = f"[bold yellow]{ou_node.name}[/bold yellow]  [dim]{ou_node.id}[/dim]"
        if ou_has_custom:
            ou_label += f"  [cyan]SCPs: {scp_label}[/cyan]"

        branch = parent_branch.add(ou_label)

        for acct in ou_node.accounts:
            acct_scps = target_scp_map.get(acct.id, [])
            if _is_custom(acct_scps):
                acct_label = (
                    f"[bold]{acct.name}[/bold]  [dim]{acct.id}[/dim]"
                    f"  [cyan]SCPs: {_scp_names(acct_scps)}[/cyan]"
                )
                branch.add(acct_label)

        for child in ou_node.children:
            _attach_node(child, branch)

    tree = Tree("[bold]Organization SCP Audit[/bold]")
    for node in nodes:
        _attach_node(node, tree)

    console.print(tree)
    console.print(
        "\n[dim]Legend:  "
        "[bold yellow]OU name[/bold yellow]  "
        "[cyan]SCPs: ...[/cyan] = custom SCPs attached  "
        "Nodes without custom SCPs are shown without SCP info[/dim]"
    )

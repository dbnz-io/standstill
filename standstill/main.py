from __future__ import annotations

from typing import Annotated, Optional

import typer

from standstill import state as _state
from standstill.commands import accounts as accounts_cmd
from standstill.commands import apply as apply_cmd
from standstill.commands import blueprint as blueprint_cmd
from standstill.commands import catalog as catalog_cmd
from standstill.commands import check as check_cmd
from standstill.commands import config as config_cmd
from standstill.commands import cost as cost_cmd
from standstill.commands import disable as disable_cmd
from standstill.commands import lake as lake_cmd
from standstill.commands import lz as lz_cmd
from standstill.commands import operations as ops_cmd
from standstill.commands import ou as ou_cmd
from standstill.commands import recorder as recorder_cmd
from standstill.commands import security as security_cmd
from standstill.commands import view as view_cmd

app = typer.Typer(
    name="standstill",
    help="[bold]Standstill[/bold] — AWS Control Tower management CLI.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

app.add_typer(view_cmd.app, name="view")
app.add_typer(catalog_cmd.app, name="catalog")
app.add_typer(cost_cmd.app, name="cost")
app.add_typer(ops_cmd.app, name="operations")
app.add_typer(config_cmd.app, name="config")
app.add_typer(accounts_cmd.app, name="accounts")
app.add_typer(blueprint_cmd.app, name="blueprint")
app.add_typer(ou_cmd.app, name="ou")
app.add_typer(recorder_cmd.app, name="recorder")
app.add_typer(security_cmd.app, name="security")
app.add_typer(lake_cmd.app, name="lake")
app.add_typer(lz_cmd.app, name="lz")
app.command("check")(check_cmd.check)
app.command("apply")(apply_cmd.apply)
app.command("disable")(disable_cmd.disable)


@app.callback()
def _global_options(
    profile: Annotated[
        Optional[str],
        typer.Option("--profile", "-p", help="AWS profile name.", envvar="AWS_PROFILE"),
    ] = None,
    region: Annotated[
        Optional[str],
        typer.Option("--region", "-r", help="AWS region.", envvar="AWS_DEFAULT_REGION"),
    ] = None,
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format: table | json | csv"),
    ] = "table",
) -> None:
    _state.state.profile = profile
    _state.state.region = region
    _state.state.output = output
    _state.state.reset()


if __name__ == "__main__":
    app()

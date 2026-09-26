from __future__ import annotations

from typing import Annotated, Optional

import typer
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)
from rich.console import Console

from standstill import state as _state
from standstill.commands import accounts as accounts_cmd
from standstill.commands import apply as apply_cmd
from standstill.commands import blueprint as blueprint_cmd
from standstill.commands import catalog as catalog_cmd
from standstill.commands import check as check_cmd
from standstill.commands import config as config_cmd
from standstill.commands import disable as disable_cmd
from standstill.commands import lake as lake_cmd
from standstill.commands import lz as lz_cmd
from standstill.commands import notifications as notify_cmd
from standstill.commands import operations as ops_cmd
from standstill.commands import ou as ou_cmd
from standstill.commands import recorder as recorder_cmd
from standstill.commands import scp as scp_cmd
from standstill.commands import security as security_cmd
from standstill.commands import sso as sso_cmd
from standstill.commands import view as view_cmd

app = typer.Typer(
    name="standstill",
    help="[bold]Standstill[/bold] — AWS Control Tower management CLI.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    # Expected AWS/runtime errors are handled by main() below with a clean
    # one-line message. Disabling Typer's Rich exception handler prevents the
    # full traceback + locals dump from leaking on e.g. a mistyped profile.
    pretty_exceptions_enable=False,
)

app.add_typer(view_cmd.app, name="view")
app.add_typer(catalog_cmd.app, name="catalog")
app.add_typer(ops_cmd.app, name="operations")
app.add_typer(config_cmd.app, name="config")
app.add_typer(accounts_cmd.app, name="accounts")
app.add_typer(blueprint_cmd.app, name="blueprint")
app.add_typer(ou_cmd.app, name="ou")
app.add_typer(recorder_cmd.app, name="recorder")
app.add_typer(security_cmd.app, name="security")
app.add_typer(lake_cmd.app, name="lake")
app.add_typer(scp_cmd.app, name="scp")
app.add_typer(sso_cmd.app, name="sso")
app.add_typer(notify_cmd.app, name="notify")
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


def _clean_message(exc: BaseException) -> str:
    """Extract a human-readable message from an AWS/runtime exception."""
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "")
        msg = err.get("Message", str(exc))
        return f"{msg} ({code})" if code else msg
    return str(exc)


def _record_audit(exit_code: int) -> None:
    """Best-effort audit record for this invocation (never raises)."""
    try:
        import sys

        from standstill import audit
        audit.record_invocation(
            sys.argv[1:],
            exit_code,
            profile=_state.state.effective_profile,
            region=_state.state.region,
        )
    except Exception:
        pass


def main() -> None:
    """Console-script entry point.

    Wraps the Typer app so that expected AWS and runtime failures surface as a
    single clean ``Error:`` line on stderr with a non-zero exit — the same
    treatment ``check`` already gives them — instead of a raw traceback.
    Unexpected exceptions still propagate so genuine bugs remain visible. Every
    invocation is recorded to the audit log (see standstill.audit) with its exit
    code, centrally so the trail cannot silently omit a mutation.
    """
    err = Console(stderr=True)
    try:
        app()
    except SystemExit as exc:
        # Normal Typer/Click exit path (success or typer.Exit(n)).
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        _record_audit(code)
        raise
    except KeyboardInterrupt:
        err.print("\n[dim]Aborted.[/dim]")
        _record_audit(130)
        raise SystemExit(130)
    except (RuntimeError, ClientError, BotoCoreError, ProfileNotFound, NoCredentialsError) as exc:
        err.print(f"[bold red]Error:[/bold red] {_clean_message(exc)}")
        _record_audit(1)
        raise SystemExit(1)
    else:
        # app() returned without raising SystemExit (rare, but be safe).
        _record_audit(0)


if __name__ == "__main__":
    main()

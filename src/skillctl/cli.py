from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, NoReturn, TypeVar

import typer

from skillctl import __version__
from skillctl.bootstrap import build_runtime
from skillctl.canonical import canonical_json
from skillctl.errors import (
    AdapterFailure,
    ApprovalRequired,
    GovernanceValidationError,
    LedgerCorruption,
    PolicyDenied,
    SafetyViolation,
    StalePlan,
    StateCorruption,
    UnsupportedCapability,
)
from skillctl.portal import run_local_portal


app = typer.Typer(no_args_is_help=True)
T = TypeVar("T")
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9])/(?:[^\s\"']+)")
_PLAN_ID = re.compile(r"plan-[0-9a-f]{32}")
_DEPLOYMENT_ID = re.compile(r"deployment-[0-9a-f]{32}")


class DecisionOption(str, Enum):
    approved = "approved"
    rejected = "rejected"


def _emit(value: object) -> None:
    typer.echo(canonical_json(value).decode("utf-8"))


def _public_message(error: Exception) -> str:
    return _ABSOLUTE_PATH.sub("<redacted>", str(error))


def _fail(error: Exception, exit_code: int) -> NoReturn:
    typer.echo(
        canonical_json({"error": _public_message(error)}).decode("utf-8"),
        err=True,
    )
    raise typer.Exit(exit_code)


def _execute(operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (GovernanceValidationError, PolicyDenied, SafetyViolation) as error:
        _fail(error, 2)
    except ApprovalRequired as error:
        _fail(error, 3)
    except (AdapterFailure, UnsupportedCapability) as error:
        _fail(error, 5)
    except (StalePlan, LedgerCorruption, StateCorruption) as error:
        _fail(error, 6)


def _require_plan_id(plan_id: str) -> None:
    if _PLAN_ID.fullmatch(plan_id) is None:
        raise GovernanceValidationError("cli: invalid plan id")


def _require_deployment_id(deployment_id: str) -> None:
    if _DEPLOYMENT_ID.fullmatch(deployment_id) is None:
        raise GovernanceValidationError("cli: invalid deployment id")


@app.callback()
def main() -> None:
    pass


@app.command()
def version() -> None:
    typer.echo(f"skillctl {__version__}")


@app.command()
def portal(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8000,
    state_dir: Annotated[
        Path, typer.Option("--state-dir")
    ] = Path.home() / ".local" / "state" / "skillctl",
) -> None:
    """启动本地 Skill 资产与治理看板。"""
    _execute(
        lambda: run_local_portal(host=host, port=port, state_dir=state_dir)
    )


@app.command()
def status(
    config: Annotated[Path, typer.Option("--config")],
    target: Annotated[str | None, typer.Option("--target")] = None,
) -> None:
    result = _execute(lambda: build_runtime(config).read.status(target))
    _emit(result)


@app.command("plan")
def plan_command(
    config: Annotated[Path, typer.Option("--config")],
    target_id: Annotated[str, typer.Argument()],
    expires_minutes: Annotated[
        int, typer.Option("--expires-minutes", min=1)
    ] = 30,
) -> None:
    result = _execute(
        lambda: build_runtime(config).create_plan(
            target_id, expires_in=timedelta(minutes=expires_minutes)
        )
    )
    _emit(result)


@app.command("approve")
def approve_command(
    config: Annotated[Path, typer.Option("--config")],
    plan_id: Annotated[str, typer.Argument()],
    approver: Annotated[str, typer.Option("--approver")],
    decision: Annotated[DecisionOption, typer.Option("--decision")],
    reason: Annotated[str, typer.Option("--reason")],
) -> None:
    def operation() -> object:
        _require_plan_id(plan_id)
        return build_runtime(config).approvals.record(
            plan_id,
            approver,
            decision.value,
            reason,
            now=datetime.now(timezone.utc),
        )

    result = _execute(operation)
    _emit(result)


@app.command("apply")
def apply_command(
    config: Annotated[Path, typer.Option("--config")],
    plan_id: Annotated[str, typer.Argument()],
) -> None:
    def operation() -> object:
        _require_plan_id(plan_id)
        return build_runtime(config).deployment.apply(plan_id)

    result = _execute(operation)
    _emit(result)


@app.command()
def drift(
    config: Annotated[Path, typer.Option("--config")],
    target: Annotated[str | None, typer.Option("--target")] = None,
) -> None:
    result = _execute(lambda: build_runtime(config).read.drift(target))
    _emit(result)
    if result.has_drift:
        raise typer.Exit(4)


@app.command("rollback")
def rollback_command(
    config: Annotated[Path, typer.Option("--config")],
    deployment_id: Annotated[str, typer.Argument()],
    rollback_plan_id: Annotated[str, typer.Argument()],
) -> None:
    def operation() -> object:
        _require_deployment_id(deployment_id)
        _require_plan_id(rollback_plan_id)
        return build_runtime(config).deployment.rollback(
            deployment_id, rollback_plan_id
        )

    result = _execute(operation)
    _emit(result)

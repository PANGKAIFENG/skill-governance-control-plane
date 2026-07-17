import json
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

import skillctl.cli as cli_module
from skillctl.canonical import canonical_json
from skillctl.cli import app
from skillctl.config import ControlPlaneConfig
from skillctl.errors import (
    AdapterFailure,
    ApprovalRequired,
    GovernanceValidationError,
    LedgerCorruption,
    PolicyDenied,
    SafetyViolation,
    StalePlan,
    UnsupportedCapability,
)
from skillctl.models import DriftReport


runner = CliRunner()


def _align_canary_authority_source(governance: Path) -> None:
    assets_path = governance / "assets.yaml"
    assets = yaml.safe_load(assets_path.read_text(encoding="utf-8"))
    assets["items"][0]["source_path"] = "canary-skill"
    assets_path.write_text(
        yaml.safe_dump(assets, sort_keys=False), encoding="utf-8"
    )


def test_version_reports_package_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout == "skillctl 0.1.0\n"


def test_hatchling_packages_the_src_skillctl_package() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())

    assert pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/skillctl"
    ]


def test_help_exposes_governance_and_portal_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in (
        "status",
        "plan",
        "approve",
        "apply",
        "drift",
        "rollback",
        "portal",
    ):
        assert command in result.stdout


def test_portal_command_runs_local_ui(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[str, int, Path]] = []

    def run_local_portal(*, host: str, port: int, state_dir: Path) -> None:
        calls.append((host, port, state_dir))

    monkeypatch.setattr(
        cli_module,
        "run_local_portal",
        run_local_portal,
        raising=False,
    )

    result = runner.invoke(
        app,
        [
            "portal",
            "--port",
            "8123",
            "--state-dir",
            str(tmp_path / "portal-state"),
        ],
    )

    assert result.exit_code == 0
    assert calls == [("127.0.0.1", 8123, tmp_path / "portal-state")]


class _FakeRuntime:
    def __init__(self, *, error: Exception | None = None, drift: bool = False) -> None:
        self.error = error
        self.has_drift = drift
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.approvals = SimpleNamespace(record=self._approve)
        self.deployment = SimpleNamespace(apply=self._apply, rollback=self._rollback)
        self.read = SimpleNamespace(status=self._status, drift=self._drift)

    def _result(self, name: str, *args: Any) -> dict[str, Any]:
        self.calls.append((name, args))
        if self.error is not None:
            raise self.error
        return {"command": name}

    def create_plan(self, target_id: str, *, expires_in: object) -> dict[str, Any]:
        return self._result("plan", target_id, expires_in)

    def _approve(
        self,
        plan_id: str,
        approver: str,
        decision: str,
        reason: str,
        *,
        now: datetime,
    ) -> dict[str, Any]:
        return self._result(
            "approve", plan_id, approver, decision, reason, now
        )

    def _apply(self, plan_id: str) -> dict[str, Any]:
        return self._result("apply", plan_id)

    def _rollback(self, deployment_id: str, plan_id: str) -> dict[str, Any]:
        return self._result("rollback", deployment_id, plan_id)

    def _status(self, target_id: str | None) -> dict[str, Any]:
        return self._result("status", target_id)

    def _drift(self, target_id: str | None) -> DriftReport:
        self.calls.append(("drift", (target_id,)))
        if self.error is not None:
            raise self.error
        return DriftReport(
            generated_at=datetime(2026, 7, 13, tzinfo=timezone.utc),
            target_id=target_id,
            changes=(
                ({"target_id": "target-local-b"},) if self.has_drift else ()
            ),
            has_drift=self.has_drift,
            evidence_refs=(),
        )


def test_plan_success_outputs_only_canonical_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _FakeRuntime()
    monkeypatch.setattr(cli_module, "build_runtime", lambda _: runtime)

    result = runner.invoke(
        app,
        [
            "plan",
            "--config",
            str(tmp_path / "config.yaml"),
            "target-local-b",
            "--expires-minutes",
            "30",
        ],
    )

    expected = {"command": "plan"}
    assert result.exit_code == 0
    assert result.stdout == canonical_json(expected).decode("utf-8") + "\n"
    assert runtime.calls == [("plan", ("target-local-b", timedelta(minutes=30)))]


def test_successful_commands_forward_exact_arguments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _FakeRuntime()
    config_path = tmp_path / "config.yaml"
    built: list[Path] = []

    def fake_build(path: Path) -> _FakeRuntime:
        built.append(path)
        return runtime

    monkeypatch.setattr(cli_module, "build_runtime", fake_build)
    commands = (
        (["status", "--config", str(config_path), "--target", "target-local-a"], "status"),
        (
            [
                "approve",
                "--config",
                str(config_path),
                "plan-" + "a" * 32,
                "--approver",
                " Reviewer A ",
                "--decision",
                "rejected",
                "--reason",
                " Keep exact reason ",
            ],
            "approve",
        ),
        (["apply", "--config", str(config_path), "plan-" + "b" * 32], "apply"),
        (["drift", "--config", str(config_path), "--target", "target-local-b"], "drift"),
        (
            [
                "rollback",
                "--config",
                str(config_path),
                "deployment-" + "c" * 32,
                "plan-" + "d" * 32,
            ],
            "rollback",
        ),
    )

    for arguments, expected_command in commands:
        result = runner.invoke(app, arguments)
        assert result.exit_code == 0
        expected_payload: object = {"command": expected_command}
        if expected_command == "drift":
            expected_payload = DriftReport(
                generated_at=datetime(2026, 7, 13, tzinfo=timezone.utc),
                target_id="target-local-b",
                changes=(),
                has_drift=False,
                evidence_refs=(),
            )
        assert result.stdout == canonical_json(expected_payload).decode("utf-8") + "\n"

    assert built == [config_path] * len(commands)
    assert runtime.calls[0] == ("status", ("target-local-a",))
    approval_call = runtime.calls[1]
    assert approval_call[0] == "approve"
    assert approval_call[1][:4] == (
        "plan-" + "a" * 32,
        " Reviewer A ",
        "rejected",
        " Keep exact reason ",
    )
    approval_now = approval_call[1][4]
    assert isinstance(approval_now, datetime)
    assert approval_now.tzinfo is timezone.utc
    assert runtime.calls[2:] == [
        ("apply", ("plan-" + "b" * 32,)),
        ("drift", ("target-local-b",)),
        ("rollback", ("deployment-" + "c" * 32, "plan-" + "d" * 32)),
    ]


@pytest.mark.parametrize(
    ("command", "error", "expected_code"),
    (
        ("plan", GovernanceValidationError("invalid input"), 2),
        ("apply", PolicyDenied("denied"), 2),
        ("apply", SafetyViolation("unsafe"), 2),
        ("apply", ApprovalRequired("approval required"), 3),
        ("apply", AdapterFailure("adapter failed"), 5),
        ("apply", UnsupportedCapability("unsupported"), 5),
        ("apply", StalePlan("stale"), 6),
        ("apply", LedgerCorruption("state failed"), 6),
    ),
)
def test_cli_maps_typed_errors_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
    error: Exception,
    expected_code: int,
) -> None:
    runtime = _FakeRuntime(error=error)
    monkeypatch.setattr(cli_module, "build_runtime", lambda _: runtime)
    arguments = [command, "--config", str(tmp_path / "config.yaml")]
    arguments += ["target-local-b"] if command == "plan" else ["plan-" + "a" * 32]

    result = runner.invoke(app, arguments)

    assert result.exit_code == expected_code
    assert result.stdout == ""
    assert result.stderr == canonical_json({"error": str(error)}).decode("utf-8") + "\n"
    assert "Traceback" not in result.stderr


def test_cli_redacts_absolute_path_from_typed_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    authority_path = "/private/authority/canary-skill"
    runtime = _FakeRuntime(
        error=SafetyViolation("unsafe authority path " + authority_path)
    )
    monkeypatch.setattr(cli_module, "build_runtime", lambda _: runtime)

    result = runner.invoke(
        app,
        ["apply", "--config", str(tmp_path / "config.yaml"), "plan-" + "a" * 32],
    )

    assert result.exit_code == 2
    assert authority_path not in result.stderr
    assert result.stderr == canonical_json(
        {"error": "unsafe authority path <redacted>"}
    ).decode("utf-8") + "\n"


def test_drift_returns_exit_four_with_canonical_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _FakeRuntime(drift=True)
    monkeypatch.setattr(cli_module, "build_runtime", lambda _: runtime)

    result = runner.invoke(
        app, ["drift", "--config", str(tmp_path / "config.yaml")]
    )

    report = runtime._drift(None)
    assert result.exit_code == 4
    assert result.stdout == canonical_json(report).decode("utf-8") + "\n"


def _approved_cli_plan(mvp_root: Path, tmp_path: Path) -> tuple[Path, str]:
    governance = mvp_root / "governance"
    _align_canary_authority_source(governance)
    runtime_root = tmp_path / "runtime"
    targets_path = governance / "targets.yaml"
    targets = yaml.safe_load(targets_path.read_text(encoding="utf-8"))
    for item in targets["items"]:
        item["config"]["root"] = str((runtime_root / item["id"]).resolve())
    targets_path.write_text(
        yaml.safe_dump(targets, sort_keys=False), encoding="utf-8"
    )

    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    executables: dict[str, Path] = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\nprintf '{}\\n'\n", encoding="utf-8")
        executable.chmod(0o700)
        executables[name] = executable
    config = ControlPlaneConfig(
        registry_root=governance,
        state_root=governance,
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(mvp_root / "authority",),
        allowed_runtime_roots=(runtime_root,),
        trusted_cli_paths=executables,
    )
    config_path = tmp_path / "control-plane.yaml"
    config_path.write_text(
        yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    base = ["--config", str(config_path)]
    plan_result = runner.invoke(app, ["plan", *base, "target-local-b"])
    assert plan_result.exit_code == 0, plan_result.stderr
    plan_id = json.loads(plan_result.stdout)["id"]
    approval_result = runner.invoke(
        app,
        [
            "approve",
            *base,
            plan_id,
            "--approver",
            "reviewer",
            "--decision",
            "approved",
            "--reason",
            "reviewed",
        ],
    )
    assert approval_result.exit_code == 0, approval_result.stderr
    return config_path, plan_id


@pytest.mark.parametrize(
    ("arguments", "message"),
    (
        (
            (
                "approve",
                "--config",
                "{config}",
                "not-a-plan-id",
                "--approver",
                "reviewer",
                "--decision",
                "approved",
                "--reason",
                "reviewed",
            ),
            "cli: invalid plan id",
        ),
        (
            ("apply", "--config", "{config}", "not-a-plan-id"),
            "cli: invalid plan id",
        ),
        (
            (
                "rollback",
                "--config",
                "{config}",
                "not-a-deployment-id",
                "plan-" + "a" * 32,
            ),
            "cli: invalid deployment id",
        ),
        (
            (
                "rollback",
                "--config",
                "{config}",
                "deployment-" + "a" * 32,
                "not-a-plan-id",
            ),
            "cli: invalid plan id",
        ),
    ),
)
def test_cli_rejects_malformed_persistent_record_ids_as_input_errors(
    mvp_root: Path,
    tmp_path: Path,
    arguments: tuple[str, ...],
    message: str,
) -> None:
    config_path, _ = _approved_cli_plan(mvp_root, tmp_path)
    rendered = tuple(
        str(config_path) if argument == "{config}" else argument
        for argument in arguments
    )

    result = runner.invoke(app, list(rendered))

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == canonical_json({"error": message}).decode("utf-8") + "\n"
    assert "Traceback" not in result.stderr


def test_cli_keeps_well_formed_missing_plan_as_state_failure(
    mvp_root: Path, tmp_path: Path
) -> None:
    config_path, existing_plan_id = _approved_cli_plan(mvp_root, tmp_path)
    missing_plan_id = "plan-" + "f" * 32
    assert missing_plan_id != existing_plan_id

    result = runner.invoke(
        app, ["apply", "--config", str(config_path), missing_plan_id]
    )

    assert result.exit_code == 6
    assert result.stdout == ""
    assert result.stderr == canonical_json(
        {"error": "plan: invalid stored record"}
    ).decode("utf-8") + "\n"
    assert "Traceback" not in result.stderr


def test_cli_maps_corrupt_persisted_approval_to_state_failure(
    mvp_root: Path, tmp_path: Path
) -> None:
    config_path, plan_id = _approved_cli_plan(mvp_root, tmp_path)
    approval_path = (
        mvp_root
        / "governance"
        / "approvals"
        / f"approval-{plan_id}.json"
    )
    approval_path.write_text("{", encoding="utf-8")

    result = runner.invoke(
        app, ["apply", "--config", str(config_path), plan_id]
    )

    assert result.exit_code == 6
    assert result.stdout == ""
    assert result.stderr == canonical_json(
        {"error": "approval: invalid stored record"}
    ).decode("utf-8") + "\n"
    assert "Traceback" not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_cli_maps_corrupt_projection_descriptor_to_state_failure(
    mvp_root: Path, tmp_path: Path
) -> None:
    config_path, plan_id = _approved_cli_plan(mvp_root, tmp_path)
    descriptor_path = tmp_path / "projections" / plan_id / ".descriptor.json"
    descriptor_path.write_text("{", encoding="utf-8")

    result = runner.invoke(
        app, ["apply", "--config", str(config_path), plan_id]
    )

    assert result.exit_code == 6
    assert result.stdout == ""
    assert result.stderr == canonical_json(
        {"error": "projection descriptor is invalid"}
    ).decode("utf-8") + "\n"
    assert "Traceback" not in result.stderr
    assert str(tmp_path) not in result.stderr

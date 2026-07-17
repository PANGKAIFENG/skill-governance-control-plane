from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import JsonValue

from skillctl.adapters.base import require_capability
from skillctl.adapters.skillshare import (
    APPLY,
    DIFF,
    DRY_RUN,
    TARGET_LIST,
    SkillshareAdapter,
)
from skillctl.canonical import canonical_digest
from skillctl.config import ControlPlaneConfig
from skillctl.errors import AdapterFailure, SafetyViolation, UnsupportedCapabilityError
from skillctl.models import (
    CapabilityManifest,
    DeploymentResult,
    Plan,
    ProjectionDescriptor,
    Target,
)
from skillctl.projection import ProjectionBuilder
from skillctl.runner import CommandResult

_VALID_DIFF: JsonValue = {
    "targets": [
        {"name": "target-a", "synced": True, "items": []},
        {"name": "target-b", "synced": True, "items": []},
    ],
    "duration": "1ms",
}


class FakeRunner:
    def __init__(self, payload: JsonValue = _VALID_DIFF) -> None:
        self.calls: list[tuple[Path, tuple[str, ...], Path]] = []
        self.payload = payload

    def run(self, executable: Path, args: tuple[str, ...], *, cwd: Path) -> CommandResult:
        self.calls.append((executable, args, cwd))
        return CommandResult(payload=self.payload)


def _config(tmp_path: Path) -> ControlPlaneConfig:
    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    executables = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        executables[name] = executable
    return ControlPlaneConfig(
        registry_root=tmp_path / "registry",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(tmp_path / "authority",),
        allowed_runtime_roots=(tmp_path / "runtime",),
        trusted_cli_paths=executables,
    )


def _manifest(state: str = "supported") -> CapabilityManifest:
    return CapabilityManifest.model_validate(
        {operation: state for operation in ("discover", "plan", "apply", "verify", "rollback")}
    )


def _target(manifest: CapabilityManifest) -> Target:
    return Target(
        id="target",
        adapter_id="skillshare",
        protocol="filesystem",
        config={},
        capabilities=manifest,
    )


def _projection(config: ControlPlaneConfig, plan_id: str = "plan-1") -> ProjectionDescriptor:
    source = config.authority_roots[0] / "canary-skill"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text("# Canary\n", encoding="utf-8")
    return ProjectionBuilder(config).build(
        plan_id,
        source,
        (config.allowed_runtime_roots[0] / "target-a", config.allowed_runtime_roots[0] / "target-b"),
    )


def _plan(descriptor: ProjectionDescriptor) -> Plan:
    now = datetime.now(UTC)
    paths = tuple(
        str(path)
        for path in sorted(
            (
                Path(descriptor.root).parents[1] / "runtime/target-a",
                Path(descriptor.root).parents[1] / "runtime/target-b",
            )
        )
    )
    return Plan(
        id=descriptor.plan_id,
        operation="deploy",
        target_id="target",
        parent_deployment_id=None,
        changes=(),
        risk="low",
        policy_decision="allow",
        policy_reasons=(),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        source_state_digest="source",
        desired_state_digest="desired",
        observed_state_digest="observed",
        adapter_manifest_digest="manifest",
        adapter_evidence_digest="adapter",
        runtime_target_paths=paths,
        runtime_target_paths_digest=canonical_digest(paths),
        evidence_refs=(),
        plan_digest="plan",
    )


@pytest.mark.parametrize("state", ("unsupported", "unverified"))
@pytest.mark.parametrize("operation", ("discover", "plan", "apply", "verify", "rollback"))
def test_require_capability_fails_closed_for_every_operation(
    state: str, operation: str
) -> None:
    with pytest.raises(UnsupportedCapabilityError, match="capability"):
        require_capability(_manifest(state), operation)


def test_adapter_uses_only_exact_allowed_argv_and_projection_cwd(tmp_path: Path) -> None:
    config = _config(tmp_path)
    descriptor = _projection(config)
    manifest = _manifest()
    target = _target(manifest)
    runner = FakeRunner()
    adapter = SkillshareAdapter(config, runner=runner, manifest=manifest)
    plan = _plan(descriptor)
    deployment = DeploymentResult(
        deployment_id="deployment-1",
        target_id=target.id,
        resolved_target_paths=plan.runtime_target_paths,
        changed_asset_ids=(),
        result="applied",
        evidence_refs=(),
    )

    adapter.discover(target, descriptor)
    adapter.plan(target, (), plan.id, descriptor)
    adapter.apply(target, plan, deployment.deployment_id, descriptor)
    adapter.verify(target, deployment, descriptor)
    adapter.rollback(target, plan, "deployment-2", descriptor)

    assert [args for _, args, _ in runner.calls] == [
        TARGET_LIST,
        DRY_RUN,
        APPLY,
        DIFF,
        APPLY,
    ]
    assert {cwd for _, _, cwd in runner.calls} == {Path(descriptor.root)}
    forbidden = {"--global", "--force", "collect", "install", "uninstall", "pull", "push", "update"}
    assert not forbidden.intersection(arg for _, args, _ in runner.calls for arg in args)


def test_plan_uses_dry_run_and_binds_evidence_to_projection(tmp_path: Path) -> None:
    config = _config(tmp_path)
    descriptor = _projection(config)
    manifest = _manifest()
    runner = FakeRunner()
    adapter = SkillshareAdapter(config, runner=runner, manifest=manifest)

    evidence = adapter.plan(_target(manifest), (), descriptor.plan_id, descriptor)

    assert runner.calls[-1][1] in (DIFF, DRY_RUN)
    assert evidence.resolved_target_paths == tuple(
        sorted(
            (
                str(config.allowed_runtime_roots[0] / "target-a"),
                str(config.allowed_runtime_roots[0] / "target-b"),
            )
        )
    )


def test_adapter_revalidates_projection_before_runner(tmp_path: Path) -> None:
    config = _config(tmp_path)
    descriptor = _projection(config)
    manifest = _manifest()
    runner = FakeRunner()
    adapter = SkillshareAdapter(config, runner=runner, manifest=manifest)
    project_config = Path(descriptor.root) / "skillshare.config.yaml"
    project_config.write_text(project_config.read_text() + "# changed\n")

    with pytest.raises(SafetyViolation, match="digest"):
        adapter.discover(_target(manifest), descriptor)
    assert runner.calls == []


def test_adapter_checks_capability_before_runner(tmp_path: Path) -> None:
    config = _config(tmp_path)
    descriptor = _projection(config)
    manifest = _manifest("unverified")
    runner = FakeRunner()
    adapter = SkillshareAdapter(config, runner=runner, manifest=manifest)

    with pytest.raises(UnsupportedCapabilityError):
        adapter.discover(_target(manifest), descriptor)
    assert runner.calls == []


def _verify_with_payload(tmp_path: Path, payload: JsonValue) -> bool:
    config = _config(tmp_path)
    descriptor = _projection(config)
    manifest = _manifest()
    target = _target(manifest)
    plan = _plan(descriptor)
    deployment = DeploymentResult(
        deployment_id="deployment-1",
        target_id=target.id,
        resolved_target_paths=plan.runtime_target_paths,
        changed_asset_ids=(),
        result="applied",
        evidence_refs=(),
    )
    adapter = SkillshareAdapter(
        config, runner=FakeRunner(payload), manifest=manifest
    )
    return adapter.verify(target, deployment, descriptor).healthy


@pytest.mark.parametrize(
    "payload",
    (
        {"error": "failed"},
        [],
        None,
        {"targets": "target-a"},
        {"targets": [{"name": "target-a", "synced": True, "items": []}]},
        {"targets": ["target-a", "target-b"]},
        {
            "targets": [
                {"name": "target-a", "items": []},
                {"name": "target-b", "synced": True, "items": []},
            ]
        },
        {
            "targets": [
                {"name": "target-a", "synced": "true", "items": []},
                {"name": "target-b", "synced": True, "items": []},
            ]
        },
        {
            "targets": [
                {"name": "target-a", "synced": True, "items": "none"},
                {"name": "target-b", "synced": True, "items": []},
            ]
        },
        {
            "targets": [
                {"name": "target-a", "synced": True, "items": []},
                {"name": "target-a", "synced": True, "items": []},
            ]
        },
        {
            "targets": [
                {"name": "target-a", "synced": True, "items": []},
                {"name": "target-b", "synced": True, "items": []},
                {"name": "target-c", "synced": True, "items": []},
            ]
        },
    ),
)
def test_verify_rejects_malformed_diff_payload(
    tmp_path: Path, payload: JsonValue
) -> None:
    with pytest.raises(AdapterFailure, match="diff output is invalid") as captured:
        _verify_with_payload(tmp_path, payload)
    assert captured.value.__cause__ is None
    assert "failed" not in str(captured.value)


@pytest.mark.parametrize(
    "payload",
    (
        {
            "targets": [
                {"name": "target-a", "synced": False, "items": []},
                {"name": "target-b", "synced": True, "items": []},
            ]
        },
        {
            "targets": [
                {"name": "target-a", "synced": True, "items": [{"path": "x"}]},
                {"name": "target-b", "synced": True, "items": []},
            ]
        },
    ),
)
def test_verify_reports_valid_diff_drift_as_unhealthy(
    tmp_path: Path, payload: JsonValue
) -> None:
    assert _verify_with_payload(tmp_path, payload) is False

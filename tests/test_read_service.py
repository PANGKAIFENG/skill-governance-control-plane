from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import stat

import pytest
import yaml

from skillctl.approvals import ApprovalService
from skillctl.adapters.skillshare import SkillshareAdapter
from skillctl.bootstrap import (
    FileRuntimeSnapshotStore,
    ProjectionLocator,
    build_runtime,
    runtime_target_paths,
)
from skillctl.canonical import canonical_digest
from skillctl.config import ControlPlaneConfig
from skillctl.errors import AdapterFailure
from skillctl.ledger import DeploymentLedger
from skillctl.models import (
    AdapterPlanEvidence,
    CapabilityManifest,
    DeploymentLedgerEntry,
    DeploymentResult,
    ObservedState,
    Plan,
    PlanChange,
    ProjectionDescriptor,
    Target,
    VerificationResult,
)
from skillctl.planner import PlanService, calculate_changes, desired_assets
from skillctl.projection import ProjectionBuilder, validate_projection
from skillctl.read_service import GovernanceReadService
from skillctl.repository import DocumentRepository
from skillctl.service import DeploymentService


NOW = datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc)


class ReadAdapter:
    def __init__(self, manifest: CapabilityManifest) -> None:
        self.manifest = manifest
        self.calls: list[str] = []
        self.healthy = True

    def discover(
        self, target: Target, projection: ProjectionDescriptor
    ) -> tuple[ObservedState, ...]:
        self.calls.append("discover")
        return ()

    def verify(
        self,
        target: Target,
        deployment: DeploymentResult,
        projection: ProjectionDescriptor,
    ) -> VerificationResult:
        self.calls.append("verify")
        return VerificationResult(
            deployment_id=deployment.deployment_id,
            target_id=target.id,
            resolved_target_paths=deployment.resolved_target_paths,
            healthy=self.healthy,
            drift={"detected": not self.healthy},
            evidence_refs=(),
        )

    def plan(
        self,
        target: Target,
        changes: tuple[PlanChange, ...],
        plan_id: str,
        projection: ProjectionDescriptor,
    ) -> AdapterPlanEvidence:
        raise AssertionError

    def apply(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult:
        raise AssertionError

    def rollback(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult:
        raise AssertionError


def _read_service(
    mvp_root: Path,
) -> tuple[GovernanceReadService, ReadAdapter, Plan, DeploymentLedgerEntry]:
    root = mvp_root / "governance"
    repository = DocumentRepository(root, root)
    snapshot = repository.load_snapshot()
    target = next(item for item in snapshot.targets if item.id == "target-local-b")
    runtime_paths = tuple(
        sorted(
            str((mvp_root / "runtime" / target.id / name).resolve())
            for name in ("target-a", "target-b")
        )
    )
    changes = calculate_changes(desired_assets(snapshot, target.id), ())
    evidence = AdapterPlanEvidence(
        adapter_id=target.adapter_id,
        target_id=target.id,
        changes_digest=canonical_digest(changes),
        resolved_target_paths=runtime_paths,
        evidence_refs=(),
        raw_evidence_digest=canonical_digest({"dry_run": "ok"}),
    )
    plan = PlanService(
        repository, runtime_target_paths_resolver=lambda _: runtime_paths
    ).create(
        target.id,
        adapter_evidence=evidence,
        now=NOW,
        expires_in=timedelta(minutes=30),
    )
    approval = ApprovalService(repository).record(
        plan.id, "reviewer", "approved", "reviewed", now=NOW
    )
    descriptor = ProjectionDescriptor(
        plan_id=plan.id,
        root=str((mvp_root / "projections" / plan.id).resolve()),
        manifest_digest=canonical_digest({"manifest": "ok"}),
        config_digest=canonical_digest({"config": "ok"}),
        runtime_target_paths_digest=plan.runtime_target_paths_digest,
    )
    entry = DeploymentLedgerEntry(
        schema_version="1.0",
        deployment_id="deployment-" + "a" * 32,
        plan_id=plan.id,
        parent_deployment_id=None,
        target_id=target.id,
        asset_ids=tuple(change.asset_id for change in plan.changes),
        source_revisions={"asset-canary": "revision-canary-1"},
        change_types=tuple(change.change_type for change in plan.changes),
        approval_ref=approval.id,
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        result="succeeded",
        evidence_refs=(),
        previous_entry_hash=None,
        entry_hash="",
    )
    ledger = DeploymentLedger(root / "deployment-ledger.jsonl")
    ledger.append(entry)
    adapter = ReadAdapter(target.capabilities)
    service = GovernanceReadService(
        repository,
        ledger=ledger,
        adapter_for_target=lambda _: adapter,
        projection_for_plan=lambda _: descriptor,
        now=lambda: NOW + timedelta(minutes=1),
    )
    return service, adapter, plan, ledger.read_all()[0]


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _align_canary_authority_source(governance: Path) -> None:
    assets_path = governance / "assets.yaml"
    assets = yaml.safe_load(assets_path.read_text(encoding="utf-8"))
    assets["items"][0]["source_path"] = "canary-skill"
    assets_path.write_text(
        yaml.safe_dump(assets, sort_keys=False), encoding="utf-8"
    )


def test_read_service_six_methods_are_read_only_and_status_is_healthy(
    mvp_root: Path,
) -> None:
    service, adapter, plan, deployment = _read_service(mvp_root)
    root = mvp_root / "governance"
    before = _tree_bytes(root)

    assert service.snapshot().targets
    assert service.deployments() == (deployment,)
    assert service.get_plan(plan.id) == plan
    assert service.approval_for_plan(plan.id) is not None
    status = service.status("target-local-b")
    drift = service.drift("target-local-b")

    assert status.drift_count == 0
    assert status.target_health["target-local-b"]["status"] == "healthy"
    assert drift.has_drift is False
    assert adapter.calls == ["discover", "verify", "discover", "verify"]
    assert _tree_bytes(root) == before
    for forbidden in ("apply", "rollback", "adapter", "runner", "repository"):
        assert not hasattr(service, forbidden)


def test_read_service_lists_plans_without_writing_state(mvp_root: Path) -> None:
    service, _, plan, _ = _read_service(mvp_root)
    root = mvp_root / "governance"
    before = _tree_bytes(root)

    assert service.plans() == (plan,)
    assert _tree_bytes(root) == before
    for forbidden in ("apply", "rollback", "adapter", "runner", "repository"):
        assert not hasattr(service, forbidden)


def test_read_service_reports_verify_diff_without_writes(mvp_root: Path) -> None:
    service, adapter, _, _ = _read_service(mvp_root)
    root = mvp_root / "governance"
    before = _tree_bytes(root)
    adapter.healthy = False

    status = service.status("target-local-b")
    drift = service.drift("target-local-b")

    assert status.drift_count == 1
    assert drift.has_drift is True
    assert drift.changes[0]["target_id"] == "target-local-b"
    assert _tree_bytes(root) == before


def _config(tmp_path: Path, *, registry_root: Path | None = None) -> ControlPlaneConfig:
    bin_root = tmp_path / "bin"
    bin_root.mkdir(exist_ok=True)
    executables: dict[str, Path] = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\nprintf '{}\\n'\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        executables[name] = executable
    root = registry_root or tmp_path / "registry"
    return ControlPlaneConfig(
        registry_root=root,
        state_root=root,
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(tmp_path / "authority",),
        allowed_runtime_roots=(tmp_path / "runtime",),
        trusted_cli_paths=executables,
    )


def test_runtime_target_paths_are_generic_sorted_and_allowed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    target = Target(
        id="arbitrary-third-target",
        adapter_id="filesystem",
        protocol="filesystem",
        config={"root": str((tmp_path / "runtime" / "arbitrary").resolve())},
        capabilities=CapabilityManifest(
            discover="supported",
            plan="supported",
            apply="supported",
            verify="supported",
            rollback="supported",
        ),
    )

    assert runtime_target_paths(config, target) == tuple(
        sorted(
            str((tmp_path / "runtime" / "arbitrary" / name).resolve())
            for name in ("target-a", "target-b")
        )
    )


@pytest.mark.parametrize("existing_skill", (False, True))
def test_snapshot_store_builds_isolated_rollback_projection(
    tmp_path: Path, existing_skill: bool
) -> None:
    config = _config(tmp_path)
    source = config.authority_roots[0] / "canary-skill"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text("new\n")
    target = Target(
        id="target-any",
        adapter_id="filesystem",
        protocol="filesystem",
        config={"root": str((config.allowed_runtime_roots[0] / "any").resolve())},
        capabilities=CapabilityManifest(
            discover="supported",
            plan="supported",
            apply="supported",
            verify="supported",
            rollback="supported",
        ),
    )
    paths = runtime_target_paths(config, target)
    for path_string in paths:
        path = Path(path_string)
        path.mkdir(parents=True)
        if existing_skill:
            skill = path / "canary-skill"
            skill.mkdir()
            (skill / "SKILL.md").write_text("old\n")
    descriptor = ProjectionBuilder(config).build(
        "plan-" + "a" * 32, source, tuple(map(Path, paths))
    )
    locator = ProjectionLocator(config)
    locator.save(descriptor)
    store = FileRuntimeSnapshotStore(config, locator)

    store.capture("deployment-" + "a" * 32, target, object(), descriptor)  # type: ignore[arg-type]
    rollback = store.rollback_projection(
        "deployment-" + "a" * 32,
        "plan-" + "b" * 32,
        target,
        paths,
    )

    assert locator.for_plan_id(rollback.plan_id) == rollback
    assert validate_projection(config, rollback) == paths
    copied = Path(rollback.root) / ".skillshare" / "skills" / "canary-skill" / "SKILL.md"
    assert copied.read_text() == "old\n" if existing_skill else not copied.exists()
    assert (source / "SKILL.md").read_text() == "new\n"


def test_build_runtime_composes_plan_with_one_reserved_plan_id(
    mvp_root: Path, tmp_path: Path
) -> None:
    governance = mvp_root / "governance"
    _align_canary_authority_source(governance)
    targets_path = governance / "targets.yaml"
    targets = yaml.safe_load(targets_path.read_text())
    for item in targets["items"]:
        item["config"]["root"] = str((tmp_path / "runtime" / item["id"]).resolve())
    targets_path.write_text(yaml.safe_dump(targets, sort_keys=False))
    config = _config(tmp_path, registry_root=governance).model_copy(
        update={"authority_roots": (mvp_root / "authority",)}
    )
    config_path = tmp_path / "control-plane.yaml"
    config_path.write_text(yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False))

    runtime = build_runtime(config_path, now=lambda: NOW)
    plan = runtime.create_plan("target-local-b", expires_in=timedelta(minutes=30))
    descriptor = runtime.projections.for_plan_id(plan.id)

    assert descriptor.plan_id == plan.id
    assert descriptor.runtime_target_paths_digest == plan.runtime_target_paths_digest
    assert plan.runtime_target_paths == runtime_target_paths(
        config, next(target for target in runtime.repository.load_snapshot().targets if target.id == plan.target_id)
    )


def test_build_runtime_wires_shared_services_without_read_side_writers(
    mvp_root: Path, tmp_path: Path
) -> None:
    governance = mvp_root / "governance"
    _align_canary_authority_source(governance)
    targets_path = governance / "targets.yaml"
    targets = yaml.safe_load(targets_path.read_text())
    for item in targets["items"]:
        item["config"]["root"] = str(
            (tmp_path / "runtime" / item["id"]).resolve()
        )
    targets_path.write_text(yaml.safe_dump(targets, sort_keys=False))
    config = _config(tmp_path, registry_root=governance).model_copy(
        update={"authority_roots": (mvp_root / "authority",)}
    )
    config_path = tmp_path / "control-plane.yaml"
    config_path.write_text(
        yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False)
    )

    runtime = build_runtime(config_path, now=lambda: NOW)
    deployment_state = vars(runtime.deployment)
    read_state = vars(runtime.read)
    target = runtime.repository.load_snapshot().targets[0]
    deployment_adapter = deployment_state["_adapter_for_target"](target)
    read_adapter = read_state["_adapter_for_target"](target)

    assert isinstance(runtime.approvals, ApprovalService)
    assert isinstance(runtime.deployment, DeploymentService)
    assert isinstance(runtime.read, GovernanceReadService)
    assert deployment_state["_ledger"] is read_state["_ledger"]
    assert deployment_state["_adapter_for_target"] is read_state["_adapter_for_target"]
    assert deployment_state["_projection_for_plan"] is read_state["_projection_for_plan"]
    assert deployment_state["_now"] is read_state["_now"]
    assert "_snapshot_store" in deployment_state
    assert "_snapshot_store" not in read_state
    assert isinstance(deployment_adapter, SkillshareAdapter)
    assert isinstance(read_adapter, SkillshareAdapter)
    assert deployment_adapter is not read_adapter
    assert deployment_adapter.manifest == target.capabilities
    assert vars(deployment_adapter)["_runner"] is vars(read_adapter)["_runner"]


def test_create_plan_dry_run_failure_leaves_no_plan_or_projection(
    mvp_root: Path, tmp_path: Path
) -> None:
    governance = mvp_root / "governance"
    _align_canary_authority_source(governance)
    targets_path = governance / "targets.yaml"
    targets = yaml.safe_load(targets_path.read_text())
    for item in targets["items"]:
        item["config"]["root"] = str((tmp_path / "runtime" / item["id"]).resolve())
    targets_path.write_text(yaml.safe_dump(targets, sort_keys=False))
    config = _config(tmp_path, registry_root=governance).model_copy(
        update={"authority_roots": (mvp_root / "authority",)}
    )
    skillshare = config.trusted_cli_paths["skillshare"]
    skillshare.write_text("#!/bin/sh\nexit 1\n")
    config_path = tmp_path / "control-plane.yaml"
    config_path.write_text(yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False))
    runtime = build_runtime(config_path, now=lambda: NOW)

    with pytest.raises(AdapterFailure):
        runtime.create_plan("target-local-b", expires_in=timedelta(minutes=30))

    assert not (governance / "plans").exists()
    assert not config.projection_root.exists() or not tuple(config.projection_root.iterdir())

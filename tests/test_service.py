from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from skillctl.approvals import ApprovalService
from skillctl.canonical import canonical_digest, canonical_json
from skillctl.errors import (
    AdapterFailure,
    ApprovalRequired,
    LedgerCorruption,
    StalePlan,
    UnsupportedCapabilityError,
)
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
from skillctl.repository import DocumentRepository
from skillctl.service import DeploymentService


NOW = datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc)


def _runtime_paths(target: Target) -> tuple[str, ...]:
    root = target.config.get("root")
    assert isinstance(root, str)
    return tuple(sorted(str((Path(root) / name).resolve()) for name in ("target-a", "target-b")))


class FakeAdapter:
    def __init__(
        self,
        observations: tuple[ObservedState, ...],
        *,
        fail_stage: str | None = None,
        manifest: CapabilityManifest,
    ) -> None:
        self.calls: list[str] = []
        self.observations = observations
        self.fail_stage = fail_stage
        self.manifest = manifest

    def discover(
        self, target: Target, projection: ProjectionDescriptor
    ) -> tuple[ObservedState, ...]:
        self.calls.append("discover")
        return self.observations

    def apply(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult:
        self.calls.append("apply")
        if self.fail_stage == "apply":
            raise AdapterFailure("adapter: apply failed")
        return DeploymentResult(
            deployment_id=deployment_id,
            target_id=target.id,
            resolved_target_paths=plan.runtime_target_paths,
            changed_asset_ids=tuple(change.asset_id for change in plan.changes),
            result="applied",
            evidence_refs=(),
        )

    def plan(
        self,
        target: Target,
        changes: tuple[PlanChange, ...],
        plan_id: str,
        projection: ProjectionDescriptor,
    ) -> AdapterPlanEvidence:
        raise AssertionError("plan is not used by DeploymentService")

    def verify(
        self,
        target: Target,
        deployment: DeploymentResult,
        projection: ProjectionDescriptor,
    ) -> VerificationResult:
        self.calls.append("verify")
        if self.fail_stage == "verify":
            raise AdapterFailure("adapter: verify failed")
        return VerificationResult(
            deployment_id=deployment.deployment_id,
            target_id=target.id,
            resolved_target_paths=deployment.resolved_target_paths,
            healthy=True,
            drift={"detected": False},
            evidence_refs=(),
        )

    def rollback(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult:
        self.calls.append("rollback")
        return DeploymentResult(
            deployment_id=deployment_id,
            target_id=target.id,
            resolved_target_paths=plan.runtime_target_paths,
            changed_asset_ids=tuple(change.asset_id for change in plan.changes),
            result="rolled-back",
            evidence_refs=(),
        )


class MemoryLedger:
    def __init__(self) -> None:
        self.entries: list[DeploymentLedgerEntry] = []
        self.append_calls = 0
        self.fail_append = False

    def append(self, entry: DeploymentLedgerEntry) -> None:
        self.append_calls += 1
        if self.fail_append:
            raise LedgerCorruption("ledger: append failed")
        self.entries.append(entry)

    def read_all(self) -> tuple[DeploymentLedgerEntry, ...]:
        return tuple(self.entries)


class MemorySnapshotStore:
    def __init__(self, descriptors: dict[str, ProjectionDescriptor]) -> None:
        self.descriptors = descriptors
        self.captures: list[str] = []

    def capture(
        self,
        deployment_id: str,
        target: Target,
        plan: Plan,
        projection: ProjectionDescriptor,
    ) -> None:
        self.captures.append(deployment_id)

    def rollback_projection(
        self,
        deployment_id: str,
        rollback_plan_id: str,
        target: Target,
        runtime_target_paths: tuple[str, ...],
    ) -> ProjectionDescriptor:
        parent = self.descriptors[next(iter(self.descriptors))]
        descriptor = parent.model_copy(
            update={
                "plan_id": rollback_plan_id,
                "root": str((Path(parent.root).parent / rollback_plan_id).resolve()),
            }
        )
        self.descriptors[rollback_plan_id] = descriptor
        return descriptor


def _approved_service(
    mvp_root: Path,
    *,
    fail_stage: str | None = None,
    service_now: datetime | Callable[[], datetime] = NOW + timedelta(minutes=1),
    target_id: str = "target-local-b",
) -> tuple[DeploymentService, FakeAdapter, MemoryLedger, Plan]:
    root = mvp_root / "governance"
    targets_path = root / "targets.yaml"
    targets_payload = yaml.safe_load(targets_path.read_text())
    for item in targets_payload["items"]:
        item["config"]["root"] = str((mvp_root / "runtime" / item["id"]).resolve())
    targets_path.write_text(yaml.safe_dump(targets_payload, sort_keys=False))
    repository = DocumentRepository(root, root)
    snapshot = repository.load_snapshot()
    target = next(item for item in snapshot.targets if item.id == target_id)
    runtime_paths = _runtime_paths(target)
    for path in runtime_paths:
        Path(path).mkdir(parents=True)
    observations = tuple(
        item for item in snapshot.observations if item.target_id == target_id
    )
    changes = calculate_changes(desired_assets(snapshot, target_id), observations)
    evidence = AdapterPlanEvidence(
        adapter_id=target.adapter_id,
        target_id=target_id,
        changes_digest=canonical_digest(changes),
        resolved_target_paths=runtime_paths,
        evidence_refs=(),
        raw_evidence_digest=canonical_digest({"dry_run": "ok"}),
    )
    plan = PlanService(
        repository,
        runtime_target_paths_resolver=_runtime_paths,
    ).create(
        target_id,
        adapter_evidence=evidence,
        now=NOW,
        expires_in=timedelta(minutes=30),
    )
    ApprovalService(repository).record(
        plan.id, "reviewer", "approved", "reviewed", now=NOW
    )
    descriptor = ProjectionDescriptor(
        plan_id=plan.id,
        root=str((mvp_root / "projections" / plan.id).resolve()),
        manifest_digest=canonical_digest({"manifest": "ok"}),
        config_digest=canonical_digest({"config": "ok"}),
        runtime_target_paths_digest=plan.runtime_target_paths_digest,
    )
    adapter = FakeAdapter(
        (), fail_stage=fail_stage, manifest=target.capabilities
    )
    ledger = MemoryLedger()
    descriptors = {plan.id: descriptor}
    deployment_ids = iter(
        ("deployment-" + "a" * 32, "deployment-" + "b" * 32)
    )
    service = DeploymentService(
        repository,
        ledger=ledger,
        adapter_for_target=lambda _: adapter,
        projection_for_plan=lambda candidate: descriptors[candidate.id],
        runtime_target_paths_resolver=_runtime_paths,
        snapshot_store=MemorySnapshotStore(descriptors),
        now=service_now if callable(service_now) else lambda: service_now,
        deployment_id_factory=lambda: next(deployment_ids),
        plan_id_factory=lambda: "plan-" + "c" * 32,
    )
    return service, adapter, ledger, plan


def _sequence_clock(*moments: datetime) -> Callable[[], datetime]:
    sequence = iter(moments)
    return lambda: next(sequence)


def test_apply_orders_discovery_apply_verify_and_ledger(mvp_root: Path) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root)

    entry = service.apply(plan.id)

    assert adapter.calls == ["discover", "apply", "verify"]
    assert entry.result == "succeeded"
    assert ledger.entries == [entry]


def test_apply_allows_empty_discovery_when_registry_observation_digest_is_fresh(
    mvp_root: Path,
) -> None:
    service, adapter, ledger, plan = _approved_service(
        mvp_root, target_id="target-local-a"
    )

    entry = service.apply(plan.id)

    assert adapter.observations == ()
    assert adapter.calls == ["discover", "apply", "verify"]
    assert entry.result == "succeeded"
    assert ledger.entries == [entry]


def test_apply_failure_appends_one_failed_ledger_without_retry(mvp_root: Path) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root, fail_stage="apply")

    with pytest.raises(AdapterFailure, match=r"^adapter: apply failed$"):
        service.apply(plan.id)

    assert adapter.calls == ["discover", "apply"]
    assert [entry.result for entry in ledger.entries] == ["failed"]


def test_apply_without_approval_never_calls_adapter_or_ledger(mvp_root: Path) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root)
    (mvp_root / "governance" / "approvals" / f"approval-{plan.id}.json").unlink()

    with pytest.raises(ApprovalRequired, match=r"^deployment: approved plan required$"):
        service.apply(plan.id)

    assert adapter.calls == []
    assert ledger.append_calls == 0


def test_apply_expired_plan_never_calls_adapter_or_ledger(mvp_root: Path) -> None:
    service, adapter, ledger, plan = _approved_service(
        mvp_root, service_now=NOW + timedelta(minutes=30)
    )

    with pytest.raises(StalePlan, match=r"^deployment: stale plan$"):
        service.apply(plan.id)

    assert adapter.calls == []
    assert ledger.append_calls == 0


def test_apply_rechecks_expiry_between_precheck_and_mutation(
    mvp_root: Path,
) -> None:
    service, adapter, ledger, plan = _approved_service(
        mvp_root,
        service_now=_sequence_clock(
            NOW + timedelta(minutes=1),
            NOW + timedelta(minutes=30),
        ),
    )

    with pytest.raises(StalePlan, match=r"^deployment: stale plan$"):
        service.apply(plan.id)

    assert adapter.calls == ["discover"]
    assert ledger.append_calls == 0


@pytest.mark.parametrize(
    "digest_kind", ("source", "desired", "observed", "manifest", "runtime_paths")
)
def test_apply_fresh_state_digest_change_stops_before_mutation_without_ledger(
    mvp_root: Path, digest_kind: str
) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root)
    governance = mvp_root / "governance"
    if digest_kind in {"source", "desired"}:
        path = governance / "assets.yaml"
        payload = yaml.safe_load(path.read_text())
        field = "source_revision" if digest_kind == "source" else "name"
        payload["items"][0][field] = "changed"
    elif digest_kind == "observed":
        path = governance / "observed-states.yaml"
        payload = yaml.safe_load(path.read_text())
        item = dict(payload["items"][0])
        item["id"] = "observation-canary-local-b"
        item["target_id"] = "target-local-b"
        payload["items"].append(item)
    else:
        path = governance / "targets.yaml"
        payload = yaml.safe_load(path.read_text())
        target = payload["items"][1]
        if digest_kind == "manifest":
            target["adapter_id"] = "changed-adapter"
        else:
            target["config"]["root"] = str((mvp_root / "other-runtime").resolve())
    path.write_text(yaml.safe_dump(payload, sort_keys=False))

    with pytest.raises(StalePlan, match=r"^deployment: stale plan$"):
        service.apply(plan.id)

    assert adapter.calls == ["discover"]
    assert ledger.append_calls == 0


def test_apply_approval_plan_digest_mismatch_never_calls_adapter_or_ledger(
    mvp_root: Path,
) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root)
    path = mvp_root / "governance" / "approvals" / f"approval-{plan.id}.json"
    payload = yaml.safe_load(path.read_text())
    payload["plan_digest"] = canonical_digest({"wrong": True})
    path.write_bytes(canonical_json(payload))

    with pytest.raises(StalePlan, match=r"^deployment: stale plan$"):
        service.apply(plan.id)

    assert adapter.calls == []
    assert ledger.append_calls == 0


def test_apply_unsupported_capability_is_pre_mutation_gate(mvp_root: Path) -> None:
    targets_path = mvp_root / "governance" / "targets.yaml"
    payload = yaml.safe_load(targets_path.read_text())
    payload["items"][1]["capabilities"]["apply"] = "unsupported"
    targets_path.write_text(yaml.safe_dump(payload, sort_keys=False))
    service, adapter, ledger, plan = _approved_service(mvp_root)

    with pytest.raises(UnsupportedCapabilityError):
        service.apply(plan.id)

    assert adapter.calls == ["discover"]
    assert ledger.append_calls == 0


def test_verify_failure_appends_one_failed_ledger_without_retry(mvp_root: Path) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root, fail_stage="verify")

    with pytest.raises(AdapterFailure, match=r"^adapter: verify failed$"):
        service.apply(plan.id)

    assert adapter.calls == ["discover", "apply", "verify"]
    assert [entry.result for entry in ledger.entries] == ["failed"]


def test_success_ledger_failure_is_not_retried(mvp_root: Path) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root)
    ledger.fail_append = True

    with pytest.raises(LedgerCorruption, match=r"^ledger: append failed$"):
        service.apply(plan.id)

    assert adapter.calls == ["discover", "apply", "verify"]
    assert ledger.append_calls == 1


def test_failure_ledger_failure_replaces_adapter_error_without_retry(
    mvp_root: Path,
) -> None:
    service, adapter, ledger, plan = _approved_service(mvp_root, fail_stage="apply")
    ledger.fail_append = True

    with pytest.raises(LedgerCorruption, match=r"^ledger: append failed$"):
        service.apply(plan.id)

    assert adapter.calls == ["discover", "apply"]
    assert ledger.append_calls == 1


def test_rollback_requires_new_plan_and_approval_then_verifies(
    mvp_root: Path,
) -> None:
    service, adapter, ledger, deploy_plan = _approved_service(mvp_root)
    deployment = service.apply(deploy_plan.id)
    rollback_plan = service.create_rollback_plan(deployment.deployment_id, now=NOW)
    adapter.calls.clear()

    assert rollback_plan.id != deploy_plan.id
    assert rollback_plan.operation == "rollback"
    assert rollback_plan.parent_deployment_id == deployment.deployment_id
    with pytest.raises(ApprovalRequired, match=r"^rollback: approved plan required$"):
        service.rollback(deployment.deployment_id, rollback_plan.id)
    assert adapter.calls == []
    assert len(ledger.entries) == 1

    repository = DocumentRepository(mvp_root / "governance", mvp_root / "governance")
    ApprovalService(repository).record(
        rollback_plan.id, "reviewer", "approved", "restore reviewed", now=NOW
    )
    rollback_entry = service.rollback(deployment.deployment_id, rollback_plan.id)

    assert adapter.calls == ["discover", "rollback", "verify"]
    assert rollback_entry.result == "rolled_back"
    assert rollback_entry.parent_deployment_id == deployment.deployment_id
    assert [entry.result for entry in ledger.entries] == ["succeeded", "rolled_back"]


def test_rollback_rechecks_expiry_between_precheck_and_mutation(
    mvp_root: Path,
) -> None:
    service, adapter, ledger, deploy_plan = _approved_service(
        mvp_root,
        service_now=_sequence_clock(
            NOW + timedelta(minutes=1),
            NOW + timedelta(minutes=1),
            NOW + timedelta(minutes=1),
            NOW + timedelta(minutes=1),
            NOW + timedelta(minutes=30),
        ),
    )
    deployment = service.apply(deploy_plan.id)
    rollback_plan = service.create_rollback_plan(deployment.deployment_id, now=NOW)
    repository = DocumentRepository(mvp_root / "governance", mvp_root / "governance")
    ApprovalService(repository).record(
        rollback_plan.id, "reviewer", "approved", "restore reviewed", now=NOW
    )
    adapter.calls.clear()

    with pytest.raises(StalePlan, match=r"^rollback: stale plan$"):
        service.rollback(deployment.deployment_id, rollback_plan.id)

    assert adapter.calls == ["discover"]
    assert len(ledger.entries) == 1


def test_rollback_rejects_adapter_manifest_mismatch_before_capability(
    mvp_root: Path,
) -> None:
    service, adapter, ledger, deploy_plan = _approved_service(mvp_root)
    deployment = service.apply(deploy_plan.id)
    rollback_plan = service.create_rollback_plan(deployment.deployment_id, now=NOW)
    repository = DocumentRepository(mvp_root / "governance", mvp_root / "governance")
    ApprovalService(repository).record(
        rollback_plan.id, "reviewer", "approved", "restore reviewed", now=NOW
    )
    adapter.calls.clear()
    adapter.manifest = adapter.manifest.model_copy(update={"rollback": "unsupported"})

    with pytest.raises(StalePlan, match=r"^rollback: stale plan$"):
        service.rollback(deployment.deployment_id, rollback_plan.id)

    assert adapter.calls == []
    assert len(ledger.entries) == 1

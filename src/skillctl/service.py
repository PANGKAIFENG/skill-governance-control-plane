from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol
from uuid import uuid4

from skillctl.adapters.base import Adapter, require_capability
from skillctl.canonical import canonical_digest
from skillctl.errors import AdapterFailure, ApprovalRequired, LedgerCorruption, StalePlan
from skillctl.models import (
    DeploymentLedgerEntry,
    DeploymentResult,
    EvidenceRef,
    Plan,
    PlanChange,
    ProjectionDescriptor,
    Target,
)
from skillctl.planner import desired_assets
from skillctl.repository import DocumentRepository, GovernanceSnapshot


class Ledger(Protocol):
    def append(self, entry: DeploymentLedgerEntry) -> None: ...

    def read_all(self) -> tuple[DeploymentLedgerEntry, ...]: ...


class RuntimeSnapshotStore(Protocol):
    def capture(
        self,
        deployment_id: str,
        target: Target,
        plan: Plan,
        projection: ProjectionDescriptor,
    ) -> None: ...

    def rollback_projection(
        self,
        deployment_id: str,
        rollback_plan_id: str,
        target: Target,
        runtime_target_paths: tuple[str, ...],
    ) -> ProjectionDescriptor: ...


class DeploymentService:
    def __init__(
        self,
        repository: DocumentRepository,
        *,
        ledger: Ledger,
        adapter_for_target: Callable[[Target], Adapter],
        projection_for_plan: Callable[[Plan], ProjectionDescriptor],
        runtime_target_paths_resolver: Callable[[Target], tuple[str, ...]],
        snapshot_store: RuntimeSnapshotStore,
        now: Callable[[], datetime],
        deployment_id_factory: Callable[[], str] | None = None,
        plan_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._repository = repository
        self._ledger = ledger
        self._adapter_for_target = adapter_for_target
        self._projection_for_plan = projection_for_plan
        self._runtime_target_paths_resolver = runtime_target_paths_resolver
        self._snapshot_store = snapshot_store
        self._now = now
        self._deployment_id_factory = deployment_id_factory or (
            lambda: "deployment-" + uuid4().hex
        )
        self._plan_id_factory = plan_id_factory or (lambda: "plan-" + uuid4().hex)

    def apply(self, plan_id: str) -> DeploymentLedgerEntry:
        plan = self._repository.get_plan(plan_id)
        snapshot = self._repository.load_snapshot()
        target = self._target(snapshot, plan.target_id)
        approval = self._repository.get_approval(plan.id)
        if approval is None or approval.decision != "approved":
            raise ApprovalRequired("deployment: approved plan required")
        now = self._now()
        if now >= plan.expires_at or approval.plan_digest != plan.plan_digest:
            raise StalePlan("deployment: stale plan")

        projection = self._projection_for_plan(plan)
        adapter = self._adapter_for_target(target)
        if adapter.manifest != target.capabilities:
            raise StalePlan("deployment: stale plan")
        require_capability(target.capabilities, "discover")
        adapter.discover(target, projection)
        self._validate_fresh_state(plan, snapshot, target)
        require_capability(target.capabilities, "apply")
        require_capability(target.capabilities, "verify")

        deployment_id = self._deployment_id_factory()
        self._snapshot_store.capture(deployment_id, target, plan, projection)
        if self._now() >= plan.expires_at:
            raise StalePlan("deployment: stale plan")
        result: DeploymentResult | None = None
        try:
            result = adapter.apply(target, plan, deployment_id, projection)
            verification = adapter.verify(target, result, projection)
            if not verification.healthy:
                raise AdapterFailure("deployment: verification failed")
        except Exception:
            self._ledger.append(
                self._entry(
                    deployment_id=deployment_id,
                    plan=plan,
                    approval_ref=approval.id,
                    started_at=now,
                    result="failed",
                    evidence_refs=() if result is None else result.evidence_refs,
                    snapshot=snapshot,
                )
            )
            raise

        entry = self._entry(
            deployment_id=deployment_id,
            plan=plan,
            approval_ref=approval.id,
            started_at=now,
            result="succeeded",
            evidence_refs=result.evidence_refs + verification.evidence_refs,
            snapshot=snapshot,
        )
        self._ledger.append(entry)
        return entry

    def create_rollback_plan(self, deployment_id: str, *, now: datetime) -> Plan:
        if now.tzinfo is None or now.utcoffset() is None:
            raise StalePlan("rollback: invalid plan time")
        parent = self._deployment(deployment_id)
        if parent.result != "succeeded" or parent.parent_deployment_id is not None:
            raise LedgerCorruption("rollback: invalid deployment state")
        parent_plan = self._repository.get_plan(parent.plan_id)
        snapshot = self._repository.load_snapshot()
        target = self._target(snapshot, parent.target_id)
        runtime_paths = self._runtime_target_paths_resolver(target)
        plan_id = self._plan_id_factory()
        projection = self._snapshot_store.rollback_projection(
            deployment_id, plan_id, target, runtime_paths
        )
        changes = tuple(self._inverse_change(change) for change in parent_plan.changes)
        manifest = self._manifest_digest(target)
        unsigned = Plan(
            id=plan_id,
            operation="rollback",
            target_id=target.id,
            parent_deployment_id=deployment_id,
            changes=changes,
            risk=parent_plan.risk,
            policy_decision="allow",
            policy_reasons=(),
            created_at=now,
            expires_at=now + timedelta(minutes=30),
            source_state_digest=parent_plan.desired_state_digest,
            desired_state_digest=canonical_digest(
                {"snapshot_manifest": projection.manifest_digest}
            ),
            observed_state_digest=parent_plan.desired_state_digest,
            adapter_manifest_digest=manifest,
            adapter_evidence_digest=canonical_digest(projection),
            runtime_target_paths=runtime_paths,
            runtime_target_paths_digest=canonical_digest(runtime_paths),
            evidence_refs=(),
            plan_digest="",
        )
        plan = unsigned.model_copy(
            update={
                "plan_digest": canonical_digest(
                    unsigned.model_dump(mode="json", exclude={"plan_digest"})
                )
            }
        )
        self._repository.create_plan(plan)
        return plan

    def rollback(
        self, deployment_id: str, rollback_plan_id: str
    ) -> DeploymentLedgerEntry:
        parent = self._deployment(deployment_id)
        plan = self._repository.get_plan(rollback_plan_id)
        snapshot = self._repository.load_snapshot()
        target = self._target(snapshot, parent.target_id)
        approval = self._repository.get_approval(plan.id)
        if approval is None or approval.decision != "approved":
            raise ApprovalRequired("rollback: approved plan required")
        now = self._now()
        if now >= plan.expires_at or approval.plan_digest != plan.plan_digest:
            raise StalePlan("rollback: stale plan")
        projection = self._projection_for_plan(plan)
        self._validate_rollback_plan(plan, parent, target, projection)
        adapter = self._adapter_for_target(target)
        if adapter.manifest != target.capabilities:
            raise StalePlan("rollback: stale plan")
        require_capability(target.capabilities, "discover")
        adapter.discover(target, projection)
        require_capability(target.capabilities, "rollback")
        require_capability(target.capabilities, "verify")

        rollback_deployment_id = self._deployment_id_factory()
        if self._now() >= plan.expires_at:
            raise StalePlan("rollback: stale plan")
        result: DeploymentResult | None = None
        try:
            result = adapter.rollback(
                target, plan, rollback_deployment_id, projection
            )
            verification = adapter.verify(target, result, projection)
            if not verification.healthy:
                raise AdapterFailure("rollback: verification failed")
        except Exception:
            self._ledger.append(
                self._entry(
                    deployment_id=rollback_deployment_id,
                    plan=plan,
                    approval_ref=approval.id,
                    started_at=now,
                    result="failed",
                    evidence_refs=() if result is None else result.evidence_refs,
                    snapshot=snapshot,
                )
            )
            raise
        entry = self._entry(
            deployment_id=rollback_deployment_id,
            plan=plan,
            approval_ref=approval.id,
            started_at=now,
            result="rolled_back",
            evidence_refs=result.evidence_refs + verification.evidence_refs,
            snapshot=snapshot,
        )
        self._ledger.append(entry)
        return entry

    @staticmethod
    def _target(snapshot: GovernanceSnapshot, target_id: str) -> Target:
        target = next((item for item in snapshot.targets if item.id == target_id), None)
        if target is None:
            raise StalePlan("deployment: stale plan")
        return target

    def _validate_fresh_state(
        self,
        plan: Plan,
        snapshot: GovernanceSnapshot,
        target: Target,
    ) -> None:
        desired = desired_assets(snapshot, target.id)
        source_state = tuple(
            {
                "id": asset.id,
                "source_uri": asset.source_uri,
                "source_path": asset.source_path,
                "source_revision": asset.source_revision,
                "source_checksum": asset.source_checksum,
            }
            for asset in desired
        )
        runtime_paths = self._runtime_target_paths_resolver(target)
        snapshot_observations = tuple(
            item for item in snapshot.observations if item.target_id == target.id
        )
        if (
            plan.source_state_digest != canonical_digest(source_state)
            or plan.desired_state_digest != canonical_digest(desired)
            or plan.observed_state_digest != canonical_digest(snapshot_observations)
            or plan.adapter_manifest_digest != self._manifest_digest(target)
            or plan.runtime_target_paths != runtime_paths
            or plan.runtime_target_paths_digest != canonical_digest(runtime_paths)
        ):
            raise StalePlan("deployment: stale plan")

    @staticmethod
    def _manifest_digest(target: Target) -> str:
        return canonical_digest(
            {
                "adapter_id": target.adapter_id,
                "protocol": target.protocol,
                "capabilities": target.capabilities,
            }
        )

    def _deployment(self, deployment_id: str) -> DeploymentLedgerEntry:
        deployment = next(
            (
                entry
                for entry in self._ledger.read_all()
                if entry.deployment_id == deployment_id
            ),
            None,
        )
        if deployment is None:
            raise LedgerCorruption("deployment: unknown deployment")
        return deployment

    @staticmethod
    def _inverse_change(change: PlanChange) -> PlanChange:
        return change.model_copy(
            update={
                "change_type": "prune" if change.before_revision is None else "update",
                "before_revision": change.after_revision,
                "after_revision": change.before_revision,
                "before_visibility": change.after_visibility,
                "after_visibility": change.before_visibility,
                "evidence_refs": (),
            }
        )

    def _validate_rollback_plan(
        self,
        plan: Plan,
        parent: DeploymentLedgerEntry,
        target: Target,
        projection: ProjectionDescriptor,
    ) -> None:
        parent_plan = self._repository.get_plan(parent.plan_id)
        runtime_paths = self._runtime_target_paths_resolver(target)
        if (
            plan.operation != "rollback"
            or plan.parent_deployment_id != parent.deployment_id
            or plan.target_id != target.id
            or plan.source_state_digest != parent_plan.desired_state_digest
            or plan.desired_state_digest
            != canonical_digest({"snapshot_manifest": projection.manifest_digest})
            or plan.observed_state_digest != parent_plan.desired_state_digest
            or plan.adapter_manifest_digest != self._manifest_digest(target)
            or plan.adapter_evidence_digest != canonical_digest(projection)
            or plan.runtime_target_paths != runtime_paths
            or plan.runtime_target_paths_digest != canonical_digest(runtime_paths)
        ):
            raise StalePlan("rollback: stale plan")

    def _entry(
        self,
        *,
        deployment_id: str,
        plan: Plan,
        approval_ref: str,
        started_at: datetime,
        result: str,
        evidence_refs: tuple[EvidenceRef, ...],
        snapshot: GovernanceSnapshot,
    ) -> DeploymentLedgerEntry:
        desired = desired_assets(snapshot, plan.target_id)
        source_revisions = (
            {
                change.asset_id: change.after_revision
                for change in plan.changes
                if change.after_revision is not None
            }
            if plan.operation == "rollback"
            else {asset.id: asset.source_revision for asset in desired}
        )
        return DeploymentLedgerEntry(
            schema_version="1.0",
            deployment_id=deployment_id,
            plan_id=plan.id,
            parent_deployment_id=plan.parent_deployment_id,
            target_id=plan.target_id,
            asset_ids=tuple(change.asset_id for change in plan.changes),
            source_revisions=source_revisions,
            change_types=tuple(change.change_type for change in plan.changes),
            approval_ref=approval_ref,
            started_at=started_at,
            finished_at=self._now(),
            result=result,
            evidence_refs=evidence_refs,
            previous_entry_hash=None,
            entry_hash="",
        )

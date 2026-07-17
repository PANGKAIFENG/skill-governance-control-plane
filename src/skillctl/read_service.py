from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import cast

from pydantic import JsonValue

from skillctl.adapters.base import Adapter, require_capability
from skillctl.errors import GovernanceValidationError, StalePlan
from skillctl.models import (
    Approval,
    DeploymentLedgerEntry,
    DeploymentResult,
    DriftReport,
    EvidenceRef,
    Plan,
    ProjectionDescriptor,
    StatusReport,
    Target,
    VerificationResult,
)
from skillctl.repository import DocumentRepository, GovernanceSnapshot
from skillctl.service import Ledger


class GovernanceReadService:
    def __init__(
        self,
        repository: DocumentRepository,
        *,
        ledger: Ledger,
        adapter_for_target: Callable[[Target], Adapter],
        projection_for_plan: Callable[[Plan], ProjectionDescriptor],
        now: Callable[[], datetime],
    ) -> None:
        self._repository = repository
        self._ledger = ledger
        self._adapter_for_target = adapter_for_target
        self._projection_for_plan = projection_for_plan
        self._now = now

    def snapshot(self) -> GovernanceSnapshot:
        return self._repository.load_snapshot()

    def status(self, target_id: str | None = None) -> StatusReport:
        snapshot, targets = self._selected_targets(target_id)
        latest = self._latest_successful_deployments()
        target_health: dict[str, JsonValue] = {}
        observed_revisions: dict[str, str] = {}
        evidence_refs: list[EvidenceRef] = []
        drift_count = 0
        for target in targets:
            deployment = latest.get(target.id)
            if deployment is None:
                target_health[target.id] = cast(JsonValue, {"status": "unmanaged"})
                for observation in snapshot.observations:
                    if observation.target_id == target.id:
                        observed_revisions[
                            f"{target.id}:{observation.asset_id}"
                        ] = observation.revision
                        evidence_refs.extend(observation.evidence_refs)
                continue
            verification, discovered_refs = self._verification(target, deployment)
            health = "healthy" if verification.healthy else "drifted"
            if not verification.healthy:
                drift_count += 1
            target_health[target.id] = cast(
                JsonValue,
                {
                    "status": health,
                    "deployment_id": deployment.deployment_id,
                    "drift": verification.model_dump(mode="json")["drift"],
                },
            )
            for asset_id, revision in deployment.source_revisions.items():
                observed_revisions[f"{target.id}:{asset_id}"] = revision
            evidence_refs.extend(discovered_refs)
            evidence_refs.extend(verification.evidence_refs)
        return StatusReport(
            generated_at=self._now(),
            target_id=target_id,
            target_health=target_health,
            observed_revisions=observed_revisions,
            drift_count=drift_count,
            evidence_refs=tuple(evidence_refs),
        )

    def drift(self, target_id: str | None = None) -> DriftReport:
        _, targets = self._selected_targets(target_id)
        latest = self._latest_successful_deployments()
        changes: list[dict[str, JsonValue]] = []
        evidence_refs: list[EvidenceRef] = []
        for target in targets:
            deployment = latest.get(target.id)
            if deployment is None:
                continue
            verification, discovered_refs = self._verification(target, deployment)
            evidence_refs.extend(discovered_refs)
            evidence_refs.extend(verification.evidence_refs)
            if not verification.healthy:
                changes.append(
                    {
                        "target_id": target.id,
                        "deployment_id": deployment.deployment_id,
                        "drift": cast(
                            JsonValue,
                            verification.model_dump(mode="json")["drift"],
                        ),
                    }
                )
        return DriftReport(
            generated_at=self._now(),
            target_id=target_id,
            changes=tuple(changes),
            has_drift=bool(changes),
            evidence_refs=tuple(evidence_refs),
        )

    def deployments(self) -> tuple[DeploymentLedgerEntry, ...]:
        return self._ledger.read_all()

    def get_plan(self, plan_id: str) -> Plan:
        return self._repository.get_plan(plan_id)

    def plans(self) -> tuple[Plan, ...]:
        return self._repository.list_plans()

    def approval_for_plan(self, plan_id: str) -> Approval | None:
        return self._repository.get_approval(plan_id)

    def _selected_targets(
        self, target_id: str | None
    ) -> tuple[GovernanceSnapshot, tuple[Target, ...]]:
        snapshot = self._repository.load_snapshot()
        if target_id is None:
            return snapshot, snapshot.targets
        targets = tuple(target for target in snapshot.targets if target.id == target_id)
        if not targets:
            raise GovernanceValidationError("read service: unknown target")
        return snapshot, targets

    def _latest_successful_deployments(
        self,
    ) -> dict[str, DeploymentLedgerEntry]:
        latest: dict[str, DeploymentLedgerEntry] = {}
        for entry in self._ledger.read_all():
            if entry.result in {"succeeded", "rolled_back"}:
                latest[entry.target_id] = entry
        return latest

    def _verification(
        self, target: Target, deployment: DeploymentLedgerEntry
    ) -> tuple[VerificationResult, tuple[EvidenceRef, ...]]:
        plan = self._repository.get_plan(deployment.plan_id)
        if plan.target_id != target.id:
            raise StalePlan("read service: stale deployment")
        projection = self._projection_for_plan(plan)
        adapter = self._adapter_for_target(target)
        if adapter.manifest != target.capabilities:
            raise StalePlan("read service: stale adapter")
        require_capability(adapter.manifest, "discover")
        observations = adapter.discover(target, projection)
        require_capability(adapter.manifest, "verify")
        result = DeploymentResult(
            deployment_id=deployment.deployment_id,
            target_id=target.id,
            resolved_target_paths=plan.runtime_target_paths,
            changed_asset_ids=deployment.asset_ids,
            result=deployment.result,
            evidence_refs=deployment.evidence_refs,
        )
        verification = adapter.verify(target, result, projection)
        discovered_refs = tuple(
            ref for observation in observations for ref in observation.evidence_refs
        )
        return verification, discovered_refs

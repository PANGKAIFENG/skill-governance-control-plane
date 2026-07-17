from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable
from uuid import uuid4

from skillctl.canonical import canonical_digest
from skillctl.errors import GovernanceValidationError
from skillctl.models import AdapterPlanEvidence, Asset, ObservedState, Plan, PlanChange, Target
from skillctl.repository import DocumentRepository, GovernanceSnapshot


def desired_assets(snapshot: GovernanceSnapshot, target_id: str) -> tuple[Asset, ...]:
    if target_id not in {target.id for target in snapshot.targets}:
        raise GovernanceValidationError("planner: unknown target")

    matching_profile_ids: set[str] = set()
    for profile in snapshot.profiles:
        selector = profile.selector
        target_ids = selector.get("target_ids")
        if (
            set(selector) != {"target_ids"}
            or not isinstance(target_ids, Sequence)
            or isinstance(target_ids, (str, bytes, bytearray))
            or not all(isinstance(item, str) and item for item in target_ids)
        ):
            raise GovernanceValidationError("planner: invalid selector")
        if target_id in target_ids:
            matching_profile_ids.add(profile.id)

    approved_asset_ids = {
        membership.asset_id
        for membership in snapshot.memberships
        if membership.profile_id in matching_profile_ids and bool(membership.approval_ref.strip())
    }
    return tuple(
        sorted(
            (
                asset
                for asset in snapshot.assets
                if asset.id in approved_asset_ids
                and asset.lifecycle not in {"quarantined", "deferred"}
            ),
            key=lambda asset: asset.id,
        )
    )


def calculate_changes(
    desired: Sequence[Asset], observations: Sequence[ObservedState]
) -> tuple[PlanChange, ...]:
    observed_by_asset: dict[str, ObservedState] = {}
    for observation in observations:
        if observation.asset_id in observed_by_asset:
            raise GovernanceValidationError("planner: duplicate observation")
        observed_by_asset[observation.asset_id] = observation

    changes: list[PlanChange] = []
    for asset in sorted(desired, key=lambda item: item.id):
        current_observation = observed_by_asset.get(asset.id)
        if current_observation is None:
            change_type = "create"
            before_revision = None
        elif (
            current_observation.revision != asset.source_revision
            or current_observation.checksum != asset.source_checksum
        ):
            change_type = "update"
            before_revision = current_observation.revision
        else:
            continue
        changes.append(
            PlanChange(
                change_type=change_type,
                asset_id=asset.id,
                before_revision=before_revision,
                after_revision=asset.source_revision,
                before_visibility=None,
                after_visibility=asset.visibility,
                binding_id=None,
                permission_delta=(),
                evidence_refs=(),
            )
        )
    return tuple(changes)


def plan_digest(plan: Plan) -> str:
    return canonical_digest(plan.model_dump(mode="json", exclude={"plan_digest"}))


class PlanService:
    def __init__(
        self,
        repository: DocumentRepository,
        *,
        adapter_manifest_digest: str | None = None,
        runtime_target_paths_resolver: Callable[[Target], tuple[str, ...]] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._repository = repository
        self._adapter_manifest_digest = adapter_manifest_digest
        self._runtime_target_paths_resolver = (
            runtime_target_paths_resolver or self._default_runtime_target_paths
        )
        self._id_factory = id_factory or (lambda: "plan-" + uuid4().hex)

    def create(
        self,
        target_id: str,
        *,
        adapter_evidence: AdapterPlanEvidence,
        now: datetime,
        expires_in: timedelta,
    ) -> Plan:
        if now.tzinfo is None or now.utcoffset() is None or expires_in <= timedelta(0):
            raise GovernanceValidationError("plan: invalid expiry")
        snapshot = self._repository.load_snapshot()
        target = next((item for item in snapshot.targets if item.id == target_id), None)
        if target is None:
            raise GovernanceValidationError("plan: unknown target")
        plan_id = self._id_factory()
        if not plan_id.startswith("plan-"):
            raise GovernanceValidationError("plan: invalid id")

        desired = desired_assets(snapshot, target_id)
        observations = tuple(item for item in snapshot.observations if item.target_id == target_id)
        changes = calculate_changes(desired, observations)
        runtime_target_paths = self._runtime_target_paths_resolver(target)
        if (
            adapter_evidence.adapter_id != target.adapter_id
            or adapter_evidence.target_id != target_id
            or adapter_evidence.changes_digest != canonical_digest(changes)
            or adapter_evidence.resolved_target_paths != runtime_target_paths
            or any(ref.owner_id != plan_id for ref in adapter_evidence.evidence_refs)
        ):
            raise GovernanceValidationError("plan: adapter evidence mismatch")

        manifest_digest = self._adapter_manifest_digest or canonical_digest(
            {
                "adapter_id": target.adapter_id,
                "protocol": target.protocol,
                "capabilities": target.capabilities,
            }
        )
        unsigned = Plan(
            id=plan_id,
            operation="deploy",
            target_id=target_id,
            parent_deployment_id=None,
            changes=changes,
            risk="low",
            policy_decision="allow",
            policy_reasons=(),
            created_at=now,
            expires_at=now + expires_in,
            source_state_digest=canonical_digest(
                tuple(
                    {
                        "id": asset.id,
                        "source_uri": asset.source_uri,
                        "source_path": asset.source_path,
                        "source_revision": asset.source_revision,
                        "source_checksum": asset.source_checksum,
                    }
                    for asset in desired
                )
            ),
            desired_state_digest=canonical_digest(desired),
            observed_state_digest=canonical_digest(observations),
            adapter_manifest_digest=manifest_digest,
            adapter_evidence_digest=canonical_digest(adapter_evidence),
            runtime_target_paths=runtime_target_paths,
            runtime_target_paths_digest=canonical_digest(runtime_target_paths),
            evidence_refs=adapter_evidence.evidence_refs,
            plan_digest="",
        )
        plan = unsigned.model_copy(update={"plan_digest": plan_digest(unsigned)})
        self._repository.create_plan(plan)
        return plan

    def get(self, plan_id: str) -> Plan:
        return self._repository.get_plan(plan_id)

    @staticmethod
    def _default_runtime_target_paths(target: Target) -> tuple[str, ...]:
        root = target.config.get("root")
        if not isinstance(root, str) or not root or not Path(root).is_absolute():
            raise GovernanceValidationError("plan: runtime target paths unavailable")
        resolved = str(Path(root).resolve(strict=False))
        if resolved != root:
            raise GovernanceValidationError("plan: runtime target paths unavailable")
        return (resolved,)

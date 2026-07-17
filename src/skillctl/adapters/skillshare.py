from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from pydantic import JsonValue

from skillctl.adapters.base import AdapterOperation, require_capability
from skillctl.canonical import canonical_digest
from skillctl.config import ControlPlaneConfig
from skillctl.errors import AdapterFailure, SafetyViolation
from skillctl.models import (
    AdapterPlanEvidence,
    CapabilityManifest,
    DeploymentResult,
    ObservedState,
    Plan,
    PlanChange,
    ProjectionDescriptor,
    Target,
    VerificationResult,
)
from skillctl.projection import validate_projection
from skillctl.runner import Runner

TARGET_LIST = ("target", "list", "--project", "--json", "--no-tui")
DIFF = ("diff", "--project", "--json", "--no-tui")
DRY_RUN = ("sync", "--project", "--dry-run", "--json", "--quiet")
APPLY = ("sync", "--project", "--json", "--quiet")

_FORBIDDEN_ARGUMENTS = {
    "--global",
    "--force",
    "collect",
    "install",
    "uninstall",
    "pull",
    "push",
    "update",
}
_ALLOWED_COMMANDS = {TARGET_LIST, DIFF, DRY_RUN, APPLY}


class SkillshareAdapter:
    def __init__(
        self,
        config: ControlPlaneConfig,
        *,
        runner: Runner,
        manifest: CapabilityManifest,
    ) -> None:
        self._config = config
        self._runner = runner
        self.manifest = manifest
        self._executable = config.trusted_cli_paths["skillshare"]

    def _run(
        self,
        operation: AdapterOperation,
        args: tuple[str, ...],
        projection: ProjectionDescriptor,
    ) -> tuple[JsonValue, tuple[str, ...]]:
        require_capability(self.manifest, operation)
        target_paths = validate_projection(self._config, projection)
        if args not in _ALLOWED_COMMANDS or _FORBIDDEN_ARGUMENTS.intersection(args):
            raise SafetyViolation("Skillshare command is not allowed")
        result = self._runner.run(
            self._executable, args, cwd=Path(projection.root)
        )
        return result.payload, target_paths

    def discover(
        self, target: Target, projection: ProjectionDescriptor
    ) -> tuple[ObservedState, ...]:
        self._run("discover", TARGET_LIST, projection)
        return ()

    def plan(
        self,
        target: Target,
        changes: tuple[PlanChange, ...],
        plan_id: str,
        projection: ProjectionDescriptor,
    ) -> AdapterPlanEvidence:
        if plan_id != projection.plan_id:
            raise SafetyViolation("adapter plan does not match projection")
        payload, target_paths = self._run("plan", DRY_RUN, projection)
        return AdapterPlanEvidence(
            adapter_id=target.adapter_id,
            target_id=target.id,
            changes_digest=canonical_digest(changes),
            resolved_target_paths=target_paths,
            evidence_refs=(),
            raw_evidence_digest=canonical_digest(payload),
        )

    def apply(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult:
        target_paths = self._validate_plan(target, plan, projection)
        self._run("apply", APPLY, projection)
        return DeploymentResult(
            deployment_id=deployment_id,
            target_id=target.id,
            resolved_target_paths=target_paths,
            changed_asset_ids=tuple(change.asset_id for change in plan.changes),
            result="applied",
            evidence_refs=(),
        )

    def verify(
        self,
        target: Target,
        deployment: DeploymentResult,
        projection: ProjectionDescriptor,
    ) -> VerificationResult:
        payload, target_paths = self._run("verify", DIFF, projection)
        if deployment.target_id != target.id or deployment.resolved_target_paths != target_paths:
            raise SafetyViolation("deployment does not match projection targets")
        healthy, drift = _parse_diff(payload)
        return VerificationResult(
            deployment_id=deployment.deployment_id,
            target_id=target.id,
            resolved_target_paths=target_paths,
            healthy=healthy,
            drift=drift,
            evidence_refs=(),
        )

    def rollback(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult:
        target_paths = self._validate_plan(target, plan, projection)
        self._run("rollback", APPLY, projection)
        return DeploymentResult(
            deployment_id=deployment_id,
            target_id=target.id,
            resolved_target_paths=target_paths,
            changed_asset_ids=tuple(change.asset_id for change in plan.changes),
            result="rolled-back",
            evidence_refs=(),
        )

    def _validate_plan(
        self, target: Target, plan: Plan, projection: ProjectionDescriptor
    ) -> tuple[str, ...]:
        target_paths = validate_projection(self._config, projection)
        if (
            plan.id != projection.plan_id
            or plan.target_id != target.id
            or plan.runtime_target_paths != target_paths
        ):
            raise SafetyViolation("plan does not match projection targets")
        return target_paths


def _parse_diff(payload: JsonValue) -> tuple[bool, dict[str, JsonValue]]:
    expected_targets = {"target-a", "target-b"}
    if not isinstance(payload, Mapping):
        raise AdapterFailure("Skillshare diff output is invalid") from None

    targets = payload.get("targets")
    if not isinstance(targets, Sequence) or isinstance(targets, str):
        raise AdapterFailure("Skillshare diff output is invalid") from None

    target_states: dict[str, tuple[bool, bool]] = {}
    for target_state in targets:
        if not isinstance(target_state, Mapping):
            raise AdapterFailure("Skillshare diff output is invalid") from None

        name = target_state.get("name")
        synced = target_state.get("synced")
        items = target_state.get("items")
        if (
            not isinstance(name, str)
            or name not in expected_targets
            or name in target_states
            or not isinstance(synced, bool)
            or not isinstance(items, Sequence)
            or isinstance(items, str)
        ):
            raise AdapterFailure("Skillshare diff output is invalid") from None
        target_states[name] = (synced, bool(items))

    if set(target_states) != expected_targets:
        raise AdapterFailure("Skillshare diff output is invalid") from None

    has_drift = any(not synced or has_items for synced, has_items in target_states.values())
    drift: dict[str, JsonValue] = {"detected": has_drift}
    return not has_drift, drift

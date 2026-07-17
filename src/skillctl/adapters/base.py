from __future__ import annotations

from typing import Literal, Protocol

from skillctl.errors import UnsupportedCapabilityError
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

AdapterOperation = Literal["discover", "plan", "apply", "verify", "rollback"]


def require_capability(
    manifest: CapabilityManifest, operation: AdapterOperation
) -> None:
    if getattr(manifest, operation) != "supported":
        raise UnsupportedCapabilityError("adapter capability is not supported")


class Adapter(Protocol):
    manifest: CapabilityManifest

    def discover(
        self, target: Target, projection: ProjectionDescriptor
    ) -> tuple[ObservedState, ...]: ...

    def plan(
        self,
        target: Target,
        changes: tuple[PlanChange, ...],
        plan_id: str,
        projection: ProjectionDescriptor,
    ) -> AdapterPlanEvidence: ...

    def apply(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult: ...

    def verify(
        self,
        target: Target,
        deployment: DeploymentResult,
        projection: ProjectionDescriptor,
    ) -> VerificationResult: ...

    def rollback(
        self,
        target: Target,
        plan: Plan,
        deployment_id: str,
        projection: ProjectionDescriptor,
    ) -> DeploymentResult: ...

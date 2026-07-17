from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from pydantic import JsonValue

from skillctl.models import (
    Asset,
    DeploymentLedgerEntry,
    DriftReport,
    StatusReport,
    Target,
)
from skillctl.repository import GovernanceSnapshot


@dataclass(frozen=True)
class AssetPresentation:
    id: str
    name: str
    owner: str
    visibility: str
    revision: str


@dataclass(frozen=True)
class TargetPresentation:
    id: str
    adapter_id: str
    protocol: str
    available: bool


@dataclass(frozen=True)
class TargetHealthPresentation:
    id: str
    adapter_id: str
    protocol: str
    health: str
    observed: tuple[str, ...]


@dataclass(frozen=True)
class DeploymentPresentation:
    deployment_id: str
    plan_id: str
    target_id: str
    result: str
    finished_at: datetime


@dataclass(frozen=True)
class WorkspacePresentation:
    consumer_type: str
    consumer_id: str
    asset_ids: tuple[str, ...]
    targets: tuple[TargetPresentation, ...]


@dataclass(frozen=True)
class ProjectPresentation:
    id: str
    name: str
    policy_id: str
    assets: tuple[AssetPresentation, ...]
    workspaces: tuple[WorkspacePresentation, ...]
    unbound_asset_count: int


@dataclass(frozen=True)
class DashboardPresentation:
    projects: tuple[ProjectPresentation, ...]
    unassigned_assets: tuple[AssetPresentation, ...]
    issue_count: int
    asset_count: int
    target_count: int
    drift_count: int
    failed_deployment_count: int
    generated_at: datetime | None
    targets: tuple[TargetHealthPresentation, ...]
    deployments: tuple[DeploymentPresentation, ...]


def build_dashboard_presentation(
    snapshot: GovernanceSnapshot,
    status: StatusReport | None = None,
    drift: DriftReport | None = None,
    deployments: tuple[DeploymentLedgerEntry, ...] = (),
) -> DashboardPresentation:
    assets = {asset.id: asset for asset in snapshot.assets}
    targets = {target.id: target for target in snapshot.targets}
    profiles = {profile.id: profile for profile in snapshot.profiles}
    memberships_by_profile: dict[str, set[str]] = defaultdict(set)
    issue_count = 0

    for membership in snapshot.memberships:
        if membership.profile_id not in profiles:
            issue_count += 1
            continue
        if membership.asset_id not in assets:
            issue_count += 1
            continue
        memberships_by_profile[membership.profile_id].add(membership.asset_id)

    bindings_by_asset: dict[str, list[tuple[str, str, TargetPresentation]]] = (
        defaultdict(list)
    )
    for binding in snapshot.bindings:
        if binding.asset_id not in assets:
            issue_count += 1
            continue
        consumer_type = binding.consumer_type.strip()
        consumer_id = binding.consumer_id.strip()
        if not consumer_type:
            consumer_type = "未标识类型"
            issue_count += 1
        if not consumer_id:
            consumer_id = "未标识工作区"
            issue_count += 1
        target_model = targets.get(binding.target_id)
        if target_model is None:
            issue_count += 1
        bindings_by_asset[binding.asset_id].append(
            (
                consumer_type,
                consumer_id,
                _target_presentation(target_model, binding.target_id),
            )
        )

    projects = []
    assigned_asset_ids: set[str] = set()
    for profile_id in sorted(profiles):
        profile = profiles[profile_id]
        asset_ids = memberships_by_profile.get(profile_id, set())
        assigned_asset_ids.update(asset_ids)
        workspace_assets: dict[tuple[str, str], set[str]] = defaultdict(set)
        workspace_targets: dict[
            tuple[str, str], dict[str, TargetPresentation]
        ] = defaultdict(dict)
        for asset_id in sorted(asset_ids):
            for consumer_type, consumer_id, target_view in bindings_by_asset.get(
                asset_id, ()
            ):
                key = (consumer_type, consumer_id)
                workspace_assets[key].add(asset_id)
                workspace_targets[key][target_view.id] = target_view

        workspaces = tuple(
            WorkspacePresentation(
                consumer_type=consumer_type,
                consumer_id=consumer_id,
                asset_ids=tuple(sorted(workspace_assets[(consumer_type, consumer_id)])),
                targets=tuple(
                    target_view
                    for _, target_view in sorted(
                        workspace_targets[(consumer_type, consumer_id)].items()
                    )
                ),
            )
            for consumer_type, consumer_id in sorted(
                workspace_assets,
                key=lambda key: (
                    key[1] != "未标识工作区",
                    key[0],
                    key[1],
                ),
            )
        )
        projects.append(
            ProjectPresentation(
                id=profile.id,
                name=profile.name,
                policy_id=profile.policy_id,
                assets=tuple(
                    _asset_presentation(assets[asset_id])
                    for asset_id in sorted(asset_ids)
                ),
                workspaces=workspaces,
                unbound_asset_count=sum(
                    1 for asset_id in asset_ids if not bindings_by_asset.get(asset_id)
                ),
            )
        )

    return DashboardPresentation(
        projects=tuple(projects),
        unassigned_assets=tuple(
            _asset_presentation(asset)
            for asset_id, asset in sorted(assets.items())
            if asset_id not in assigned_asset_ids
        ),
        issue_count=issue_count,
        asset_count=len(assets),
        target_count=len(targets),
        drift_count=0 if status is None else status.drift_count,
        failed_deployment_count=sum(
            1 for deployment in deployments if deployment.result == "failed"
        ),
        generated_at=None if status is None else status.generated_at,
        targets=_target_health_presentations(targets, status),
        deployments=tuple(
            DeploymentPresentation(
                deployment_id=deployment.deployment_id,
                plan_id=deployment.plan_id,
                target_id=deployment.target_id,
                result=deployment.result,
                finished_at=deployment.finished_at,
            )
            for deployment in reversed(deployments[-10:])
        ),
    )


def _asset_presentation(asset: Asset) -> AssetPresentation:
    return AssetPresentation(
        id=asset.id,
        name=asset.name,
        owner=asset.owner,
        visibility=asset.visibility,
        revision=asset.source_revision,
    )


def _target_presentation(target: Target | None, target_id: str) -> TargetPresentation:
    if target is None:
        return TargetPresentation(
            id=target_id,
            adapter_id="未知 Adapter",
            protocol="未知协议",
            available=False,
        )
    return TargetPresentation(
        id=target.id,
        adapter_id=target.adapter_id,
        protocol=target.protocol,
        available=True,
    )


def _target_health_presentations(
    targets: dict[str, Target], status: StatusReport | None
) -> tuple[TargetHealthPresentation, ...]:
    rows = []
    for target_id, target in sorted(targets.items()):
        health = "unknown"
        observed: tuple[str, ...] = ()
        if status is not None:
            value = status.target_health.get(target_id, {"status": "unknown"})
            if isinstance(value, Mapping):
                mapping = cast(Mapping[str, JsonValue], value)
                health = str(mapping.get("status", "unknown"))
            observed = tuple(
                sorted(
                    revision
                    for key, revision in status.observed_revisions.items()
                    if key.startswith(f"{target_id}:")
                )
            )
        rows.append(
            TargetHealthPresentation(
                id=target.id,
                adapter_id=target.adapter_id,
                protocol=target.protocol,
                health=health,
                observed=observed,
            )
        )
    return tuple(rows)

from __future__ import annotations

from datetime import datetime, timezone

from skillctl.models import (
    Asset,
    CapabilityManifest,
    ConsumerBinding,
    DeploymentProfile,
    ProfileMembership,
    Target,
)
from skillctl.repository import GovernanceSnapshot
from skillctl.web.presentation import build_dashboard_presentation


NOW = datetime(2026, 7, 14, tzinfo=timezone.utc)


def _asset(asset_id: str) -> Asset:
    return Asset(
        id=asset_id,
        name=asset_id.removeprefix("asset-"),
        asset_type="skill",
        owner="governance",
        visibility="private",
        lifecycle="canonical",
        authority_class="private",
        source_uri=None,
        source_path=None,
        source_revision=f"revision-{asset_id}",
        source_checksum=f"sha256:{asset_id}",
        license_state="internal",
        revision_policy="pinned",
    )


def _profile(profile_id: str) -> DeploymentProfile:
    return DeploymentProfile(
        id=profile_id,
        name=profile_id.removeprefix("profile-"),
        selector={},
        policy_id="policy-default",
    )


def _membership(profile_id: str, asset_id: str) -> ProfileMembership:
    return ProfileMembership(
        id=f"membership-{profile_id}-{asset_id}",
        asset_id=asset_id,
        profile_id=profile_id,
        approved_at=NOW,
        approval_ref="approval-membership",
    )


def _target(target_id: str) -> Target:
    return Target(
        id=target_id,
        adapter_id="filesystem",
        protocol="filesystem",
        config={},
        capabilities=CapabilityManifest(
            discover="supported",
            plan="supported",
            apply="supported",
            verify="supported",
            rollback="supported",
        ),
    )


def _binding(
    binding_id: str,
    asset_id: str,
    target_id: str,
    consumer_type: str,
    consumer_id: str,
) -> ConsumerBinding:
    return ConsumerBinding(
        id=binding_id,
        asset_id=asset_id,
        target_id=target_id,
        consumer_type=consumer_type,
        consumer_id=consumer_id,
        approved_at=NOW,
        approval_ref="approval-binding",
    )


def test_builds_stable_multi_project_workspace_projection() -> None:
    snapshot = GovernanceSnapshot(
        assets=(_asset("asset-zulu"), _asset("asset-alpha"), _asset("asset-shared")),
        targets=(_target("target-zulu"), _target("target-alpha")),
        profiles=(_profile("profile-zulu"), _profile("profile-alpha")),
        memberships=(
            _membership("profile-zulu", "asset-shared"),
            _membership("profile-alpha", "asset-shared"),
            _membership("profile-alpha", "asset-alpha"),
        ),
        bindings=(
            _binding(
                "binding-zulu",
                "asset-shared",
                "target-zulu",
                "project",
                "workspace-zulu",
            ),
            _binding(
                "binding-alpha",
                "asset-alpha",
                "target-alpha",
                "project",
                "workspace-alpha",
            ),
        ),
        observations=(),
    )

    first = build_dashboard_presentation(snapshot)
    second = build_dashboard_presentation(snapshot)

    assert first == second
    assert tuple(project.id for project in first.projects) == (
        "profile-alpha",
        "profile-zulu",
    )
    assert tuple(asset.id for asset in first.projects[0].assets) == (
        "asset-alpha",
        "asset-shared",
    )
    assert tuple(workspace.consumer_id for workspace in first.projects[0].workspaces) == (
        "workspace-alpha",
        "workspace-zulu",
    )
    assert first.projects[1].assets[0].id == "asset-shared"
    assert first.unassigned_assets[0].id == "asset-zulu"


def test_keeps_empty_unbound_and_dangling_relationships_visible_without_raising() -> None:
    snapshot = GovernanceSnapshot(
        assets=(_asset("asset-unbound"), _asset("asset-orphan")),
        targets=(_target("target-known"),),
        profiles=(_profile("profile-empty"), _profile("profile-main")),
        memberships=(
            _membership("profile-main", "asset-unbound"),
            _membership("profile-missing", "asset-orphan"),
            _membership("profile-main", "asset-missing"),
        ),
        bindings=(
            _binding(
                "binding-empty-consumer",
                "asset-unbound",
                "target-known",
                "project",
                "",
            ),
            _binding(
                "binding-missing-target",
                "asset-unbound",
                "target-missing",
                "project",
                "workspace-main",
            ),
            _binding(
                "binding-missing-asset",
                "asset-missing",
                "target-known",
                "project",
                "workspace-main",
            ),
        ),
        observations=(),
    )

    result = build_dashboard_presentation(snapshot)

    empty, main = result.projects
    assert empty.id == "profile-empty"
    assert empty.assets == () and empty.workspaces == ()
    assert main.unbound_asset_count == 0
    assert tuple(workspace.consumer_id for workspace in main.workspaces) == (
        "未标识工作区",
        "workspace-main",
    )
    assert main.workspaces[1].targets[0].id == "target-missing"
    assert main.workspaces[1].targets[0].available is False
    assert tuple(asset.id for asset in result.unassigned_assets) == ("asset-orphan",)
    assert result.issue_count == 5

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from collections.abc import Iterator
import socket
from threading import Thread
import time
from typing import Any
from urllib.request import urlopen

import pytest
import uvicorn

from skillctl.models import (
    Approval,
    Asset,
    CapabilityManifest,
    ConsumerBinding,
    DeploymentLedgerEntry,
    DeploymentProfile,
    DriftReport,
    Plan,
    PlanChange,
    ProfileMembership,
    StatusReport,
    Target,
)
from skillctl.repository import GovernanceSnapshot
from skillctl.runtime_inventory.models import (
    RuntimeIgnoredSkill,
    RuntimeInventoryReadResult,
    RuntimeInventorySnapshot,
    RuntimeSkillAsset,
    RuntimeSkillInstance,
    RuntimeTarget,
)
from skillctl.web.readiness import GateReadiness


NOW = datetime(2026, 7, 14, 3, 0, tzinfo=timezone.utc)
PLAN_ID = "plan-" + "a" * 32
PLAN_DIGEST = "sha256:" + "d" * 64


class FakeReadService:
    def __init__(self, *, approved: bool = False) -> None:
        asset = Asset(
            id="asset-canary-long-identifier-for-responsive-checks",
            name="canary-skill",
            asset_type="skill",
            owner="governance<script>alert(1)</script>",
            visibility="private",
            lifecycle="canonical",
            authority_class="private",
            source_uri=None,
            source_path="/Users/hidden/authority/canary-skill",
            source_revision="revision-canary-1",
            source_checksum="sha256:canary",
            license_state="internal",
            revision_policy="pinned",
        )
        shared_asset = asset.model_copy(
            update={
                "id": "asset-shared-across-projects",
                "name": "shared-review-skill",
                "source_revision": "revision-shared-2",
                "source_checksum": "sha256:shared",
            }
        )
        unbound_asset = asset.model_copy(
            update={
                "id": "asset-without-consumer-binding",
                "name": "unbound-skill",
                "source_revision": "revision-unbound-1",
                "source_checksum": "sha256:unbound",
            }
        )
        target = Target(
            id="target-local-b",
            adapter_id="filesystem",
            protocol="filesystem",
            credential_ref="PORTAL_TEST_CREDENTIAL",
            config={"root": "/Users/hidden/runtime"},
            capabilities=CapabilityManifest(
                discover="supported",
                plan="supported",
                apply="supported",
                verify="supported",
                rollback="supported",
            ),
        )
        change = PlanChange(
            change_type="update",
            asset_id=asset.id,
            before_revision="revision-before",
            after_revision="revision-after",
            before_visibility="private",
            after_visibility="public",
            binding_id="binding-canary-local-b",
            permission_delta=("read", "publish"),
            evidence_refs=(),
        )
        self.plan = Plan(
            id=PLAN_ID,
            operation="deploy",
            target_id=target.id,
            parent_deployment_id=None,
            changes=(change,),
            risk="high",
            policy_decision="review_required",
            policy_reasons=("Visibility changes require <review>.",),
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            source_state_digest="sha256:" + "1" * 64,
            desired_state_digest="sha256:" + "2" * 64,
            observed_state_digest="sha256:" + "3" * 64,
            adapter_manifest_digest="sha256:" + "4" * 64,
            adapter_evidence_digest="sha256:" + "5" * 64,
            runtime_target_paths=("/Users/hidden/runtime/target-a",),
            runtime_target_paths_digest="sha256:" + "6" * 64,
            evidence_refs=(),
            plan_digest=PLAN_DIGEST,
        )
        self._snapshot = GovernanceSnapshot(
            assets=(asset, shared_asset, unbound_asset),
            targets=(target,),
            profiles=(
                DeploymentProfile(
                    id="profile-design",
                    name="设计协作项目",
                    selector={},
                    policy_id="policy-private",
                ),
                DeploymentProfile(
                    id="profile-product",
                    name="产品治理项目",
                    selector={},
                    policy_id="policy-private",
                ),
            ),
            memberships=(
                ProfileMembership(
                    id="membership-design-shared",
                    asset_id=shared_asset.id,
                    profile_id="profile-design",
                    approved_at=NOW,
                    approval_ref="approval-membership-design",
                ),
                ProfileMembership(
                    id="membership-product-canary",
                    asset_id=asset.id,
                    profile_id="profile-product",
                    approved_at=NOW,
                    approval_ref="approval-membership-product",
                ),
                ProfileMembership(
                    id="membership-product-shared",
                    asset_id=shared_asset.id,
                    profile_id="profile-product",
                    approved_at=NOW,
                    approval_ref="approval-membership-product-shared",
                ),
                ProfileMembership(
                    id="membership-product-unbound",
                    asset_id=unbound_asset.id,
                    profile_id="profile-product",
                    approved_at=NOW,
                    approval_ref="approval-membership-product-unbound",
                ),
            ),
            bindings=(
                ConsumerBinding(
                    id="binding-canary-workspace-product",
                    asset_id=asset.id,
                    target_id=target.id,
                    consumer_type="workspace",
                    consumer_id="workspace-product-long-identifier-for-responsive-checks",
                    approved_at=NOW,
                    approval_ref="approval-binding-product",
                ),
                ConsumerBinding(
                    id="binding-shared-workspace-design",
                    asset_id=shared_asset.id,
                    target_id="target-missing-read-only",
                    consumer_type="workspace",
                    consumer_id="workspace-design",
                    approved_at=NOW,
                    approval_ref="approval-binding-design",
                ),
            ),
            observations=(),
        )
        self._status = StatusReport(
            generated_at=NOW,
            target_id=None,
            target_health={
                target.id: {
                    "status": "drifted",
                    "deployment_id": "deployment-" + "b" * 32,
                    "drift": {"revision": "unexpected"},
                }
            },
            observed_revisions={f"{target.id}:{asset.id}": "revision-observed-0"},
            drift_count=1,
            evidence_refs=(),
        )
        self._drift = DriftReport(
            generated_at=NOW,
            target_id=None,
            changes=(
                {
                    "target_id": target.id,
                    "deployment_id": "deployment-" + "b" * 32,
                    "drift": {"revision": "unexpected"},
                },
            ),
            has_drift=True,
            evidence_refs=(),
        )
        self._deployments = (
            DeploymentLedgerEntry(
                schema_version="1.0",
                deployment_id="deployment-" + "b" * 32,
                plan_id=self.plan.id,
                parent_deployment_id=None,
                target_id=target.id,
                asset_ids=(asset.id,),
                source_revisions={asset.id: asset.source_revision},
                change_types=("update",),
                approval_ref=f"approval-{self.plan.id}",
                started_at=NOW - timedelta(minutes=2),
                finished_at=NOW - timedelta(minutes=1),
                result="failed",
                evidence_refs=(),
                previous_entry_hash=None,
                entry_hash="sha256:" + "7" * 64,
            ),
        )
        self._approval = (
            Approval(
                id=f"approval-{self.plan.id}",
                plan_id=self.plan.id,
                plan_digest=self.plan.plan_digest,
                decision="approved",
                approver="portal-reviewer",
                reason="Reviewed typed diff",
                decided_at=NOW,
            )
            if approved
            else None
        )

    def snapshot(self) -> GovernanceSnapshot:
        return self._snapshot

    def status(self, target_id: str | None = None) -> StatusReport:
        return self._status

    def drift(self, target_id: str | None = None) -> DriftReport:
        return self._drift

    def deployments(self) -> tuple[DeploymentLedgerEntry, ...]:
        return self._deployments

    def plans(self) -> tuple[Plan, ...]:
        return (self.plan,)

    def get_plan(self, plan_id: str) -> Plan:
        if plan_id != self.plan.id:
            raise LookupError("TOP_SECRET_RAW_EXCEPTION /Users/hidden/authority")
        return self.plan

    def approval_for_plan(self, plan_id: str) -> Approval | None:
        return self._approval


class ApprovalSpy:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def record(self, *args: Any, **kwargs: Any) -> Approval:
        self.calls.append({"args": args, "kwargs": kwargs})
        return Approval(
            id=f"approval-{PLAN_ID}",
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
            decision=args[2],
            approver=args[1],
            reason=args[3],
            decided_at=kwargs["now"],
        )


class FakeReadinessProvider:
    def __init__(self) -> None:
        self.rows: tuple[GateReadiness, ...] = (
            GateReadiness(
                "Gate 1", "运行源基线", "VERIFIED", "由 Gate 2 复核证据证明"
            ),
            GateReadiness(
                "Gate 2",
                "核心资产裁决",
                "COMPLETED_WITH_CONCERNS",
                "裁决完成，保留已记录关注项",
            ),
            GateReadiness(
                "Gate 3", "Authority 候选", "COMPLETED", "13 个批准路径已完成"
            ),
            GateReadiness(
                "Gate 4", "Adapter 兼容性", "PASS", "隔离兼容性与安全校验通过"
            ),
        )

    def readiness(self) -> tuple[GateReadiness, ...]:
        return self.rows


class FakeRuntimeInventoryReader:
    def __init__(self, result: RuntimeInventoryReadResult | None = None) -> None:
        shared = RuntimeSkillInstance(
            location_kind="shared",
            target_name=None,
            path="/Users/shared/skills/design-review",
            distribution_mode="shared",
            digest="sha256:" + "a" * 64,
            is_symlink=False,
            readable=True,
        )
        claude_copy = RuntimeSkillInstance(
            location_kind="target",
            target_name="Claude",
            path="/Users/agents/claude/skills/design-review",
            distribution_mode="copy",
            digest="sha256:" + "a" * 64,
            is_symlink=False,
            readable=True,
        )
        codex_diverged = RuntimeSkillInstance(
            location_kind="target",
            target_name="Codex",
            path="/Users/agents/codex/skills/visual-scan",
            distribution_mode="symlink",
            digest="sha256:" + "b" * 64,
            is_symlink=True,
            readable=True,
        )
        local_copy = RuntimeSkillInstance(
            location_kind="target",
            target_name="Codex",
            path="/Users/agents/codex/skills/local-tool",
            distribution_mode="copy",
            digest="sha256:" + "c" * 64,
            is_symlink=False,
            readable=True,
        )
        snapshot = RuntimeInventorySnapshot(
            generated_at=NOW,
            skillshare_version="0.20.21",
            source_path="/Users/shared/skills",
            targets=(
                RuntimeTarget(
                    name="Claude",
                    path="/Users/agents/claude/skills",
                    mode="merge",
                ),
                RuntimeTarget(
                    name="Codex",
                    path="/Users/agents/codex/skills",
                    mode="copy",
                ),
                RuntimeTarget(
                    name="WorkBuddy",
                    path="/Users/agents/workbuddy/skills",
                    mode="copy",
                    readable=False,
                ),
            ),
            assets=(
                RuntimeSkillAsset(
                    key="visual-scan",
                    name="Visual Scan",
                    description="视觉内容检查",
                    status="diverged",
                    source_instance=shared.model_copy(
                        update={"path": "/Users/shared/skills/visual-scan"}
                    ),
                    target_instances=(codex_diverged,),
                ),
                RuntimeSkillAsset(
                    key="design-review",
                    name="Design Review",
                    description="设计评审",
                    status="consistent",
                    source_instance=shared,
                    target_instances=(claude_copy,),
                ),
                RuntimeSkillAsset(
                    key="local-tool",
                    name="Local Tool",
                    description=None,
                    status="local_only",
                    source_instance=None,
                    target_instances=(local_copy,),
                ),
            ),
            ignored=(
                RuntimeIgnoredSkill(
                    name="ignored-experiment",
                    path="/Users/shared/skills/ignored-experiment",
                    reason=".skillignore",
                ),
            ),
            warnings=("target WorkBuddy unreadable",),
            snapshot_digest="sha256:" + "f" * 64,
        )
        self.result = result or RuntimeInventoryReadResult(
            available=True,
            snapshot=snapshot,
        )
        self.read_calls = 0

    def read(self) -> RuntimeInventoryReadResult:
        self.read_calls += 1
        return self.result


@pytest.fixture
def read_service() -> FakeReadService:
    return FakeReadService()


@pytest.fixture
def approval_spy() -> ApprovalSpy:
    return ApprovalSpy()


@pytest.fixture
def readiness_provider() -> FakeReadinessProvider:
    return FakeReadinessProvider()


@pytest.fixture
def runtime_inventory_reader() -> FakeRuntimeInventoryReader:
    return FakeRuntimeInventoryReader()


@pytest.fixture
def portal_server() -> Iterator[tuple[str, ApprovalSpy]]:
    from skillctl.web.app import PortalReadProviders, create_app
    from skillctl.web.security import DecisionTokenStore

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    approval = ApprovalSpy()
    app = create_app(
        FakeReadService(),
        approval,
        DecisionTokenStore(
            now=lambda: NOW,
            allowed_origins=(origin,),
            approver="portal-reviewer",
        ),
        PortalReadProviders(FakeReadinessProvider(), FakeRuntimeInventoryReader()),
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="critical",
            access_log=False,
        )
    )
    thread = Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        try:
            with urlopen(origin, timeout=0.2) as response:
                if response.status == 200:
                    break
        except OSError:
            time.sleep(0.02)
    else:
        server.should_exit = True
        thread.join(timeout=2)
        raise RuntimeError("portal server did not start")
    try:
        yield origin, approval
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        assert not thread.is_alive()

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from skillctl.approvals import ApprovalService
from skillctl.canonical import canonical_digest
from skillctl.errors import PolicyDenied, StalePlan
from skillctl.models import AdapterPlanEvidence, Approval, Plan
from skillctl.planner import PlanService, calculate_changes, desired_assets
from skillctl.repository import DocumentRepository
import skillctl.repository as repository_module


NOW = datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc)


def _repository(mvp_root: Path) -> DocumentRepository:
    root = mvp_root / "governance"
    return DocumentRepository(root, root)


def _create_plan(repository: DocumentRepository, *, expires_in: timedelta) -> Plan:
    snapshot = repository.load_snapshot()
    changes = calculate_changes(desired_assets(snapshot, "target-local-b"), ())
    evidence = AdapterPlanEvidence(
        adapter_id="filesystem",
        target_id="target-local-b",
        changes_digest=canonical_digest(changes),
        resolved_target_paths=("/private/tmp/skill-governance-target-b",),
        evidence_refs=(),
        raw_evidence_digest=canonical_digest({"dry_run": "ok"}),
    )
    return PlanService(repository).create(
        "target-local-b",
        adapter_evidence=evidence,
        now=NOW,
        expires_in=expires_in,
    )


def test_record_persists_approval_bound_to_verified_plan(mvp_root: Path) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))

    approval = ApprovalService(repository).record(
        plan.id, "alice", "approved", "reviewed typed diff", now=NOW
    )

    assert approval == Approval.model_validate_json(
        (mvp_root / "governance" / "approvals" / f"approval-{plan.id}.json").read_bytes()
    )
    assert approval.id == f"approval-{plan.id}"
    assert approval.plan_digest == plan.plan_digest


@pytest.mark.parametrize(
    ("approver", "reason"), [("", "reviewed"), ("   ", "reviewed"), ("alice", "")]
)
def test_record_rejects_blank_approver_or_reason(
    mvp_root: Path, approver: str, reason: str
) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))

    with pytest.raises(PolicyDenied, match=r"^approval: identity and reason required$"):
        ApprovalService(repository).record(plan.id, approver, "approved", reason, now=NOW)


@pytest.mark.parametrize(
    "reason",
    (
        "token=synthetic-credential-value",
        "password: synthetic-credential-value",
        "api_key=synthetic-credential-value",
        "Bearer synthetic-credential-value",
        "ghp_" + "syntheticcredentialvalue",
        "github_pat_" + "syntheticcredentialvalue",
        "sk-" + "syntheticcredentialvalue",
    ),
    ids=(
        "token-pair",
        "password-pair",
        "api-key-pair",
        "bearer",
        "github-token",
        "github-pat",
        "api-token",
    ),
)
def test_record_rejects_secret_like_reason_without_persisting(
    mvp_root: Path, reason: str
) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))

    with pytest.raises(
        PolicyDenied, match=r"^approval: secret-like reason is forbidden$"
    ):
        ApprovalService(repository).record(
            plan.id, "alice", "approved", reason, now=NOW
        )

    approval_path = (
        mvp_root / "governance" / "approvals" / f"approval-{plan.id}.json"
    )
    assert not approval_path.exists()
    assert all(
        reason.encode() not in path.read_bytes()
        for path in (mvp_root / "governance").rglob("*")
        if path.is_file()
    )


def test_record_rejects_sensitive_environment_value_without_persisting(
    mvp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))
    synthetic_value = "synthetic-environment-credential"
    monkeypatch.setenv("SYNTHETIC_API_TOKEN", synthetic_value)

    with pytest.raises(
        PolicyDenied, match=r"^approval: secret-like reason is forbidden$"
    ):
        ApprovalService(repository).record(
            plan.id,
            "alice",
            "approved",
            f"credential supplied: {synthetic_value}",
            now=NOW,
        )

    approval_path = (
        mvp_root / "governance" / "approvals" / f"approval-{plan.id}.json"
    )
    assert not approval_path.exists()
    assert all(
        synthetic_value.encode() not in path.read_bytes()
        for path in (mvp_root / "governance").rglob("*")
        if path.is_file()
    )


def test_record_rejects_expired_plan(mvp_root: Path) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(seconds=1))

    with pytest.raises(StalePlan, match=r"^approval: plan expired$"):
        ApprovalService(repository).record(
            plan.id,
            "alice",
            "approved",
            "reviewed typed diff",
            now=NOW + timedelta(seconds=1),
        )


def test_approve_reject_race_has_exactly_one_success(mvp_root: Path) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))
    service = ApprovalService(repository)

    def record(decision: str) -> str:
        try:
            service.record(
                plan.id,
                decision,
                decision,  # type: ignore[arg-type]
                "concurrent review",
                now=NOW,
            )
        except PolicyDenied:
            return "conflict"
        return "success"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(record, ("approved", "rejected")))

    assert sorted(results) == ["conflict", "success"]
    assert len(list((mvp_root / "governance" / "approvals").glob("approval-*.json"))) == 1


def test_approval_short_write_failure_leaves_no_final_and_is_retryable(
    mvp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))
    service = ApprovalService(repository)
    directory = mvp_root / "governance" / "approvals"
    final_path = directory / f"approval-{plan.id}.json"
    real_write = os.write
    calls = 0

    def short_then_fail(descriptor: int, payload: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, payload[: max(1, len(payload) // 2)])
        raise OSError

    with monkeypatch.context() as context:
        context.setattr(repository_module.os, "write", short_then_fail)
        with pytest.raises(PolicyDenied, match=r"^approval: persistence failed$"):
            service.record(plan.id, "alice", "approved", "reviewed", now=NOW)

    assert not final_path.exists()
    assert not tuple(directory.iterdir())
    assert service.record(plan.id, "alice", "approved", "reviewed", now=NOW)


@pytest.mark.parametrize("failure_stage", ["fsync", "claim"])
def test_approval_preclaim_failure_leaves_no_final_and_is_retryable(
    mvp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))
    service = ApprovalService(repository)
    directory = mvp_root / "governance" / "approvals"
    final_path = directory / f"approval-{plan.id}.json"

    with monkeypatch.context() as context:
        if failure_stage == "fsync":
            context.setattr(
                repository_module.os, "fsync", lambda _: (_ for _ in ()).throw(OSError())
            )
        else:
            context.setattr(
                repository_module.os,
                "link",
                lambda *args, **kwargs: (_ for _ in ()).throw(OSError()),
            )
        with pytest.raises(PolicyDenied, match=r"^approval: persistence failed$"):
            service.record(plan.id, "alice", "approved", "reviewed", now=NOW)

    assert not final_path.exists()
    assert not tuple(directory.iterdir())
    assert service.record(plan.id, "alice", "approved", "reviewed", now=NOW)


def test_record_rejects_tampered_plan_without_raw_or_path_leak(mvp_root: Path) -> None:
    repository = _repository(mvp_root)
    plan = _create_plan(repository, expires_in=timedelta(minutes=30))
    plan_path = mvp_root / "governance" / "plans" / f"{plan.id}.json"
    raw = plan_path.read_text(encoding="utf-8").replace("asset-canary", "TOP_SECRET_VALUE")
    plan_path.write_text(raw, encoding="utf-8")

    with pytest.raises(StalePlan, match=r"^plan: invalid stored record$") as caught:
        ApprovalService(repository).record(plan.id, "alice", "approved", "reviewed", now=NOW)

    assert "TOP_SECRET_VALUE" not in str(caught.value)
    assert str(mvp_root) not in str(caught.value)

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from skillctl.canonical import canonical_digest
from skillctl.errors import GovernanceValidationError, StalePlan
from skillctl.models import AdapterPlanEvidence
from skillctl.planner import PlanService, calculate_changes, desired_assets, plan_digest
from skillctl.repository import DocumentRepository
import skillctl.repository as repository_module


EXPECTED_ROOT = Path(__file__).parents[1] / "expected"


def _repository(mvp_root: Path) -> DocumentRepository:
    governance_root = mvp_root / "governance"
    return DocumentRepository(governance_root, governance_root)


def _fixture(name: str) -> object:
    return json.loads((EXPECTED_ROOT / name).read_text(encoding="utf-8"))


def test_desired_assets_uses_matching_profile_and_approved_memberships(
    mvp_root: Path,
) -> None:
    snapshot = _repository(mvp_root).load_snapshot()

    assert tuple(asset.id for asset in desired_assets(snapshot, "target-local-b")) == (
        "asset-canary",
    )


def test_desired_assets_rejects_non_mvp_selector(mvp_root: Path) -> None:
    snapshot = _repository(mvp_root).load_snapshot()
    invalid_profile = snapshot.profiles[0].model_copy(
        update={"selector": {"target_ids": ["target-local-a"], "tags": ["local"]}}
    )

    with pytest.raises(GovernanceValidationError, match=r"^planner: invalid selector$"):
        desired_assets(
            snapshot.model_copy(update={"profiles": (invalid_profile,)}), "target-local-a"
        )


@pytest.mark.parametrize("lifecycle", ["quarantined", "deferred"])
def test_desired_assets_never_contains_isolated_assets(mvp_root: Path, lifecycle: str) -> None:
    snapshot = _repository(mvp_root).load_snapshot()
    isolated = snapshot.assets[0].model_copy(update={"lifecycle": lifecycle})
    snapshot = snapshot.model_copy(update={"assets": (isolated,)})

    assert desired_assets(snapshot, "target-local-a") == ()


def test_calculate_changes_matches_create_fixture(mvp_root: Path) -> None:
    snapshot = _repository(mvp_root).load_snapshot()
    changes = calculate_changes(desired_assets(snapshot, "target-local-a"), ())

    assert [change.model_dump(mode="json") for change in changes] == _fixture("plan-create.json")


def test_calculate_changes_matches_update_fixture(mvp_root: Path) -> None:
    snapshot = _repository(mvp_root).load_snapshot()
    observation = snapshot.observations[0].model_copy(
        update={"revision": "revision-old", "checksum": "sha256:old"}
    )
    changes = calculate_changes(desired_assets(snapshot, "target-local-a"), (observation,))

    assert [change.model_dump(mode="json") for change in changes] == _fixture("plan-update.json")


def test_calculate_changes_returns_noop_for_matching_revision_and_checksum(
    mvp_root: Path,
) -> None:
    snapshot = _repository(mvp_root).load_snapshot()

    assert (
        calculate_changes(desired_assets(snapshot, "target-local-a"), snapshot.observations) == ()
    )


def test_plan_service_persists_a_recomputable_seven_digest_plan(
    mvp_root: Path,
) -> None:
    repository = _repository(mvp_root)
    snapshot = repository.load_snapshot()
    changes = calculate_changes(desired_assets(snapshot, "target-local-b"), ())
    paths = ("/private/tmp/skill-governance-target-b",)
    evidence = AdapterPlanEvidence(
        adapter_id="filesystem",
        target_id="target-local-b",
        changes_digest=canonical_digest(changes),
        resolved_target_paths=paths,
        evidence_refs=(),
        raw_evidence_digest=canonical_digest({"dry_run": "ok"}),
    )
    service = PlanService(repository)
    now = datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc)

    plan = service.create(
        "target-local-b",
        adapter_evidence=evidence,
        now=now,
        expires_in=timedelta(minutes=30),
    )

    assert plan.id.startswith("plan-") and len(plan.id) == len("plan-") + 32
    assert plan.expires_at == now + timedelta(minutes=30)
    assert plan.plan_digest == plan_digest(plan)
    assert all(
        digest.startswith("sha256:")
        for digest in (
            plan.source_state_digest,
            plan.desired_state_digest,
            plan.observed_state_digest,
            plan.adapter_manifest_digest,
            plan.adapter_evidence_digest,
            plan.runtime_target_paths_digest,
            plan.plan_digest,
        )
    )
    assert service.get(plan.id) == plan


@pytest.mark.parametrize("mismatch", ["target", "changes", "paths"])
def test_plan_service_rejects_adapter_evidence_not_bound_to_this_plan(
    mvp_root: Path, mismatch: str
) -> None:
    repository = _repository(mvp_root)
    snapshot = repository.load_snapshot()
    changes = calculate_changes(desired_assets(snapshot, "target-local-a"), snapshot.observations)
    evidence = AdapterPlanEvidence(
        adapter_id="filesystem",
        target_id="target-local-a",
        changes_digest=canonical_digest(changes),
        resolved_target_paths=("/private/tmp/skill-governance-target-a",),
        evidence_refs=(),
        raw_evidence_digest=canonical_digest({"dry_run": "ok"}),
    )
    if mismatch == "target":
        evidence = evidence.model_copy(update={"target_id": "target-local-b"})
    elif mismatch == "changes":
        evidence = evidence.model_copy(update={"changes_digest": canonical_digest({"wrong": True})})
    else:
        evidence = evidence.model_copy(
            update={"resolved_target_paths": ("/private/tmp/not-the-target",)}
        )

    with pytest.raises(GovernanceValidationError, match=r"^plan: adapter evidence mismatch$"):
        PlanService(repository).create(
            "target-local-a",
            adapter_evidence=evidence,
            now=datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc),
            expires_in=timedelta(minutes=30),
        )


def test_plan_service_exclusive_create_never_overwrites_existing_plan(
    mvp_root: Path,
) -> None:
    repository = _repository(mvp_root)
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
    plan_id = "plan-" + "a" * 32
    service = PlanService(repository, id_factory=lambda: plan_id)
    arguments = {
        "adapter_evidence": evidence,
        "now": datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc),
        "expires_in": timedelta(minutes=30),
    }
    service.create("target-local-b", **arguments)  # type: ignore[arg-type]
    path = mvp_root / "governance" / "plans" / f"{plan_id}.json"
    before = path.read_bytes()

    with pytest.raises(
        GovernanceValidationError,
        match=r"^plan: immutable record already exists$",
    ):
        service.create("target-local-b", **arguments)  # type: ignore[arg-type]

    assert path.read_bytes() == before


def test_plan_short_write_failure_leaves_no_final_and_is_retryable(
    mvp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(mvp_root)
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
    plan_id = "plan-" + "b" * 32
    service = PlanService(repository, id_factory=lambda: plan_id)
    directory = mvp_root / "governance" / "plans"
    final_path = directory / f"{plan_id}.json"
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
        with pytest.raises(GovernanceValidationError, match=r"^plan: persistence failed$"):
            service.create(
                "target-local-b",
                adapter_evidence=evidence,
                now=datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc),
                expires_in=timedelta(minutes=30),
            )

    assert not final_path.exists()
    assert not tuple(directory.iterdir())
    assert service.create(
        "target-local-b",
        adapter_evidence=evidence,
        now=datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc),
        expires_in=timedelta(minutes=30),
    )


def test_plan_reader_rejects_tampering_without_leaking_raw_or_path(
    mvp_root: Path,
) -> None:
    repository = _repository(mvp_root)
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
    service = PlanService(repository)
    plan = service.create(
        "target-local-b",
        adapter_evidence=evidence,
        now=datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc),
        expires_in=timedelta(minutes=30),
    )
    path = mvp_root / "governance" / "plans" / f"{plan.id}.json"
    raw = path.read_text(encoding="utf-8").replace("asset-canary", "TOP_SECRET_VALUE")
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(StalePlan, match=r"^plan: invalid stored record$") as caught:
        service.get(plan.id)

    assert "TOP_SECRET_VALUE" not in str(caught.value)
    assert str(mvp_root) not in str(caught.value)

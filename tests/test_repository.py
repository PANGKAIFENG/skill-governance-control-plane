from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from skillctl import errors
from skillctl.canonical import canonical_digest
from skillctl.models import AdapterPlanEvidence, Approval
from skillctl.planner import PlanService, calculate_changes, desired_assets
from skillctl.repository import DocumentRepository


def _load_yaml(path: Path) -> dict[str, object]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _write_yaml(path: Path, payload: dict[str, object]) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_list_plans_returns_verified_records_in_stable_id_order(mvp_root: Path) -> None:
    root = mvp_root / "governance"
    repository = DocumentRepository(root, root)
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
    ids = iter(("plan-" + "b" * 32, "plan-" + "a" * 32))
    planner = PlanService(repository, id_factory=lambda: next(ids))
    now = datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc)
    second = planner.create(
        "target-local-b",
        adapter_evidence=evidence,
        now=now,
        expires_in=timedelta(minutes=30),
    )
    first = planner.create(
        "target-local-b",
        adapter_evidence=evidence,
        now=now,
        expires_in=timedelta(minutes=30),
    )

    before = tuple(sorted(path.read_bytes() for path in (root / "plans").iterdir()))

    assert repository.list_plans() == (first, second)
    assert tuple(sorted(path.read_bytes() for path in (root / "plans").iterdir())) == before


def test_loads_mvp_snapshot(mvp_root: Path) -> None:
    governance_root = mvp_root / "governance"

    snapshot = DocumentRepository(governance_root, governance_root).load_snapshot()

    assert tuple(asset.id for asset in snapshot.assets) == ("asset-canary",)
    assert tuple(target.id for target in snapshot.targets) == (
        "target-local-a",
        "target-local-b",
    )
    assert tuple(profile.id for profile in snapshot.profiles) == ("profile-default",)
    assert tuple(item.id for item in snapshot.memberships) == (
        "membership-canary-default",
    )
    assert tuple(item.id for item in snapshot.bindings) == ("binding-canary-local-a",)
    assert tuple(item.id for item in snapshot.observations) == (
        "observation-canary-local-a",
    )


def test_rejects_unknown_field_without_leaking_raw_value(mvp_root: Path) -> None:
    assets_path = mvp_root / "governance" / "assets.yaml"
    payload = _load_yaml(assets_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["unknown_field"] = "TOP_SECRET_VALUE"
    _write_yaml(assets_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^assets: invalid document$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert "TOP_SECRET_VALUE" not in str(caught.value)
    assert str(mvp_root) not in str(caught.value)


def test_rejects_missing_document_without_leaking_absolute_path(
    mvp_root: Path,
) -> None:
    (mvp_root / "governance" / "targets.yaml").unlink()

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^targets: invalid document$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert str(mvp_root) not in str(caught.value)


def test_rejects_malformed_yaml_without_leaking_raw_value(mvp_root: Path) -> None:
    assets_path = mvp_root / "governance" / "assets.yaml"
    assets_path.write_text("items:\n  - id: [TOP_SECRET_VALUE\n", encoding="utf-8")

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^assets: invalid document$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert "TOP_SECRET_VALUE" not in str(caught.value)
    assert str(mvp_root) not in str(caught.value)


def test_rejects_duplicate_asset_ids(mvp_root: Path) -> None:
    assets_path = mvp_root / "governance" / "assets.yaml"
    payload = _load_yaml(assets_path)
    items = payload["items"]
    assert isinstance(items, list)
    items.append(dict(items[0]))
    _write_yaml(assets_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^assets: duplicate id asset-canary$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert str(mvp_root) not in str(caught.value)


def test_rejects_dangling_membership_asset(mvp_root: Path) -> None:
    memberships_path = mvp_root / "governance" / "profile-memberships.yaml"
    payload = _load_yaml(memberships_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["asset_id"] = "asset-missing"
    _write_yaml(memberships_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^profile-memberships: unknown asset asset-missing$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert str(mvp_root) not in str(caught.value)


def test_rejects_dangling_membership_profile(mvp_root: Path) -> None:
    memberships_path = mvp_root / "governance" / "profile-memberships.yaml"
    payload = _load_yaml(memberships_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["profile_id"] = "profile-missing"
    _write_yaml(memberships_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^profile-memberships: unknown profile profile-missing$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert str(mvp_root) not in str(caught.value)


def test_rejects_dangling_binding_target(mvp_root: Path) -> None:
    bindings_path = mvp_root / "governance" / "consumer-bindings.yaml"
    payload = _load_yaml(bindings_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["target_id"] = "target-missing"
    _write_yaml(bindings_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^consumer-bindings: unknown target target-missing$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert str(mvp_root) not in str(caught.value)


def test_rejects_dangling_binding_asset(mvp_root: Path) -> None:
    bindings_path = mvp_root / "governance" / "consumer-bindings.yaml"
    payload = _load_yaml(bindings_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["asset_id"] = "asset-missing"
    _write_yaml(bindings_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^consumer-bindings: unknown asset asset-missing$",
    ):
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()


def test_rejects_dangling_observation_asset(mvp_root: Path) -> None:
    observations_path = mvp_root / "governance" / "observed-states.yaml"
    payload = _load_yaml(observations_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["asset_id"] = "asset-missing"
    _write_yaml(observations_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^observed-states: unknown asset asset-missing$",
    ):
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()


def test_rejects_dangling_observation_target(mvp_root: Path) -> None:
    observations_path = mvp_root / "governance" / "observed-states.yaml"
    payload = _load_yaml(observations_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["target_id"] = "target-missing"
    _write_yaml(observations_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^observed-states: unknown target target-missing$",
    ):
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()


def test_rejects_blank_consumer_id(mvp_root: Path) -> None:
    bindings_path = mvp_root / "governance" / "consumer-bindings.yaml"
    payload = _load_yaml(bindings_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["consumer_id"] = "  "
    _write_yaml(bindings_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^consumer-bindings: blank consumer id binding-canary-local-a$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert str(mvp_root) not in str(caught.value)


@pytest.mark.parametrize("lifecycle", ["quarantined", "deferred"])
def test_excludes_quarantined_and_deferred_from_relationships(
    mvp_root: Path, lifecycle: str
) -> None:
    assets_path = mvp_root / "governance" / "assets.yaml"
    payload = _load_yaml(assets_path)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["lifecycle"] = lifecycle
    _write_yaml(assets_path, payload)

    with pytest.raises(
        errors.GovernanceValidationError,
        match=r"^profile-memberships: disallowed asset asset-canary$",
    ) as caught:
        DocumentRepository(
            mvp_root / "governance", mvp_root / "governance"
        ).load_snapshot()

    assert str(mvp_root) not in str(caught.value)


def test_get_approval_returns_none_or_verified_terminal_record(mvp_root: Path) -> None:
    root = mvp_root / "governance"
    repository = DocumentRepository(root, root)
    plan_id = "plan-" + "a" * 32

    assert repository.get_approval(plan_id) is None

    approval = Approval(
        id=f"approval-{plan_id}",
        plan_id=plan_id,
        plan_digest="sha256:" + "b" * 64,
        decision="approved",
        approver="reviewer",
        reason="reviewed",
        decided_at="2026-07-13T01:00:00Z",
    )
    repository.create_approval(approval)

    assert repository.get_approval(plan_id) == approval


def test_get_approval_rejects_tampered_record_without_path_leak(mvp_root: Path) -> None:
    root = mvp_root / "governance"
    repository = DocumentRepository(root, root)
    plan_id = "plan-" + "a" * 32
    approval = Approval(
        id=f"approval-{plan_id}",
        plan_id=plan_id,
        plan_digest="sha256:" + "b" * 64,
        decision="approved",
        approver="reviewer",
        reason="reviewed",
        decided_at="2026-07-13T01:00:00Z",
    )
    repository.create_approval(approval)
    path = root / "approvals" / f"approval-{plan_id}.json"
    path.write_text(path.read_text().replace(plan_id, "TOP_SECRET_VALUE"))

    with pytest.raises(
        errors.StateCorruption, match=r"^approval: invalid stored record$"
    ) as caught:
        repository.get_approval(plan_id)

    assert "TOP_SECRET_VALUE" not in str(caught.value)
    assert str(mvp_root) not in str(caught.value)

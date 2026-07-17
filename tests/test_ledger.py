from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from skillctl.canonical import canonical_digest, canonical_json
from skillctl.errors import LedgerCorruption
from skillctl.ledger import DeploymentLedger
from skillctl.models import DeploymentLedgerEntry


NOW = datetime(2026, 7, 13, 1, 0, tzinfo=timezone.utc)


def _entry(deployment_id: str) -> DeploymentLedgerEntry:
    return DeploymentLedgerEntry(
        schema_version="1.0",
        deployment_id=deployment_id,
        plan_id="plan-" + "a" * 32,
        parent_deployment_id=None,
        target_id="target-local-a",
        asset_ids=("asset-canary",),
        source_revisions={"asset-canary": "revision-canary-1"},
        change_types=("update",),
        approval_ref="approval-plan-" + "a" * 32,
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        result="succeeded",
        evidence_refs=(),
        previous_entry_hash=None,
        entry_hash="",
    )


def test_append_writes_canonical_hash_chain_and_preserves_existing_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "deployment-ledger.jsonl"
    ledger = DeploymentLedger(path)
    ledger.append(_entry("deployment-a"))
    before = path.read_bytes()

    ledger.append(_entry("deployment-b"))

    raw = path.read_bytes()
    entries = ledger.read_all()
    assert raw.startswith(before)
    assert len(raw.splitlines()) == 2
    assert raw.splitlines()[1] == canonical_json(entries[1].model_dump(mode="json"))
    assert entries[1].previous_entry_hash == entries[0].entry_hash
    assert entries[1].entry_hash == canonical_digest(
        entries[1].model_dump(mode="json", exclude={"entry_hash"})
    )


def test_append_rejects_duplicate_deployment_id(tmp_path: Path) -> None:
    ledger = DeploymentLedger(tmp_path / "deployment-ledger.jsonl")
    ledger.append(_entry("deployment-a"))

    with pytest.raises(LedgerCorruption, match=r"^ledger: duplicate deployment id$"):
        ledger.append(_entry("deployment-a"))


@pytest.mark.parametrize(
    "raw",
    [b'{"deployment_id":', b'{"deployment_id":"TOP_SECRET_VALUE"}\n'],
)
def test_read_all_fails_closed_on_truncated_or_invalid_entry(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "deployment-ledger.jsonl"
    path.write_bytes(raw)

    with pytest.raises(LedgerCorruption, match=r"^ledger: invalid entry chain$") as caught:
        DeploymentLedger(path).read_all()

    assert "TOP_SECRET_VALUE" not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


def test_read_all_detects_hash_chain_tampering_without_raw_leak(tmp_path: Path) -> None:
    path = tmp_path / "deployment-ledger.jsonl"
    ledger = DeploymentLedger(path)
    ledger.append(_entry("deployment-a"))
    ledger.append(_entry("deployment-b"))
    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["result"] = "TOP_SECRET_VALUE"
    path.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n" + lines[1] + "\n",
        encoding="utf-8",
    )

    with pytest.raises(LedgerCorruption, match=r"^ledger: invalid entry chain$") as caught:
        ledger.read_all()

    assert "TOP_SECRET_VALUE" not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


def test_concurrent_append_serializes_hash_updates(tmp_path: Path) -> None:
    path = tmp_path / "deployment-ledger.jsonl"

    def append(deployment_id: str) -> None:
        DeploymentLedger(path).append(_entry(deployment_id))

    with ThreadPoolExecutor(max_workers=2) as executor:
        tuple(executor.map(append, ("deployment-a", "deployment-b")))

    entries = DeploymentLedger(path).read_all()
    assert {entry.deployment_id for entry in entries} == {
        "deployment-a",
        "deployment-b",
    }
    assert entries[1].previous_entry_hash == entries[0].entry_hash

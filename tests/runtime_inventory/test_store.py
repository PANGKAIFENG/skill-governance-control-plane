from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skillctl.canonical import canonical_digest
from skillctl.runtime_inventory.models import RuntimeInventorySnapshot
from skillctl.runtime_inventory.store import (
    RuntimeInventoryStore,
    RuntimeInventoryStoreError,
)


def _snapshot(*, version: str = "v0.19.22") -> RuntimeInventorySnapshot:
    return RuntimeInventorySnapshot(
        generated_at=datetime(2026, 7, 17, 8, 0, tzinfo=UTC),
        skillshare_version=version,
        source_path="/runtime/shared",
        targets=(),
        assets=(),
    )


def test_save_and_read_round_trip_with_canonical_digest(tmp_path: Path) -> None:
    store = RuntimeInventoryStore(tmp_path)

    saved = store.save(_snapshot())
    result = store.read()

    assert saved.snapshot_digest == canonical_digest(
        saved.model_dump(mode="json", exclude={"snapshot_digest"})
    )
    assert (tmp_path / "runtime-inventory" / "snapshot.json").is_file()
    assert result.available is True
    assert result.snapshot == saved
    assert result.stale is False
    assert result.error_code is None


def test_read_accepts_different_json_field_order_under_canonical_rules(
    tmp_path: Path,
) -> None:
    store = RuntimeInventoryStore(tmp_path)
    saved = store.save(_snapshot())
    path = tmp_path / "runtime-inventory" / "snapshot.json"
    payload = saved.model_dump(mode="json")
    reordered = dict(reversed(tuple(payload.items())))
    path.write_text(json.dumps(reordered, separators=(",", ":")), encoding="utf-8")

    result = store.read()

    assert result.available is True
    assert result.snapshot == saved


@pytest.mark.parametrize("corruption", ("tampered", "malformed", "extra"))
def test_read_rejects_corrupt_or_non_strict_snapshot(
    tmp_path: Path,
    corruption: str,
) -> None:
    store = RuntimeInventoryStore(tmp_path)
    saved = store.save(_snapshot())
    path = tmp_path / "runtime-inventory" / "snapshot.json"
    payload = saved.model_dump(mode="json")
    if corruption == "tampered":
        payload["skillshare_version"] = "v9.9.9"
        path.write_text(json.dumps(payload), encoding="utf-8")
    elif corruption == "malformed":
        path.write_bytes(b'{"generated_at":')
    else:
        payload["unexpected"] = "must be rejected"
        payload["snapshot_digest"] = canonical_digest(
            {key: value for key, value in payload.items() if key != "snapshot_digest"}
        )
        path.write_text(json.dumps(payload), encoding="utf-8")

    result = store.read()

    assert result.available is False
    assert result.snapshot is None
    assert result.stale is False
    assert result.error_code == "invalid_snapshot"


def test_read_without_snapshot_is_explicitly_unavailable(tmp_path: Path) -> None:
    result = RuntimeInventoryStore(tmp_path).read()

    assert result.available is False
    assert result.snapshot is None
    assert result.stale is False
    assert result.error_code == "unavailable"


def test_save_and_read_reject_existing_snapshot_symlink(tmp_path: Path) -> None:
    directory = tmp_path / "runtime-inventory"
    directory.mkdir()
    target = tmp_path / "outside.json"
    target.write_text("outside remains unchanged", encoding="utf-8")
    (directory / "snapshot.json").symlink_to(target)
    store = RuntimeInventoryStore(tmp_path)

    with pytest.raises(RuntimeInventoryStoreError, match=r"^persistence_failed$"):
        store.save(_snapshot())

    assert target.read_text(encoding="utf-8") == "outside remains unchanged"
    result = store.read()
    assert result.available is False
    assert result.error_code == "invalid_snapshot"


@pytest.mark.parametrize("directory_kind", ("symlink", "file"))
def test_rejects_runtime_inventory_directory_that_is_not_a_real_directory(
    tmp_path: Path,
    directory_kind: str,
) -> None:
    directory = tmp_path / "runtime-inventory"
    if directory_kind == "symlink":
        outside = tmp_path / "outside"
        outside.mkdir()
        directory.symlink_to(outside, target_is_directory=True)
    else:
        directory.write_text("not a directory", encoding="utf-8")
    store = RuntimeInventoryStore(tmp_path)

    with pytest.raises(RuntimeInventoryStoreError, match=r"^persistence_failed$"):
        store.save(_snapshot())

    result = store.read()
    assert result.available is False
    assert result.error_code == "invalid_snapshot"


def test_read_rejects_snapshot_larger_than_limit(tmp_path: Path) -> None:
    RuntimeInventoryStore(tmp_path).save(_snapshot())

    result = RuntimeInventoryStore(tmp_path, max_snapshot_bytes=64).read()

    assert result.available is False
    assert result.error_code == "invalid_snapshot"


def test_save_retries_partial_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_write = os.write

    def partial_write(file_descriptor: int, data: bytes) -> int:
        return real_write(file_descriptor, data[: max(1, len(data) // 3)])

    monkeypatch.setattr(os, "write", partial_write)
    store = RuntimeInventoryStore(tmp_path)

    saved = store.save(_snapshot())

    assert store.read().snapshot == saved


@pytest.mark.parametrize("failure_point", ("write", "file_fsync", "replace"))
def test_save_failure_preserves_old_bytes_and_cleans_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    store = RuntimeInventoryStore(tmp_path)
    store.save(_snapshot(version="v1.0.0"))
    path = tmp_path / "runtime-inventory" / "snapshot.json"
    old_bytes = path.read_bytes()

    if failure_point == "write":
        monkeypatch.setattr(os, "write", lambda *_args: (_ for _ in ()).throw(OSError()))
    elif failure_point == "file_fsync":
        monkeypatch.setattr(os, "fsync", lambda *_args: (_ for _ in ()).throw(OSError()))
    else:
        monkeypatch.setattr(os, "replace", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))

    with pytest.raises(RuntimeInventoryStoreError, match=r"^persistence_failed$"):
        store.save(_snapshot(version="v2.0.0"))

    assert path.read_bytes() == old_bytes
    assert list(path.parent.glob(".snapshot.json.*.tmp")) == []


def test_parent_fsync_failure_leaves_a_complete_valid_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RuntimeInventoryStore(tmp_path)
    store.save(_snapshot(version="v1.0.0"))
    real_fsync = os.fsync
    calls = 0

    def fail_parent_fsync(file_descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError()
        real_fsync(file_descriptor)

    monkeypatch.setattr(os, "fsync", fail_parent_fsync)

    with pytest.raises(RuntimeInventoryStoreError, match=r"^persistence_failed$"):
        store.save(_snapshot(version="v2.0.0"))

    result = store.read()
    assert result.available is True
    assert result.snapshot is not None
    assert result.snapshot.skillshare_version == "v2.0.0"
    assert list((tmp_path / "runtime-inventory").glob(".snapshot.json.*.tmp")) == []

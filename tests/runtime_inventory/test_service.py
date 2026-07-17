from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skillctl.runtime_inventory import (
    RuntimeInventoryService,
    RuntimeInventorySnapshot,
    RuntimeInventoryStore,
)


def _snapshot(*, version: str) -> RuntimeInventorySnapshot:
    return RuntimeInventorySnapshot(
        generated_at=datetime(2026, 7, 17, 8, 0, tzinfo=UTC),
        skillshare_version=version,
        source_path="/runtime/shared",
        targets=(),
        assets=(),
    )


class StaticDiscovery:
    def __init__(
        self,
        snapshot: RuntimeInventorySnapshot,
        events: list[str] | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.events = events
        self.calls = 0

    def discover(self) -> RuntimeInventorySnapshot:
        self.calls += 1
        if self.events is not None:
            self.events.append("discover")
        return self.snapshot


class FailingDiscovery:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events

    def discover(self) -> RuntimeInventorySnapshot:
        if self.events is not None:
            self.events.append("discover")
        raise RuntimeError("credential=must-not-leak")


class RecordingStore(RuntimeInventoryStore):
    def __init__(self, state_root: Path, events: list[str]) -> None:
        super().__init__(state_root)
        self.events = events

    def save(self, snapshot: RuntimeInventorySnapshot) -> RuntimeInventorySnapshot:
        self.events.append("save")
        return super().save(snapshot)


def test_read_without_snapshot_returns_unavailable(tmp_path: Path) -> None:
    service = RuntimeInventoryService(
        StaticDiscovery(_snapshot(version="v1.0.0")),
        RuntimeInventoryStore(tmp_path),
    )

    result = service.read()

    assert result.available is False
    assert result.snapshot is None
    assert result.stale is False
    assert result.error_code == "unavailable"


def test_successful_refresh_discovers_then_saves_and_returns_new_snapshot(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    discovery = StaticDiscovery(_snapshot(version="v2.0.0"), events)
    store = RecordingStore(tmp_path, events)
    service = RuntimeInventoryService(discovery, store)

    result = service.refresh()

    assert events == ["discover", "save"]
    assert discovery.calls == 1
    assert result.success is True
    assert result.error_code is None
    assert result.snapshot is not None
    assert result.snapshot.skillshare_version == "v2.0.0"
    assert result.snapshot.snapshot_digest is not None
    read = service.read()
    assert read.available is True
    assert read.snapshot == result.snapshot
    assert read.stale is False
    assert read.error_code is None


def test_discovery_failure_preserves_old_snapshot_and_returns_sanitized_status(
    tmp_path: Path,
) -> None:
    store = RuntimeInventoryStore(tmp_path)
    old = store.save(_snapshot(version="v1.0.0"))
    path = tmp_path / "runtime-inventory" / "snapshot.json"
    old_bytes = path.read_bytes()
    service = RuntimeInventoryService(FailingDiscovery(), store)

    result = service.refresh()

    assert result.success is False
    assert result.snapshot is None
    assert result.error_code == "discovery_failed"
    assert "credential" not in result.model_dump_json()
    assert path.read_bytes() == old_bytes
    read = service.read()
    assert read.available is True
    assert read.snapshot == old
    assert read.stale is True
    assert read.error_code == "discovery_failed"


def test_save_failure_preserves_old_snapshot_and_returns_sanitized_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RuntimeInventoryStore(tmp_path)
    old = store.save(_snapshot(version="v1.0.0"))
    path = tmp_path / "runtime-inventory" / "snapshot.json"
    old_bytes = path.read_bytes()
    service = RuntimeInventoryService(
        StaticDiscovery(_snapshot(version="v2.0.0")),
        store,
    )
    monkeypatch.setattr(
        os,
        "replace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("token=must-not-leak")
        ),
    )

    result = service.refresh()

    assert result.success is False
    assert result.snapshot is None
    assert result.error_code == "persistence_failed"
    assert "token" not in result.model_dump_json()
    assert path.read_bytes() == old_bytes
    assert list(path.parent.glob(".snapshot.json.*.tmp")) == []
    read = service.read()
    assert read.available is True
    assert read.snapshot == old
    assert read.stale is True
    assert read.error_code == "persistence_failed"

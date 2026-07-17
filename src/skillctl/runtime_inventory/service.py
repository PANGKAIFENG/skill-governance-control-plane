from __future__ import annotations

from typing import Protocol

from skillctl.runtime_inventory.models import (
    RuntimeInventoryErrorCode,
    RuntimeInventoryReadResult,
    RuntimeInventoryRefreshResult,
    RuntimeInventorySnapshot,
)


class RuntimeInventoryDiscovery(Protocol):
    def discover(self) -> RuntimeInventorySnapshot: ...


class RuntimeInventorySnapshotStore(Protocol):
    def save(self, snapshot: RuntimeInventorySnapshot) -> RuntimeInventorySnapshot: ...

    def read(self) -> RuntimeInventoryReadResult: ...


class RuntimeInventoryService:
    def __init__(
        self,
        discovery: RuntimeInventoryDiscovery,
        store: RuntimeInventorySnapshotStore,
    ) -> None:
        self._discovery = discovery
        self._store = store
        self._last_refresh_error: RuntimeInventoryErrorCode | None = None

    def refresh(self) -> RuntimeInventoryRefreshResult:
        try:
            snapshot = self._discovery.discover()
        except Exception:
            self._last_refresh_error = "discovery_failed"
            return RuntimeInventoryRefreshResult(
                success=False,
                snapshot=None,
                error_code="discovery_failed",
            )
        try:
            stored = self._store.save(snapshot)
        except Exception:
            self._last_refresh_error = "persistence_failed"
            return RuntimeInventoryRefreshResult(
                success=False,
                snapshot=None,
                error_code="persistence_failed",
            )
        self._last_refresh_error = None
        return RuntimeInventoryRefreshResult(
            success=True,
            snapshot=stored,
        )

    def read(self) -> RuntimeInventoryReadResult:
        try:
            result = self._store.read()
        except Exception:
            return RuntimeInventoryReadResult(
                available=False,
                snapshot=None,
                error_code="invalid_snapshot",
            )
        if result.available and self._last_refresh_error is not None:
            return RuntimeInventoryReadResult(
                available=True,
                snapshot=result.snapshot,
                stale=True,
                error_code=self._last_refresh_error,
            )
        return result

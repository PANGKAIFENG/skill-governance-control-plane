from __future__ import annotations

from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import Field, model_validator

from skillctl.models import StrictModel


RuntimeSkillStatus: TypeAlias = Literal[
    "consistent", "diverged", "missing", "local_only", "scan_warning"
]
RuntimeLocationKind: TypeAlias = Literal["shared", "target"]
RuntimeInventoryErrorCode: TypeAlias = Literal[
    "unavailable",
    "invalid_snapshot",
    "discovery_failed",
    "persistence_failed",
]


class ScanLimits(StrictModel):
    max_files: int = Field(default=512, ge=1, le=512)
    max_file_bytes: int = Field(default=1024 * 1024, ge=1, le=1024 * 1024)
    max_total_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)


class RuntimeTarget(StrictModel):
    name: str
    path: str
    mode: str
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    readable: bool = True


class RuntimeSkillInstance(StrictModel):
    location_kind: RuntimeLocationKind
    target_name: str | None
    path: str
    distribution_mode: str
    digest: str | None
    is_symlink: bool
    readable: bool
    scan_warnings: tuple[str, ...] = ()


class RuntimeIgnoredSkill(StrictModel):
    name: str
    path: str
    reason: str


class RuntimeSkillAsset(StrictModel):
    key: str
    name: str
    description: str | None
    status: RuntimeSkillStatus
    source_instance: RuntimeSkillInstance | None
    target_instances: tuple[RuntimeSkillInstance, ...] = ()
    missing_targets: tuple[str, ...] = ()

    def target(self, name: str) -> RuntimeSkillInstance:
        for instance in self.target_instances:
            if instance.target_name == name:
                return instance
        raise KeyError(name)


class RuntimeInventorySnapshot(StrictModel):
    generated_at: datetime
    skillshare_version: str
    source_path: str
    targets: tuple[RuntimeTarget, ...]
    assets: tuple[RuntimeSkillAsset, ...]
    ignored: tuple[RuntimeIgnoredSkill, ...] = ()
    warnings: tuple[str, ...] = ()
    snapshot_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    def asset(self, name: str) -> RuntimeSkillAsset:
        for asset in self.assets:
            if asset.name == name:
                return asset
        raise KeyError(name)


class RuntimeInventoryReadResult(StrictModel):
    available: bool
    snapshot: RuntimeInventorySnapshot | None
    stale: bool = False
    error_code: RuntimeInventoryErrorCode | None = None

    @model_validator(mode="after")
    def validate_result_state(self) -> "RuntimeInventoryReadResult":
        refresh_errors = {"discovery_failed", "persistence_failed"}
        if self.available:
            if self.snapshot is None:
                raise ValueError("available inventory result requires a snapshot")
            if self.stale != (self.error_code in refresh_errors):
                raise ValueError("available inventory result has inconsistent stale state")
        elif (
            self.snapshot is not None
            or self.stale
            or self.error_code not in {"unavailable", "invalid_snapshot"}
        ):
            raise ValueError("unavailable inventory result has inconsistent state")
        return self


class RuntimeInventoryRefreshResult(StrictModel):
    success: bool
    snapshot: RuntimeInventorySnapshot | None
    error_code: RuntimeInventoryErrorCode | None = None

    @model_validator(mode="after")
    def validate_result_state(self) -> "RuntimeInventoryRefreshResult":
        if self.success:
            if self.snapshot is None or self.error_code is not None:
                raise ValueError("successful inventory refresh requires a snapshot")
        elif (
            self.snapshot is not None
            or self.error_code not in {"discovery_failed", "persistence_failed"}
        ):
            raise ValueError("failed inventory refresh has inconsistent state")
        return self

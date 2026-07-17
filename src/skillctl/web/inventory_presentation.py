from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from skillctl.runtime_inventory.models import (
    RuntimeInventoryReadResult,
    RuntimeInventorySnapshot,
    RuntimeSkillAsset,
    RuntimeSkillInstance,
    RuntimeSkillStatus,
)


_STATUS_LABELS: dict[RuntimeSkillStatus, str] = {
    "consistent": "一致",
    "diverged": "版本不一致",
    "missing": "缺失",
    "local_only": "仅本地",
    "scan_warning": "扫描告警",
}
_STATUS_ORDER: tuple[RuntimeSkillStatus, ...] = (
    "consistent",
    "diverged",
    "missing",
    "local_only",
    "scan_warning",
)


@dataclass(frozen=True)
class InventoryFilters:
    q: str = ""
    status: str = ""
    source: str = ""
    target: str = ""


@dataclass(frozen=True)
class InventoryFilterOption:
    value: str
    label: str


@dataclass(frozen=True)
class InventoryTargetPresentation:
    name: str
    path: str
    mode: str
    readable: bool
    connection_label: str


@dataclass(frozen=True)
class InventoryInstancePresentation:
    location_label: str
    path: str
    distribution_mode: str
    digest_short: str
    readable: bool
    readable_label: str
    is_symlink: bool


@dataclass(frozen=True)
class InventoryAssetPresentation:
    key: str
    name: str
    description: str | None
    status: RuntimeSkillStatus
    status_label: str
    source_label: str
    coverage_label: str
    missing_targets: tuple[str, ...]
    instances: tuple[InventoryInstancePresentation, ...]


@dataclass(frozen=True)
class InventoryIgnoredPresentation:
    name: str
    path: str
    reason: str


@dataclass(frozen=True)
class InventoryPresentation:
    available: bool
    error_label: str | None
    stale: bool
    stale_label: str | None
    generated_at: datetime | None
    skillshare_version: str | None
    source_path: str | None
    unique_skill_count: int
    connected_agent_count: int
    diverged_count: int
    local_only_count: int
    ignored_count: int
    warning_count: int
    warnings: tuple[str, ...]
    targets: tuple[InventoryTargetPresentation, ...]
    assets: tuple[InventoryAssetPresentation, ...]
    ignored: tuple[InventoryIgnoredPresentation, ...]
    filters: InventoryFilters
    status_options: tuple[InventoryFilterOption, ...]
    source_options: tuple[InventoryFilterOption, ...]
    target_options: tuple[InventoryFilterOption, ...]


def build_inventory_presentation(
    result: RuntimeInventoryReadResult,
    filters: InventoryFilters,
) -> InventoryPresentation:
    if not result.available or result.snapshot is None:
        return _unavailable_presentation(result, filters)

    snapshot = result.snapshot
    assets = tuple(
        _asset_presentation(asset, len(snapshot.targets))
        for asset in sorted(
            snapshot.assets,
            key=lambda item: (item.name.casefold(), item.key.casefold()),
        )
        if _matches_filters(asset, snapshot, filters)
    )
    targets = tuple(
        InventoryTargetPresentation(
            name=target.name,
            path=target.path,
            mode=target.mode,
            readable=target.readable,
            connection_label="已连接" if target.readable else "不可用",
        )
        for target in sorted(snapshot.targets, key=lambda item: item.name.casefold())
    )
    ignored = tuple(
        InventoryIgnoredPresentation(
            name=item.name,
            path=item.path,
            reason=item.reason,
        )
        for item in sorted(
            snapshot.ignored,
            key=lambda item: (item.name.casefold(), item.path),
        )
    )
    return InventoryPresentation(
        available=True,
        error_label=None,
        stale=result.stale,
        stale_label="上次重新盘点失败，当前快照可能已陈旧" if result.stale else None,
        generated_at=snapshot.generated_at,
        skillshare_version=snapshot.skillshare_version,
        source_path=snapshot.source_path,
        unique_skill_count=len(snapshot.assets),
        connected_agent_count=sum(target.readable for target in snapshot.targets),
        diverged_count=sum(asset.status == "diverged" for asset in snapshot.assets),
        local_only_count=sum(asset.status == "local_only" for asset in snapshot.assets),
        ignored_count=len(snapshot.ignored),
        warning_count=len(snapshot.warnings),
        warnings=tuple(snapshot.warnings),
        targets=targets,
        assets=assets,
        ignored=ignored,
        filters=filters,
        status_options=_status_options(),
        source_options=_source_options(),
        target_options=tuple(
            InventoryFilterOption(target.name, target.name)
            for target in sorted(snapshot.targets, key=lambda item: item.name.casefold())
        ),
    )


def _unavailable_presentation(
    result: RuntimeInventoryReadResult,
    filters: InventoryFilters,
) -> InventoryPresentation:
    error_label = (
        "盘点快照无法读取，请重新盘点"
        if result.error_code == "invalid_snapshot"
        else "尚无可用的运行态盘点快照"
    )
    return InventoryPresentation(
        available=False,
        error_label=error_label,
        stale=False,
        stale_label=None,
        generated_at=None,
        skillshare_version=None,
        source_path=None,
        unique_skill_count=0,
        connected_agent_count=0,
        diverged_count=0,
        local_only_count=0,
        ignored_count=0,
        warning_count=0,
        warnings=(),
        targets=(),
        assets=(),
        ignored=(),
        filters=filters,
        status_options=_status_options(),
        source_options=_source_options(),
        target_options=(),
    )


def _matches_filters(
    asset: RuntimeSkillAsset,
    snapshot: RuntimeInventorySnapshot,
    filters: InventoryFilters,
) -> bool:
    query = filters.q.strip().casefold()
    if query and query not in asset.name.casefold() and query not in (asset.description or "").casefold():
        return False
    if filters.status and filters.status not in _STATUS_LABELS:
        return False
    if filters.status and asset.status != filters.status:
        return False
    if filters.source not in {"", "shared", "local_only"}:
        return False
    if filters.source == "shared" and asset.source_instance is None:
        return False
    if filters.source == "local_only" and asset.source_instance is not None:
        return False
    target_names = {target.name for target in snapshot.targets}
    if filters.target and filters.target not in target_names:
        return False
    asset_target_names = {
        instance.target_name
        for instance in asset.target_instances
        if instance.target_name is not None
    } | set(asset.missing_targets)
    return not filters.target or filters.target in asset_target_names


def _asset_presentation(
    asset: RuntimeSkillAsset,
    target_count: int,
) -> InventoryAssetPresentation:
    source_label = "共享源" if asset.source_instance is not None else "目标本地"
    source_instances = () if asset.source_instance is None else (asset.source_instance,)
    instances = tuple(
        _instance_presentation(instance)
        for instance in sorted(
            (*source_instances, *asset.target_instances),
            key=lambda item: (
                item.location_kind != "shared",
                (item.target_name or "").casefold(),
                item.path,
            ),
        )
    )
    return InventoryAssetPresentation(
        key=asset.key,
        name=asset.name,
        description=asset.description,
        status=asset.status,
        status_label=_STATUS_LABELS[asset.status],
        source_label=source_label,
        coverage_label=f"{len(asset.target_instances)}/{target_count}",
        missing_targets=tuple(sorted(asset.missing_targets, key=str.casefold)),
        instances=instances,
    )


def _instance_presentation(
    instance: RuntimeSkillInstance,
) -> InventoryInstancePresentation:
    return InventoryInstancePresentation(
        location_label=(
            "共享源"
            if instance.location_kind == "shared"
            else instance.target_name or "未知目标"
        ),
        path=instance.path,
        distribution_mode=instance.distribution_mode,
        digest_short=_short_digest(instance.digest),
        readable=instance.readable,
        readable_label="可读" if instance.readable else "不可读",
        is_symlink=instance.is_symlink,
    )


def _short_digest(digest: str | None) -> str:
    if digest is None:
        return "未生成"
    prefix, separator, value = digest.partition(":")
    if separator:
        return f"{prefix}:{value[:12]}"
    return digest[:12]


def _status_options() -> tuple[InventoryFilterOption, ...]:
    return tuple(
        InventoryFilterOption(status, _STATUS_LABELS[status])
        for status in _STATUS_ORDER
    )


def _source_options() -> tuple[InventoryFilterOption, ...]:
    return (
        InventoryFilterOption("shared", "共享源"),
        InventoryFilterOption("local_only", "目标本地"),
    )

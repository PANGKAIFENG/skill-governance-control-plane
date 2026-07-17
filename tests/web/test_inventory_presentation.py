from __future__ import annotations

import importlib
from typing import Any


def _presentation_module() -> Any:
    return importlib.import_module("skillctl.web.inventory_presentation")


def test_presentation_builds_metrics_labels_paths_and_stable_sort(
    runtime_inventory_reader: Any,
) -> None:
    module = _presentation_module()

    view = module.build_inventory_presentation(
        runtime_inventory_reader.read(),
        module.InventoryFilters(),
    )

    assert view.available is True
    assert view.unique_skill_count == 3
    assert view.connected_agent_count == 2
    assert view.diverged_count == 1
    assert view.local_only_count == 1
    assert view.ignored_count == 1
    assert view.warning_count == 1
    assert [asset.name for asset in view.assets] == [
        "Design Review",
        "Local Tool",
        "Visual Scan",
    ]
    assert [asset.status_label for asset in view.assets] == [
        "一致",
        "仅本地",
        "版本不一致",
    ]
    design = view.assets[0]
    assert design.source_label == "共享源"
    assert [instance.location_label for instance in design.instances] == [
        "共享源",
        "Claude",
    ]
    assert design.instances[0].digest_short == "sha256:aaaaaaaaaaaa"
    assert design.instances[1].path == "/Users/agents/claude/skills/design-review"


def test_presentation_filters_only_against_snapshot_values(
    runtime_inventory_reader: Any,
) -> None:
    module = _presentation_module()
    result = runtime_inventory_reader.read()

    matched = module.build_inventory_presentation(
        result,
        module.InventoryFilters(
            q="review",
            status="consistent",
            source="shared",
            target="Claude",
        ),
    )
    unknown = module.build_inventory_presentation(
        result,
        module.InventoryFilters(
            status="../sync",
            source="/tmp/source",
            target="$(skillshare sync)",
        ),
    )

    assert [asset.name for asset in matched.assets] == ["Design Review"]
    assert unknown.assets == ()


def test_presentation_keeps_unavailable_result_as_empty_state() -> None:
    from skillctl.runtime_inventory.models import RuntimeInventoryReadResult

    module = _presentation_module()
    view = module.build_inventory_presentation(
        RuntimeInventoryReadResult(
            available=False,
            snapshot=None,
            error_code="unavailable",
        ),
        module.InventoryFilters(),
    )

    assert view.available is False
    assert view.assets == ()
    assert view.unique_skill_count == 0
    assert view.error_label == "尚无可用的运行态盘点快照"

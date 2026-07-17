from __future__ import annotations

from pathlib import Path
from typing import Any

from playwright.sync_api import Locator, Page, sync_playwright


ARTIFACT_ROOT = Path(".artifacts/portal/mobile")
PLAN_ID = "plan-" + "a" * 32


def _assert_no_horizontal_overflow(page: Page) -> None:
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert page.evaluate("document.body.scrollWidth <= document.body.clientWidth")
    for locator in page.locator("main, .table-shell, details").all():
        assert locator.evaluate("node => node.scrollWidth <= node.clientWidth + 1")


def _assert_mobile_layout(page: Page) -> None:
    _assert_no_horizontal_overflow(page)
    brand = page.locator(".brand").bounding_box()
    nav = page.locator("nav").bounding_box()
    main = page.locator("main").bounding_box()
    header = page.locator("header").bounding_box()
    assert brand is not None and nav is not None and main is not None and header is not None
    assert brand["y"] + brand["height"] <= nav["y"]
    assert header["y"] + header["height"] <= main["y"]


def _assert_inside_viewport(page: Page, locator: Locator) -> None:
    box = locator.bounding_box()
    assert box is not None
    viewport_width = page.evaluate("window.innerWidth")
    assert box["x"] >= 0
    assert box["x"] + box["width"] <= viewport_width + 1


def _assert_non_overlapping(locators: list[Locator]) -> None:
    boxes = [locator.bounding_box() for locator in locators]
    assert all(box is not None for box in boxes)
    for index, first in enumerate(boxes):
        assert first is not None
        for second in boxes[index + 1 :]:
            assert second is not None
            overlaps_x = min(first["x"] + first["width"], second["x"] + second["width"]) > max(first["x"], second["x"])
            overlaps_y = min(first["y"] + first["height"], second["y"] + second["height"]) > max(first["y"], second["y"])
            assert not (overlaps_x and overlaps_y)


def test_mobile_portal_is_responsive_and_nonblank(
    portal_server: tuple[str, Any]
) -> None:
    origin, _ = portal_server
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    console_errors: list[str] = []
    page_errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 390, "height": 844})
        page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error"
            else None,
        )
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        page.goto(origin, wait_until="networkidle")
        _assert_mobile_layout(page)
        assert page.get_by_role("heading", name="Skill 资产", exact=True).is_visible()
        assert page.get_by_role("heading", name="资产列表").is_visible()
        assert page.get_by_role("button", name="重新盘点").is_visible()
        assert page.locator("table").nth(1).locator("thead").is_hidden()
        assert (
            page.locator("table")
            .nth(1)
            .locator("td[data-label='Skill']")
            .first.is_visible()
        )
        _assert_non_overlapping(page.locator("nav a").all())
        _assert_non_overlapping(page.locator(".inventory-heading > *").all())
        for control in page.locator(".inventory-filters input, .inventory-filters select, .inventory-filters button").all():
            box = control.bounding_box()
            assert box is not None and box["height"] >= 44

        warnings = page.locator("details.inventory-warnings")
        assert not warnings.evaluate("node => node.open")
        assert "扫描告警" in warnings.locator("summary").inner_text()
        assert "1 项" in warnings.locator("summary").inner_text()
        warning_copy = warnings.get_by_text("target WorkBuddy unreadable", exact=True)
        assert warning_copy.is_hidden()
        warnings.locator("summary").click()
        assert warnings.evaluate("node => node.open")
        assert warning_copy.is_visible()
        warnings.locator("summary").click()

        details = page.locator("details.instance-details").first
        details.locator("summary").click()
        assert details.evaluate("node => node.open")
        assert details.locator("code").first.is_visible()
        _assert_inside_viewport(page, details)
        _assert_no_horizontal_overflow(page)
        inventory = ARTIFACT_ROOT / "inventory-details.png"
        page.screenshot(path=str(inventory), full_page=True)

        page.get_by_role("link", name="系统状态").click()
        page.wait_for_load_state("networkidle")
        _assert_mobile_layout(page)
        assert page.get_by_label("Gate 1 至 Gate 4 状态").is_visible()

        page.get_by_role("link", name="计划与审批").click()
        page.wait_for_load_state("networkidle")
        page.get_by_role("link", name=PLAN_ID).click()
        page.wait_for_load_state("networkidle")
        _assert_mobile_layout(page)
        for button in page.locator("button").all():
            box = button.bounding_box()
            assert box is not None and box["height"] >= 44
        plan = ARTIFACT_ROOT / "plan-detail.png"
        page.screenshot(path=str(plan), full_page=True)
        browser.close()

    assert inventory.stat().st_size > 10_000
    assert plan.stat().st_size > 10_000
    assert console_errors == []
    assert page_errors == []


def test_mobile_inventory_wraps_long_dynamic_content(
    portal_server: tuple[str, Any]
) -> None:
    origin, _ = portal_server
    console_errors: list[str] = []
    page_errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 390, "height": 844})
        page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error"
            else None,
        )
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.goto(origin, wait_until="networkidle")

        asset_cell = page.locator("td[data-label='Skill']").first
        status = page.locator(".inventory-table tbody tr").first.locator("td[data-label='状态'] .status")
        asset_cell.locator(".asset-name").evaluate(
            "node => { node.textContent = 'W'.repeat(240); }"
        )
        status.evaluate("node => { node.textContent = 'W'.repeat(120); }")
        details = asset_cell.locator("details")
        details.locator("summary").click()
        details.locator("code").first.evaluate(
            "node => { node.textContent = '/path/' + 'segment'.repeat(160); }"
        )

        _assert_mobile_layout(page)
        _assert_inside_viewport(page, asset_cell)
        _assert_inside_viewport(page, status)
        _assert_inside_viewport(page, details)
        _assert_non_overlapping([asset_cell, status])
        refresh = page.get_by_role("button", name="重新盘点")
        _assert_inside_viewport(page, refresh)
        browser.close()

    assert console_errors == []
    assert page_errors == []

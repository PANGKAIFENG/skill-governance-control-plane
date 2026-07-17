from __future__ import annotations

from pathlib import Path
from typing import Any

from playwright.sync_api import Locator, Page, sync_playwright


ARTIFACT_ROOT = Path(".artifacts/portal/desktop")
PLAN_ID = "plan-" + "a" * 32


def _assert_no_horizontal_overflow(page: Page) -> None:
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert page.evaluate("document.body.scrollWidth <= document.body.clientWidth")
    for locator in page.locator("main, .table-shell").all():
        assert locator.evaluate("node => node.scrollWidth <= node.clientWidth + 1")


def _assert_layout(page: Page) -> None:
    _assert_no_horizontal_overflow(page)
    header = page.locator("header").bounding_box()
    main = page.locator("main").bounding_box()
    assert header is not None and main is not None
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


def test_desktop_portal_layout_and_decision_have_no_apply_request(
    portal_server: tuple[str, Any]
) -> None:
    origin, approval = portal_server
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    console_errors: list[str] = []
    page_errors: list[str] = []
    posts: list[str] = []
    failed_responses: list[tuple[str, int, str | None, str | None]] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error"
            else None,
        )
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.on(
            "request",
            lambda request: posts.append(request.url)
            if request.method == "POST"
            else None,
        )
        page.on(
            "response",
            lambda response: failed_responses.append(
                (
                    response.url,
                    response.status,
                    response.request.headers.get("origin"),
                    response.request.headers.get("referer"),
                )
            )
            if response.status >= 400
            else None,
        )

        page.goto(origin, wait_until="networkidle")
        _assert_layout(page)
        assert page.get_by_role("heading", name="Skill 资产", exact=True).is_visible()
        assert page.get_by_text("唯一 Skill", exact=True).is_visible()
        assert page.get_by_role("heading", name="目标连接状态").is_visible()
        assert page.get_by_role("heading", name="资产列表").is_visible()
        assert page.get_by_label("名称").is_visible()
        assert page.get_by_label("状态", exact=True).is_visible()
        assert page.get_by_label("来源", exact=True).is_visible()
        assert page.get_by_label("目标", exact=True).is_visible()
        assert page.get_by_role("button", name="重新盘点").is_visible()
        assert page.locator("table").count() == 2
        assert page.locator(".inventory-table").bounding_box()["y"] < 900  # type: ignore[index]
        for control in page.locator(".inventory-filters input, .inventory-filters select, .inventory-filters button").all():
            box = control.bounding_box()
            assert box is not None and box["height"] >= 44
        metric_boxes = [metric.bounding_box() for metric in page.locator(".inventory-metric-grid .metric").all()]
        assert all(box is not None for box in metric_boxes)
        assert len({round(box["height"]) for box in metric_boxes if box is not None}) == 1
        _assert_non_overlapping(page.locator("nav a").all())
        _assert_non_overlapping(page.locator(".inventory-heading > *").all())

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
        inventory = ARTIFACT_ROOT / "inventory.png"
        page.screenshot(path=str(inventory), full_page=True)

        page.get_by_role("link", name="系统状态").click()
        page.wait_for_load_state("networkidle")
        _assert_layout(page)
        assert page.get_by_label("Gate 1 至 Gate 4 状态").is_visible()
        assert page.get_by_role("heading", name="项目概况").is_visible()
        system = ARTIFACT_ROOT / "system.png"
        page.screenshot(path=str(system), full_page=True)

        page.get_by_role("link", name="计划与审批").click()
        page.wait_for_load_state("networkidle")
        assert page.get_by_role("heading", name="Plans", exact=True).is_visible()
        page.get_by_role("link", name=PLAN_ID).click()
        page.wait_for_load_state("networkidle")
        _assert_layout(page)
        for button in page.locator("button").all():
            box = button.bounding_box()
            assert box is not None and box["height"] >= 44
        detail = ARTIFACT_ROOT / "plan-detail.png"
        page.screenshot(path=str(detail), full_page=True)
        page.get_by_label("Reason").fill("Browser reviewed typed diff")
        page.get_by_role("button", name="Approve").click()
        page.wait_for_load_state("networkidle")
        browser.close()

    for artifact in (inventory, system, detail):
        assert artifact.stat().st_size > 10_000
    assert console_errors == [], failed_responses
    assert page_errors == []
    assert len(approval.calls) == 1
    assert posts and all("apply" not in url and "rollback" not in url for url in posts)

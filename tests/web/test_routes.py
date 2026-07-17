from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import tomllib
from typing import Any

import pytest
from fastapi.testclient import TestClient

from skillctl.runtime_inventory.models import RuntimeInventoryRefreshResult
from skillctl.web.readiness import GateReadiness


NOW = datetime(2026, 7, 14, 3, 0, tzinfo=timezone.utc)
PLAN_ID = "plan-" + "a" * 32


def _refresh_form(response_text: str) -> dict[str, str]:
    digest = re.search(
        r'name="expected_snapshot_digest" value="([^"]+)"', response_text
    )
    token = re.search(r'name="refresh_token" value="([^"]+)"', response_text)
    assert digest is not None
    assert token is not None
    return {
        "expected_snapshot_digest": digest.group(1),
        "refresh_token": token.group(1),
    }


class _InventoryRefresherSpy:
    def __init__(
        self,
        result: RuntimeInventoryRefreshResult,
        *,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls = 0

    def refresh(self) -> RuntimeInventoryRefreshResult:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def test_project_declares_portal_dependencies_without_replacing_core_contract() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["requires-python"] == ">=3.11"
    assert project["project"]["scripts"]["skillctl"] == "skillctl.cli:app"
    dependencies = " ".join(project["project"]["dependencies"])
    dev_dependencies = " ".join(project["project"]["optional-dependencies"]["dev"])
    for package in ("fastapi", "jinja2", "uvicorn", "python-multipart"):
        assert package in dependencies
    for package in ("httpx", "playwright"):
        assert package in dev_dependencies


def _client(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
    runtime_inventory_refresher: Any | None = None,
) -> TestClient:
    from skillctl.web.app import PortalReadProviders, create_app
    from skillctl.web.security import DecisionTokenStore

    tokens = DecisionTokenStore(
        now=lambda: NOW,
        allowed_origins=("http://testserver",),
        approver="portal-reviewer",
    )
    refresh_tokens = None
    if runtime_inventory_refresher is not None:
        from skillctl.web.security import InventoryRefreshTokenStore

        refresh_tokens = InventoryRefreshTokenStore(
            now=lambda: NOW,
            allowed_origins=("http://testserver",),
        )
    providers = (
        PortalReadProviders(readiness_provider, runtime_inventory_reader)
        if runtime_inventory_refresher is None
        else PortalReadProviders(
            readiness_provider,
            runtime_inventory_reader,
            runtime_inventory_refresher,
            refresh_tokens,
        )
    )
    return TestClient(create_app(read_service, approval_spy, tokens, providers))


def test_system_renders_canonical_operations_summary(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    response = _client(
        read_service, approval_spy, readiness_provider, runtime_inventory_reader
    ).get("/system")

    assert response.status_code == 200
    for value in (
        "asset-canary-long-identifier-for-responsive-checks",
        "governance&lt;script&gt;alert(1)&lt;/script&gt;",
        "private",
        "revision-canary-1",
        "target-local-b",
        "drifted",
        "revision-observed-0",
        "1",
        "failed",
        "Gate 1",
        "Gate 1–4 已完成",
        "COMPLETED_WITH_CONCERNS",
        "Gate 4",
        "项目概况",
        "设计协作项目",
        "产品治理项目",
        "workspace-design",
        "workspace-product-long-identifier-for-responsive-checks",
        "target-missing-read-only",
        "未找到目标",
        "1 个资产未绑定工作区",
    ):
        assert value in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "/Users/hidden" not in response.text
    assert "PORTAL_TEST_CREDENTIAL" not in response.text


def test_system_does_not_claim_gate_completion_when_evidence_is_unknown(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    readiness_provider.rows = (
        *readiness_provider.rows[:3],
        GateReadiness("Gate 4", "Adapter 兼容性", "UNKNOWN", "兼容性证据不可用"),
    )

    response = _client(
        read_service, approval_spy, readiness_provider, runtime_inventory_reader
    ).get("/system")

    assert response.status_code == 200
    assert "证据未完整闭合" in response.text
    assert "Gate 1–4 已完成" not in response.text


def test_plan_list_and_detail_render_review_fields(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    client = _client(
        read_service, approval_spy, readiness_provider, runtime_inventory_reader
    )

    plans = client.get("/plans")
    detail = client.get(f"/plans/{PLAN_ID}")

    assert plans.status_code == 200
    for value in (PLAN_ID, "high", "review_required", "Visibility changes"):
        assert value in plans.text
    assert detail.status_code == 200
    for value in (
        PLAN_ID,
        "sha256:" + "d" * 64,
        "update",
        "revision-before",
        "revision-after",
        "private",
        "public",
        "binding-canary-local-b",
        "read",
        "publish",
        "Approve",
        "Reject",
    ):
        assert value in detail.text
    assert "Visibility changes require &lt;review&gt;." in detail.text
    assert "/Users/hidden" not in detail.text


def test_pages_use_security_headers_and_generic_errors(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    client = _client(
        read_service, approval_spy, readiness_provider, runtime_inventory_reader
    )

    response = client.get("/plans/not-a-plan")

    assert response.status_code == 404
    assert "Plan unavailable" in response.text
    assert "TOP_SECRET_RAW_EXCEPTION" not in response.text
    assert "/Users/hidden" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"].startswith("default-src 'self'")


def test_inventory_home_renders_real_snapshot_without_governance_fixture(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    response = _client(
        read_service, approval_spy, readiness_provider, runtime_inventory_reader
    ).get("/")

    assert response.status_code == 200
    for value in (
        "Skill 资产",
        "3",
        "2",
        "Design Review",
        "Visual Scan",
        "Local Tool",
        "版本不一致",
        "仅本地",
        "ignored-experiment",
        "WorkBuddy",
        "不可用",
        "Multica",
        "尚未连接",
        "2026-07-14",
        "target WorkBuddy unreadable",
        "<details",
        "sha256:aaaaaaaaaaaa",
        "/Users/agents/claude/skills/design-review",
    ):
        assert value in response.text
    warning_details = re.search(
        r'<details class="[^"]*\binventory-warnings\b[^"]*"(?P<attrs>[^>]*)>'
        r'(?P<body>.*?)</details>',
        response.text,
        re.DOTALL,
    )
    assert warning_details is not None
    assert "open" not in warning_details.group("attrs").split()
    assert re.search(
        r"<summary[^>]*>.*扫描告警.*1 项.*</summary>",
        warning_details.group("body"),
        re.DOTALL,
    )
    assert "target WorkBuddy unreadable" in warning_details.group("body")
    assert "canary-skill" not in response.text
    assert runtime_inventory_reader.read_calls == 1


def test_inventory_home_has_clear_empty_state_without_registry_fallback(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
) -> None:
    from skillctl.runtime_inventory.models import RuntimeInventoryReadResult

    class EmptyReader:
        def read(self) -> RuntimeInventoryReadResult:
            return RuntimeInventoryReadResult(
                available=False,
                snapshot=None,
                error_code="unavailable",
            )

    response = _client(
        read_service, approval_spy, readiness_provider, EmptyReader()
    ).get("/")

    assert response.status_code == 200
    assert "尚无可用的运行态盘点快照" in response.text
    assert "canary-skill" not in response.text


def test_inventory_home_omits_warning_disclosure_without_warnings(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    snapshot = runtime_inventory_reader.result.snapshot
    assert snapshot is not None
    runtime_inventory_reader.result = runtime_inventory_reader.result.model_copy(
        update={"snapshot": snapshot.model_copy(update={"warnings": ()})}
    )

    response = _client(
        read_service, approval_spy, readiness_provider, runtime_inventory_reader
    ).get("/")

    assert response.status_code == 200
    assert "inventory-warnings" not in response.text
    assert '<strong id="warnings-title">扫描告警</strong>' not in response.text


def test_inventory_get_filters_are_data_only_and_unknown_values_are_safe(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    client = _client(
        read_service, approval_spy, readiness_provider, runtime_inventory_reader
    )

    filtered = client.get(
        "/", params={"q": "visual", "status": "diverged", "source": "shared", "target": "Codex"}
    )
    unknown = client.get(
        "/",
        params={
            "status": "../../mutation",
            "source": "/Users/secret",
            "target": "$(skillshare sync)",
        },
    )

    assert filtered.status_code == 200
    assert "Visual Scan" in filtered.text
    assert "Design Review" not in filtered.text
    assert "Local Tool" not in filtered.text
    assert unknown.status_code == 200
    assert "没有符合当前筛选条件的 Skill" in unknown.text
    assert runtime_inventory_reader.read_calls == 2


def test_inventory_refresh_accepts_one_valid_post_and_rejects_replay(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    refresher = _InventoryRefresherSpy(
        RuntimeInventoryRefreshResult(
            success=True,
            snapshot=runtime_inventory_reader.result.snapshot,
        )
    )
    client = _client(
        read_service,
        approval_spy,
        readiness_provider,
        runtime_inventory_reader,
        refresher,
    )
    form = _refresh_form(client.get("/").text)

    response = client.post(
        "/inventory/refresh",
        data=form,
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert refresher.calls == 1
    replay = client.post(
        "/inventory/refresh",
        data=form,
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    assert replay.status_code == 400
    assert refresher.calls == 1


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, 403),
        ({"origin": "http://evil.example"}, 403),
        ({"origin": "http://testserver", "host": "evil.example"}, 403),
    ],
)
def test_inventory_refresh_requires_exact_host_and_origin(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
    headers: dict[str, str],
    expected: int,
) -> None:
    refresher = _InventoryRefresherSpy(
        RuntimeInventoryRefreshResult(
            success=True,
            snapshot=runtime_inventory_reader.result.snapshot,
        )
    )
    client = _client(
        read_service,
        approval_spy,
        readiness_provider,
        runtime_inventory_reader,
        refresher,
    )
    form = _refresh_form(client.get("/").text)

    response = client.post(
        "/inventory/refresh",
        data=form,
        headers=headers,
        follow_redirects=False,
    )

    assert response.status_code == expected
    assert refresher.calls == 0


@pytest.mark.parametrize("malformed", ["extra", "duplicate", "content_type", "too_long"])
def test_inventory_refresh_rejects_noncanonical_form_without_refreshing(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
    malformed: str,
) -> None:
    refresher = _InventoryRefresherSpy(
        RuntimeInventoryRefreshResult(
            success=True,
            snapshot=runtime_inventory_reader.result.snapshot,
        )
    )
    client = _client(
        read_service,
        approval_spy,
        readiness_provider,
        runtime_inventory_reader,
        refresher,
    )
    form = _refresh_form(client.get("/").text)
    headers = {"origin": "http://testserver"}
    data: Any = form
    if malformed == "extra":
        data = {**form, "unexpected": "field"}
    elif malformed == "duplicate":
        data = (
            f"expected_snapshot_digest={form['expected_snapshot_digest']}"
            f"&refresh_token={form['refresh_token']}"
            f"&refresh_token={form['refresh_token']}"
        )
        headers["content-type"] = "application/x-www-form-urlencoded"
    elif malformed == "content_type":
        data = "{}"
        headers["content-type"] = "application/json"
    else:
        data = "x" * 4097
        headers["content-type"] = "application/x-www-form-urlencoded"

    response = client.post(
        "/inventory/refresh",
        content=data if isinstance(data, str) else None,
        data=data if isinstance(data, dict) else None,
        headers=headers,
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert refresher.calls == 0


def test_inventory_refresh_rejects_stale_digest_before_consuming_token(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    refresher = _InventoryRefresherSpy(
        RuntimeInventoryRefreshResult(
            success=True,
            snapshot=runtime_inventory_reader.result.snapshot,
        )
    )
    client = _client(
        read_service,
        approval_spy,
        readiness_provider,
        runtime_inventory_reader,
        refresher,
    )
    form = _refresh_form(client.get("/").text)
    runtime_inventory_reader.result = runtime_inventory_reader.result.model_copy(
        update={
            "snapshot": runtime_inventory_reader.result.snapshot.model_copy(
                update={"snapshot_digest": "sha256:" + "0" * 64}
            )
        }
    )

    rejected = client.post(
        "/inventory/refresh",
        data=form,
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    current_form = _refresh_form(client.get("/").text)
    accepted = client.post(
        "/inventory/refresh",
        data=current_form,
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert rejected.status_code == 400
    assert accepted.status_code == 303
    assert refresher.calls == 1


def test_inventory_refresh_exception_keeps_old_snapshot_and_shows_safe_notice(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    refresher = _InventoryRefresherSpy(
        RuntimeInventoryRefreshResult(success=False, snapshot=None, error_code="discovery_failed"),
        error=RuntimeError("SECRET_REFRESH_DETAIL /Users/hidden"),
    )
    client = _client(
        read_service,
        approval_spy,
        readiness_provider,
        runtime_inventory_reader,
        refresher,
    )
    form = _refresh_form(client.get("/").text)

    failed = client.post(
        "/inventory/refresh",
        data=form,
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    page = client.get(failed.headers["location"])

    assert failed.status_code == 303
    assert failed.headers["location"] == "/?refresh=failed"
    assert refresher.calls == 1
    assert "Design Review" in page.text
    assert "重新盘点失败，当前仍显示上次快照" in page.text
    assert "SECRET_REFRESH_DETAIL" not in page.text
    assert "/Users/hidden" not in page.text


def test_unavailable_inventory_can_issue_a_new_token_after_failed_first_refresh(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
) -> None:
    from skillctl.runtime_inventory.models import RuntimeInventoryReadResult

    class EmptyReader:
        def read(self) -> RuntimeInventoryReadResult:
            return RuntimeInventoryReadResult(
                available=False,
                snapshot=None,
                error_code="unavailable",
            )

    refresher = _InventoryRefresherSpy(
        RuntimeInventoryRefreshResult(
            success=False,
            snapshot=None,
            error_code="discovery_failed",
        )
    )
    client = _client(
        read_service,
        approval_spy,
        readiness_provider,
        EmptyReader(),
        refresher,
    )
    first_form = _refresh_form(client.get("/").text)
    first = client.post(
        "/inventory/refresh",
        data=first_form,
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    second_form = _refresh_form(client.get(first.headers["location"]).text)

    second = client.post(
        "/inventory/refresh",
        data=second_form,
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert first.status_code == 303
    assert second.status_code == 303
    assert first_form["expected_snapshot_digest"] == second_form[
        "expected_snapshot_digest"
    ]
    assert first_form["refresh_token"] != second_form["refresh_token"]
    assert refresher.calls == 2

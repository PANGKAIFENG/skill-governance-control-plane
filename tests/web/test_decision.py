from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient

from skillctl.web.app import create_app
from skillctl.web.security import (
    DecisionTokenCapacityError,
    DecisionTokenError,
    DecisionTokenStore,
)


NOW = datetime(2026, 7, 14, 3, 0, tzinfo=timezone.utc)
PLAN_ID = "plan-" + "a" * 32
PLAN_DIGEST = "sha256:" + "d" * 64


def _token(response_text: str) -> str:
    match = re.search(r'name="decision_token" value="([^"]+)"', response_text)
    assert match is not None
    return match.group(1)


def _client(
    read_service: Any, approval_spy: Any, readiness_provider: Any
) -> tuple[TestClient, DecisionTokenStore]:
    store = DecisionTokenStore(
        now=lambda: NOW,
        allowed_origins=("http://testserver",),
        approver="portal-reviewer",
    )
    return (
        TestClient(create_app(read_service, approval_spy, store, readiness_provider)),
        store,
    )


def _form(token: str, **updates: str) -> dict[str, str]:
    payload = {
        "decision": "approved",
        "reason": "Reviewed typed diff",
        "expected_plan_digest": PLAN_DIGEST,
        "decision_token": token,
    }
    payload.update(updates)
    return payload


def test_token_is_bound_expires_once_and_fails_closed_at_capacity() -> None:
    current = [NOW]
    store = DecisionTokenStore(
        now=lambda: current[0],
        allowed_origins=("http://testserver",),
        approver="reviewer",
        max_entries=2,
    )
    first = store.issue(PLAN_ID, PLAN_DIGEST)

    with pytest.raises(DecisionTokenError):
        store.consume(first, "plan-" + "b" * 32, PLAN_DIGEST)
    store.consume(first, PLAN_ID, PLAN_DIGEST)
    with pytest.raises(DecisionTokenError):
        store.consume(first, PLAN_ID, PLAN_DIGEST)

    expiring = store.issue(PLAN_ID, PLAN_DIGEST)
    current[0] += timedelta(minutes=5)
    store.issue("plan-" + "b" * 32, PLAN_DIGEST)
    with pytest.raises(DecisionTokenCapacityError):
        store.issue("plan-" + "c" * 32, PLAN_DIGEST)
    current[0] += timedelta(minutes=5)
    replacement = store.issue("plan-" + "c" * 32, PLAN_DIGEST)
    assert replacement
    with pytest.raises(DecisionTokenError):
        store.consume(expiring, PLAN_ID, PLAN_DIGEST)


@pytest.mark.parametrize(
    ("plan_id", "plan_digest"),
    [
        ("not-a-plan", PLAN_DIGEST),
        (PLAN_ID, "not-a-digest"),
        (PLAN_ID, "sha256:" + "A" * 64),
    ],
)
def test_token_issuer_rejects_invalid_binding(plan_id: str, plan_digest: str) -> None:
    store = DecisionTokenStore(
        now=lambda: NOW,
        allowed_origins=("http://testserver",),
        approver="reviewer",
    )

    with pytest.raises(DecisionTokenError):
        store.issue(plan_id, plan_digest)


@pytest.mark.parametrize(
    "overrides",
    [
        {"ttl": timedelta(minutes=10, microseconds=1)},
        {"max_entries": 1025},
    ],
)
def test_token_store_rejects_configuration_above_security_limits(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValueError, match="^invalid decision token configuration$"):
        DecisionTokenStore(
            now=lambda: NOW,
            allowed_origins=("http://testserver",),
            approver="reviewer",
            **overrides,
        )


def test_decision_records_only_approval_and_rejects_replay(
    read_service: Any, approval_spy: Any, readiness_provider: Any
) -> None:
    client, _ = _client(read_service, approval_spy, readiness_provider)
    token = _token(client.get(f"/plans/{PLAN_ID}").text)

    response = client.post(
        f"/plans/{PLAN_ID}/decision",
        data=_form(token),
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/plans/{PLAN_ID}"
    assert approval_spy.calls == [
        {
            "args": (
                PLAN_ID,
                "portal-reviewer",
                "approved",
                "Reviewed typed diff",
            ),
            "kwargs": {"now": NOW},
        }
    ]
    replay = client.post(
        f"/plans/{PLAN_ID}/decision",
        data=_form(token),
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    assert replay.status_code == 400
    assert len(approval_spy.calls) == 1
    assert client.post("/apply").status_code == 404
    assert client.post("/rollback").status_code == 404


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, 403),
        ({"origin": "http://evil.example"}, 403),
        ({"origin": "http://testserver", "host": "evil.example"}, 403),
    ],
)
def test_decision_requires_exact_host_and_origin(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    headers: dict[str, str],
    expected: int,
) -> None:
    client, _ = _client(read_service, approval_spy, readiness_provider)
    token = _token(client.get(f"/plans/{PLAN_ID}").text)

    response = client.post(
        f"/plans/{PLAN_ID}/decision",
        data=_form(token),
        headers=headers,
        follow_redirects=False,
    )

    assert response.status_code == expected
    assert approval_spy.calls == []


@pytest.mark.parametrize(
    "payload",
    [
        {"decision": "approve"},
        {"reason": "   "},
        {"expected_plan_digest": "sha256:" + "0" * 64},
        {"unexpected": "field"},
    ],
)
def test_decision_rejects_non_whitelisted_or_stale_input(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    payload: dict[str, str],
) -> None:
    client, _ = _client(read_service, approval_spy, readiness_provider)
    token = _token(client.get(f"/plans/{PLAN_ID}").text)

    response = client.post(
        f"/plans/{PLAN_ID}/decision",
        data=_form(token, **payload),
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert approval_spy.calls == []


def test_app_factory_and_source_have_no_execution_dependency() -> None:
    import skillctl.web.app as app_module
    import skillctl.web.routes as routes_module

    assert tuple(inspect.signature(create_app).parameters) == (
        "read_service",
        "approval_service",
        "decision_tokens",
        "readiness_provider",
    )
    source = inspect.getsource(app_module) + inspect.getsource(routes_module)
    for forbidden in (
        "from skillctl.service import DeploymentService",
        "from skillctl.adapters",
        "from skillctl.runner",
        "from skillctl.ledger",
        "deployment.apply(",
        "deployment.rollback(",
        "ledger.append(",
    ):
        assert forbidden not in source


def test_inventory_refresh_tokens_are_scoped_and_isolated_from_decisions(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
    runtime_inventory_reader: Any,
) -> None:
    from skillctl.runtime_inventory.models import RuntimeInventoryRefreshResult
    from skillctl.web.app import PortalReadProviders
    from skillctl.web.security import InventoryRefreshTokenStore

    class RefresherSpy:
        calls = 0

        def refresh(self) -> RuntimeInventoryRefreshResult:
            self.calls += 1
            return RuntimeInventoryRefreshResult(
                success=True,
                snapshot=runtime_inventory_reader.result.snapshot,
            )

    decision_store = DecisionTokenStore(
        now=lambda: NOW,
        allowed_origins=("http://testserver",),
        approver="portal-reviewer",
    )
    refresh_store = InventoryRefreshTokenStore(
        now=lambda: NOW,
        allowed_origins=("http://testserver",),
    )
    refresher = RefresherSpy()
    client = TestClient(
        create_app(
            read_service,
            approval_spy,
            decision_store,
            PortalReadProviders(
                readiness_provider,
                runtime_inventory_reader,
                refresher,
                refresh_store,
            ),
        )
    )
    decision_token = _token(client.get(f"/plans/{PLAN_ID}").text)
    inventory_page = client.get("/").text
    refresh_token_match = re.search(
        r'name="refresh_token" value="([^"]+)"', inventory_page
    )
    digest_match = re.search(
        r'name="expected_snapshot_digest" value="([^"]+)"', inventory_page
    )
    assert refresh_token_match is not None
    assert digest_match is not None
    refresh_token = refresh_token_match.group(1)
    snapshot_digest = digest_match.group(1)

    assert refresh_store.scope == "inventory-refresh"
    with pytest.raises(DecisionTokenError):
        refresh_store.consume(decision_token, snapshot_digest)
    with pytest.raises(DecisionTokenError):
        decision_store.consume(refresh_token, PLAN_ID, PLAN_DIGEST)

    refresh = client.post(
        "/inventory/refresh",
        data={
            "expected_snapshot_digest": snapshot_digest,
            "refresh_token": decision_token,
        },
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    decision = client.post(
        f"/plans/{PLAN_ID}/decision",
        data=_form(refresh_token),
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert refresh.status_code == 400
    assert decision.status_code == 400
    assert refresher.calls == 0
    assert approval_spy.calls == []


def test_legacy_four_argument_app_has_empty_inventory_without_refresh_action(
    read_service: Any,
    approval_spy: Any,
    readiness_provider: Any,
) -> None:
    client = TestClient(
        create_app(
            read_service,
            approval_spy,
            DecisionTokenStore(
                now=lambda: NOW,
                allowed_origins=("http://testserver",),
                approver="portal-reviewer",
            ),
            readiness_provider,
        )
    )

    home = client.get("/")
    plans = client.get("/plans")
    refresh = client.post(
        "/inventory/refresh",
        data={
            "expected_snapshot_digest": "sha256:" + "0" * 64,
            "refresh_token": "not-issued",
        },
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )

    assert home.status_code == 200
    assert "尚无可用的运行态盘点快照" in home.text
    assert 'action="/inventory/refresh"' not in home.text
    assert plans.status_code == 200
    assert refresh.status_code == 404

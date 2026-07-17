from __future__ import annotations

import hmac
import re
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Protocol, cast

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from skillctl.models import (
    Approval,
    ApprovalDecision,
    DeploymentLedgerEntry,
    DriftReport,
    Plan,
    StatusReport,
)
from skillctl.repository import GovernanceSnapshot
from skillctl.runtime_inventory.models import (
    RuntimeInventoryReadResult,
    RuntimeInventoryRefreshResult,
)
from skillctl.web.inventory_presentation import (
    InventoryFilters,
    build_inventory_presentation,
)
from skillctl.web.presentation import build_dashboard_presentation
from skillctl.web.readiness import ReadinessProvider, build_readiness_presentation
from skillctl.web.security import (
    DecisionTokenCapacityError,
    DecisionTokenError,
    DecisionTokenStore,
    InventoryRefreshTokenStore,
)


_PLAN_ID = re.compile(r"plan-[0-9a-f]{32}")
_SNAPSHOT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_UNAVAILABLE_SNAPSHOT_DIGEST = "sha256:" + sha256(
    b"skillctl:inventory:unavailable:v1"
).hexdigest()
_TEMPLATES = Jinja2Templates(
    directory=Path(__file__).parent / "templates",
)


class ReadService(Protocol):
    def snapshot(self) -> GovernanceSnapshot: ...
    def status(self, target_id: str | None = None) -> StatusReport: ...
    def drift(self, target_id: str | None = None) -> DriftReport: ...
    def deployments(self) -> tuple[DeploymentLedgerEntry, ...]: ...
    def plans(self) -> tuple[Plan, ...]: ...
    def get_plan(self, plan_id: str) -> Plan: ...
    def approval_for_plan(self, plan_id: str) -> Approval | None: ...


class ApprovalRecorder(Protocol):
    def record(
        self,
        plan_id: str,
        approver: str,
        decision: ApprovalDecision,
        reason: str,
        *,
        now: datetime,
    ) -> Approval: ...


class RuntimeInventoryReader(Protocol):
    def read(self) -> RuntimeInventoryReadResult: ...


class RuntimeInventoryRefresher(Protocol):
    def refresh(self) -> RuntimeInventoryRefreshResult: ...


def build_router(
    read_service: ReadService,
    approval_service: ApprovalRecorder,
    decision_tokens: DecisionTokenStore,
    readiness_provider: ReadinessProvider,
    runtime_inventory_reader: RuntimeInventoryReader | None = None,
    runtime_inventory_refresher: RuntimeInventoryRefresher | None = None,
    inventory_refresh_tokens: InventoryRefreshTokenStore | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    def inventory(
        request: Request,
        q: str = "",
        status: str = "",
        source: str = "",
        target: str = "",
        refresh: str = "",
    ) -> Response:
        try:
            result = (
                RuntimeInventoryReadResult(
                    available=False,
                    snapshot=None,
                    error_code="unavailable",
                )
                if runtime_inventory_reader is None
                else runtime_inventory_reader.read()
            )
            refresh_token: str | None = None
            expected_snapshot_digest: str | None = None
            if (
                runtime_inventory_reader is not None
                and runtime_inventory_refresher is not None
                and inventory_refresh_tokens is not None
            ):
                expected_snapshot_digest = _inventory_binding_digest(result)
                if expected_snapshot_digest is not None:
                    try:
                        refresh_token = inventory_refresh_tokens.issue(
                            expected_snapshot_digest
                        )
                    except DecisionTokenCapacityError:
                        refresh_token = None
            refresh_notice = None
            if refresh == "failed":
                refresh_notice = (
                    "重新盘点失败，当前仍显示上次快照"
                    if result.available
                    else "重新盘点失败，当前仍无可用快照"
                )
            context = {
                "request": request,
                "page_id": "inventory",
                "inventory": build_inventory_presentation(
                    result,
                    InventoryFilters(q=q, status=status, source=source, target=target),
                ),
                "refresh_token": refresh_token,
                "expected_snapshot_digest": expected_snapshot_digest,
                "refresh_notice": refresh_notice,
            }
            return _TEMPLATES.TemplateResponse(request, "inventory.html", context)
        except Exception:
            return _generic_page(request, "Inventory unavailable", 500)

    @router.post("/inventory/refresh")
    async def refresh_inventory(request: Request) -> Response:
        if (
            runtime_inventory_reader is None
            or runtime_inventory_refresher is None
            or inventory_refresh_tokens is None
        ):
            return HTMLResponse("Not found", status_code=404)
        try:
            inventory_refresh_tokens.require_request_authority(request)
        except DecisionTokenError:
            return HTMLResponse("Refresh rejected", status_code=403)
        raw_headers = request.scope.get("headers", ())
        content_types = [
            value for key, value in raw_headers if key.lower() == b"content-type"
        ]
        content_lengths = [
            value for key, value in raw_headers if key.lower() == b"content-length"
        ]
        try:
            if len(content_types) != 1 or len(content_lengths) != 1:
                raise ValueError
            if content_types[0].decode("ascii") != "application/x-www-form-urlencoded":
                raise ValueError
            content_length = int(content_lengths[0].decode("ascii"))
            if not 0 <= content_length <= 4096:
                raise ValueError
            items = list((await request.form()).multi_items())
        except (UnicodeDecodeError, ValueError, TypeError):
            return HTMLResponse("Refresh rejected", status_code=400)
        expected_fields = {"expected_snapshot_digest", "refresh_token"}
        if len(items) != 2 or {key for key, _ in items} != expected_fields:
            return HTMLResponse("Refresh rejected", status_code=400)
        fields = {key: str(value) for key, value in items}
        expected_digest = fields["expected_snapshot_digest"]
        token = fields["refresh_token"]
        if (
            _SNAPSHOT_DIGEST.fullmatch(expected_digest) is None
            or not token
            or len(token) > 256
        ):
            return HTMLResponse("Refresh rejected", status_code=400)
        try:
            current_result = runtime_inventory_reader.read()
        except Exception:
            return HTMLResponse("Refresh unavailable", status_code=409)
        current_digest = _inventory_binding_digest(current_result)
        if current_digest is None or not hmac.compare_digest(
            expected_digest, current_digest
        ):
            return HTMLResponse("Refresh rejected", status_code=400)
        try:
            inventory_refresh_tokens.consume(token, current_digest)
        except DecisionTokenError:
            return HTMLResponse("Refresh rejected", status_code=400)
        try:
            result = runtime_inventory_refresher.refresh()
        except Exception:
            result = None
        location = "/" if result is not None and result.success else "/?refresh=failed"
        return RedirectResponse(location, status_code=303)

    @router.get("/system", response_class=HTMLResponse)
    def dashboard(request: Request) -> Response:
        try:
            snapshot = read_service.snapshot()
            status = read_service.status()
            drift = read_service.drift()
            deployments = read_service.deployments()
            context = {
                "request": request,
                "page_id": "system",
                "dashboard": build_dashboard_presentation(
                    snapshot,
                    status,
                    drift,
                    deployments,
                ),
                "readiness": build_readiness_presentation(
                    readiness_provider.readiness()
                ),
            }
            return _TEMPLATES.TemplateResponse(request, "dashboard.html", context)
        except Exception:
            return _generic_page(request, "Dashboard unavailable", 500)

    @router.get("/plans", response_class=HTMLResponse)
    def plans(request: Request) -> Response:
        try:
            rows = tuple(
                {
                    "plan": plan,
                    "approval": read_service.approval_for_plan(plan.id),
                }
                for plan in reversed(read_service.plans())
            )
            return _TEMPLATES.TemplateResponse(
                request,
                "plans.html",
                {"request": request, "page_id": "plans", "rows": rows},
            )
        except Exception:
            return _generic_page(request, "Plans unavailable", 500)

    @router.get("/plans/{plan_id}", response_class=HTMLResponse)
    def plan_detail(request: Request, plan_id: str) -> Response:
        if _PLAN_ID.fullmatch(plan_id) is None:
            return _generic_page(request, "Plan unavailable", 404)
        try:
            plan = read_service.get_plan(plan_id)
            approval = read_service.approval_for_plan(plan_id)
            token: str | None = None
            decision_unavailable = False
            if approval is None and decision_tokens.current_time() < plan.expires_at:
                try:
                    token = decision_tokens.issue(plan.id, plan.plan_digest)
                except DecisionTokenCapacityError:
                    decision_unavailable = True
            return _TEMPLATES.TemplateResponse(
                request,
                "plan_detail.html",
                {
                    "request": request,
                    "page_id": "plans",
                    "plan": plan,
                    "approval": approval,
                    "decision_token": token,
                    "decision_unavailable": decision_unavailable,
                },
            )
        except Exception:
            return _generic_page(request, "Plan unavailable", 404)

    @router.post("/plans/{plan_id}/decision")
    async def record_decision(request: Request, plan_id: str) -> Response:
        if _PLAN_ID.fullmatch(plan_id) is None:
            return HTMLResponse("Decision rejected", status_code=400)
        try:
            decision_tokens.require_request_authority(request)
        except DecisionTokenError:
            return HTMLResponse("Decision rejected", status_code=403)
        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        content_length = request.headers.get("content-length", "0")
        if content_type != "application/x-www-form-urlencoded":
            return HTMLResponse("Decision rejected", status_code=400)
        try:
            if int(content_length) > 4096:
                raise ValueError
            items = list((await request.form()).multi_items())
        except (ValueError, TypeError):
            return HTMLResponse("Decision rejected", status_code=400)
        expected_fields = {
            "decision",
            "reason",
            "expected_plan_digest",
            "decision_token",
        }
        if len(items) != 4 or {key for key, _ in items} != expected_fields:
            return HTMLResponse("Decision rejected", status_code=400)
        fields = {key: str(value) for key, value in items}
        decision = fields["decision"]
        reason = fields["reason"].strip()
        expected_digest = fields["expected_plan_digest"]
        token = fields["decision_token"]
        if (
            decision not in {"approved", "rejected"}
            or not reason
            or len(reason) > 500
            or not token
            or len(token) > 256
        ):
            return HTMLResponse("Decision rejected", status_code=400)
        try:
            plan = read_service.get_plan(plan_id)
            if not hmac.compare_digest(expected_digest, plan.plan_digest):
                raise DecisionTokenError("digest mismatch")
            decision_tokens.consume(token, plan_id, expected_digest)
            approval_service.record(
                plan_id,
                decision_tokens.approver,
                cast(ApprovalDecision, decision),
                reason,
                now=decision_tokens.current_time(),
            )
        except DecisionTokenError:
            return HTMLResponse("Decision rejected", status_code=400)
        except Exception:
            return HTMLResponse("Decision unavailable", status_code=409)
        return RedirectResponse(f"/plans/{plan_id}", status_code=303)

    return router


def _generic_page(request: Request, message: str, status_code: int) -> Response:
    return _TEMPLATES.TemplateResponse(
        request,
        "base.html",
        {
            "request": request,
            "page_id": "error",
            "page_title": message,
            "error_message": message,
        },
        status_code=status_code,
    )


def _inventory_binding_digest(result: RuntimeInventoryReadResult) -> str | None:
    if not result.available or result.snapshot is None:
        return _UNAVAILABLE_SNAPSHOT_DIGEST
    return result.snapshot.snapshot_digest

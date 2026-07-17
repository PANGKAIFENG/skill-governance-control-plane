from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from skillctl.errors import PolicyDenied, StalePlan
from skillctl.models import Approval, ApprovalDecision
from skillctl.redaction import contains_secret_like
from skillctl.repository import DocumentRepository


class ApprovalService:
    def __init__(self, repository: DocumentRepository) -> None:
        self._repository = repository

    def record(
        self,
        plan_id: str,
        approver: str,
        decision: ApprovalDecision,
        reason: str,
        *,
        now: datetime,
    ) -> Approval:
        if not approver.strip() or not reason.strip():
            raise PolicyDenied("approval: identity and reason required")
        if contains_secret_like(reason):
            raise PolicyDenied("approval: secret-like reason is forbidden")
        if now.tzinfo is None or now.utcoffset() is None:
            raise PolicyDenied("approval: invalid decision time")

        plan = self._repository.get_plan(plan_id)
        if now >= plan.expires_at:
            raise StalePlan("approval: plan expired")
        try:
            approval = Approval(
                id=f"approval-{plan.id}",
                plan_id=plan.id,
                plan_digest=plan.plan_digest,
                decision=decision,
                approver=approver,
                reason=reason,
                decided_at=now,
            )
        except ValidationError:
            raise PolicyDenied("approval: invalid decision") from None
        self._repository.create_approval(approval)
        return approval

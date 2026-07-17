import os
import re

from skillctl.models import is_sensitive_name

_FAIL_SAFE_MESSAGES = (
    "control-plane operation failed safely",
    "request rejected",
    "operation blocked",
    "<blocked>",
)


def _fail_safe_public_message(sensitive_values: list[str]) -> str:
    for candidate in _FAIL_SAFE_MESSAGES:
        if all(value not in candidate for value in sensitive_values):
            return candidate
    return ""


class ControlPlaneError(Exception):
    """Base class for errors safe to expose at control-plane boundaries."""

    def __init__(self, public_message: str) -> None:
        sanitized = public_message
        values = sorted(
            {
                value
                for name, value in os.environ.items()
                if value and is_sensitive_name(name)
            },
            key=len,
            reverse=True,
        )
        for value in values:
            if len(value) < 4:
                if value not in sanitized:
                    continue
                escaped = re.escape(value)
                embedded = re.search(
                    rf"(?:(?<=[\w]){escaped}|{escaped}(?=[\w]))",
                    sanitized,
                )
                if embedded:
                    sanitized = _fail_safe_public_message(values)
                    break
                sanitized = re.sub(
                    rf"(?<![\w]){re.escape(value)}(?![\w])",
                    "<redacted>",
                    sanitized,
                )
            else:
                sanitized = sanitized.replace(value, "<redacted>")
        super().__init__(sanitized)


class SchemaError(ControlPlaneError):
    pass


class ReferenceError(ControlPlaneError):
    pass


class GovernanceValidationError(ControlPlaneError):
    pass


class SafetyViolation(ControlPlaneError):
    pass


class PolicyDenied(ControlPlaneError):
    pass


class ApprovalRequired(ControlPlaneError):
    pass


class StalePlan(ControlPlaneError):
    pass


class UnsupportedCapability(ControlPlaneError):
    pass


class UnsupportedCapabilityError(UnsupportedCapability):
    pass


class AdapterFailure(ControlPlaneError):
    pass


class LedgerCorruption(ControlPlaneError):
    pass


class StateCorruption(ControlPlaneError):
    pass

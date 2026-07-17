from __future__ import annotations

import os
import re
from collections.abc import Sequence

from skillctl.models import is_sensitive_name


REDACTED = "<redacted>"

_KEY_VALUE_PATTERN = re.compile(
    r"\b(?P<name>[A-Za-z][A-Za-z0-9_.-]*)\s*(?P<separator>[:=])\s*(?P<value>[^\s,;]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+(?P<value>[^\s,;]+)")
_TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
)


def _sensitive_environment_values() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value
                for name, value in os.environ.items()
                if value
                and name.upper() not in {"PWD", "OLDPWD"}
                and is_sensitive_name(name)
            },
            key=len,
            reverse=True,
        )
    )


def _contains_environment_value(text: str, value: str) -> bool:
    if len(value) >= 4:
        return value in text
    return re.search(rf"(?<![\w]){re.escape(value)}(?![\w])", text) is not None


def contains_secret_like(text: str) -> bool:
    if _BEARER_PATTERN.search(text) or any(pattern.search(text) for pattern in _TOKEN_PATTERNS):
        return True
    if any(
        is_sensitive_name(match.group("name"))
        for match in _KEY_VALUE_PATTERN.finditer(text)
    ):
        return True
    return any(
        _contains_environment_value(text, value)
        for value in _sensitive_environment_values()
    )


def _redact_secret_like_text(text: str) -> str:
    def redact_key_value(match: re.Match[str]) -> str:
        if not is_sensitive_name(match.group("name")):
            return match.group(0)
        return f'{match.group("name")}{match.group("separator")}{REDACTED}'

    redacted = _KEY_VALUE_PATTERN.sub(redact_key_value, text)
    redacted = _BEARER_PATTERN.sub(f"Bearer {REDACTED}", redacted)
    for pattern in _TOKEN_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    for value in _sensitive_environment_values():
        if len(value) >= 4:
            redacted = redacted.replace(value, REDACTED)
        else:
            redacted = re.sub(
                rf"(?<![\w]){re.escape(value)}(?![\w])", REDACTED, redacted
            )
    return redacted


def redact_argv(argv: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for argument in argv:
        if redact_next:
            redacted.append(REDACTED)
            redact_next = False
            continue
        option = argument.lstrip("-")
        if argument.startswith("-") and "=" not in option and is_sensitive_name(option):
            redacted.append(argument)
            redact_next = True
            continue
        redacted.append(_redact_secret_like_text(argument))
    return redacted

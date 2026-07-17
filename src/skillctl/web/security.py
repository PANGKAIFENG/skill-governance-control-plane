from __future__ import annotations

import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Lock
from urllib.parse import urlsplit

from starlette.requests import Request


_PLAN_ID = re.compile(r"plan-[0-9a-f]{32}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_INVENTORY_REFRESH_BINDING_ID = "plan-696e76656e746f72792d726566726573"


class DecisionTokenError(Exception):
    pass


class DecisionTokenCapacityError(DecisionTokenError):
    pass


@dataclass(frozen=True)
class _TokenBinding:
    plan_id: str
    plan_digest: str
    created_at: datetime
    expires_at: datetime


class DecisionTokenStore:
    def __init__(
        self,
        *,
        now: Callable[[], datetime],
        allowed_origins: tuple[str, ...],
        approver: str,
        ttl: timedelta = timedelta(minutes=10),
        max_entries: int = 1024,
    ) -> None:
        if (
            not approver.strip()
            or not timedelta(0) < ttl <= timedelta(minutes=10)
            or not 1 <= max_entries <= 1024
        ):
            raise ValueError("invalid decision token configuration")
        if not allowed_origins or any(
            not self._valid_origin(origin) for origin in allowed_origins
        ):
            raise ValueError("invalid decision token configuration")
        self._now = now
        self._allowed_origins = frozenset(allowed_origins)
        self._approver = approver.strip()
        self._ttl = ttl
        self._max_entries = max_entries
        self._tokens: dict[str, _TokenBinding] = {}
        self._lock = Lock()

    @property
    def approver(self) -> str:
        return self._approver

    def current_time(self) -> datetime:
        current = self._now()
        if current.tzinfo is None or current.utcoffset() is None:
            raise DecisionTokenError("decision token unavailable")
        return current

    def issue(self, plan_id: str, plan_digest: str) -> str:
        if _PLAN_ID.fullmatch(plan_id) is None or _DIGEST.fullmatch(plan_digest) is None:
            raise DecisionTokenError("invalid decision token binding")
        current = self.current_time()
        with self._lock:
            self._remove_expired(current)
            if len(self._tokens) >= self._max_entries:
                raise DecisionTokenCapacityError("decision token capacity reached")
            token = secrets.token_urlsafe(32)
            while token in self._tokens:
                token = secrets.token_urlsafe(32)
            self._tokens[token] = _TokenBinding(
                plan_id=plan_id,
                plan_digest=plan_digest,
                created_at=current,
                expires_at=current + self._ttl,
            )
        return token

    def consume(self, token: str, plan_id: str, plan_digest: str) -> None:
        current = self.current_time()
        with self._lock:
            self._remove_expired(current)
            binding = self._tokens.get(token)
            if binding is None or not (
                hmac.compare_digest(binding.plan_id, plan_id)
                and hmac.compare_digest(binding.plan_digest, plan_digest)
            ):
                raise DecisionTokenError("invalid decision token")
            del self._tokens[token]

    def require_request_authority(self, request: Request) -> None:
        raw_headers = request.scope.get("headers", ())
        hosts = [value for key, value in raw_headers if key.lower() == b"host"]
        origins = [value for key, value in raw_headers if key.lower() == b"origin"]
        if len(hosts) != 1 or len(origins) != 1:
            raise DecisionTokenError("invalid request authority")
        try:
            host = hosts[0].decode("ascii")
            origin = origins[0].decode("ascii")
        except UnicodeDecodeError:
            raise DecisionTokenError("invalid request authority") from None
        parsed = urlsplit(origin)
        if (
            origin not in self._allowed_origins
            or parsed.netloc != host
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise DecisionTokenError("invalid request authority")

    @staticmethod
    def _valid_origin(origin: str) -> bool:
        parsed = urlsplit(origin)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and parsed.geturl() == origin
        )

    def _remove_expired(self, current: datetime) -> None:
        expired = sorted(
            (
                (token, binding)
                for token, binding in self._tokens.items()
                if current >= binding.expires_at
            ),
            key=lambda item: item[1].created_at,
        )
        for token, _ in expired:
            del self._tokens[token]


class InventoryRefreshTokenStore:
    scope = "inventory-refresh"

    def __init__(
        self,
        *,
        now: Callable[[], datetime],
        allowed_origins: tuple[str, ...],
        ttl: timedelta = timedelta(minutes=10),
        max_entries: int = 1024,
    ) -> None:
        self._store = DecisionTokenStore(
            now=now,
            allowed_origins=allowed_origins,
            approver=self.scope,
            ttl=ttl,
            max_entries=max_entries,
        )

    def issue(self, snapshot_digest: str) -> str:
        return self._store.issue(_INVENTORY_REFRESH_BINDING_ID, snapshot_digest)

    def consume(self, token: str, snapshot_digest: str) -> None:
        self._store.consume(token, _INVENTORY_REFRESH_BINDING_ID, snapshot_digest)

    def require_request_authority(self, request: Request) -> None:
        self._store.require_request_authority(request)

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from skillctl.canonical import canonical_digest, canonical_json
from skillctl.errors import LedgerCorruption
from skillctl.models import DeploymentLedgerEntry


def _reject_json_constant(_: str) -> Any:
    raise ValueError


class DeploymentLedger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, entry: DeploymentLedgerEntry) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.parent.is_symlink() or not self.path.parent.is_dir():
                raise OSError
            flags = os.O_CREAT | os.O_APPEND | os.O_RDWR
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
        except OSError:
            raise LedgerCorruption("ledger: append failed") from None

        try:
            with os.fdopen(descriptor, "r+b") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                stream.seek(0)
                entries = self._parse(stream.read())
                if any(item.deployment_id == entry.deployment_id for item in entries):
                    raise LedgerCorruption("ledger: duplicate deployment id")
                previous_hash = entries[-1].entry_hash if entries else None
                chained = entry.model_copy(
                    update={"previous_entry_hash": previous_hash, "entry_hash": ""}
                )
                entry_hash = canonical_digest(
                    chained.model_dump(mode="json", exclude={"entry_hash"})
                )
                persisted = chained.model_copy(update={"entry_hash": entry_hash})
                stream.seek(0, os.SEEK_END)
                stream.write(canonical_json(persisted.model_dump(mode="json")) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        except LedgerCorruption:
            raise
        except (OSError, ValueError, ValidationError, TypeError):
            raise LedgerCorruption("ledger: append failed") from None

    def read_all(self) -> tuple[DeploymentLedgerEntry, ...]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return ()
        except OSError:
            raise LedgerCorruption("ledger: invalid entry chain") from None

        try:
            with os.fdopen(descriptor, "rb") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
                return self._parse(stream.read())
        except LedgerCorruption:
            raise
        except OSError:
            raise LedgerCorruption("ledger: invalid entry chain") from None

    @staticmethod
    def _parse(raw: bytes) -> tuple[DeploymentLedgerEntry, ...]:
        if not raw:
            return ()
        if not raw.endswith(b"\n"):
            raise LedgerCorruption("ledger: invalid entry chain")

        entries: list[DeploymentLedgerEntry] = []
        deployment_ids: set[str] = set()
        expected_previous_hash: str | None = None
        try:
            for line in raw.splitlines():
                payload = json.loads(line, parse_constant=_reject_json_constant)
                entry = DeploymentLedgerEntry.model_validate(payload)
                if canonical_json(entry.model_dump(mode="json")) != line:
                    raise ValueError
                if entry.deployment_id in deployment_ids:
                    raise ValueError
                if entry.previous_entry_hash != expected_previous_hash:
                    raise ValueError
                expected_hash = canonical_digest(
                    entry.model_dump(mode="json", exclude={"entry_hash"})
                )
                if entry.entry_hash != expected_hash:
                    raise ValueError
                deployment_ids.add(entry.deployment_id)
                expected_previous_hash = entry.entry_hash
                entries.append(entry)
        except (json.JSONDecodeError, UnicodeError, ValidationError, ValueError, TypeError):
            raise LedgerCorruption("ledger: invalid entry chain") from None
        return tuple(entries)

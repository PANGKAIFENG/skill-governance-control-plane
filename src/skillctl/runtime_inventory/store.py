from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from pydantic import ValidationError

from skillctl.canonical import canonical_digest, canonical_json
from skillctl.runtime_inventory.models import (
    RuntimeInventoryReadResult,
    RuntimeInventorySnapshot,
)

_SNAPSHOT_NAME = "snapshot.json"
_DEFAULT_MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


class RuntimeInventoryStoreError(RuntimeError):
    """A sanitized persistence failure that is safe to expose to callers."""

    def __init__(self) -> None:
        super().__init__("persistence_failed")


class RuntimeInventoryStore:
    def __init__(
        self,
        state_root: Path,
        *,
        max_snapshot_bytes: int = _DEFAULT_MAX_SNAPSHOT_BYTES,
    ) -> None:
        if max_snapshot_bytes < 1:
            raise ValueError("max_snapshot_bytes must be positive")
        self._directory = state_root / "runtime-inventory"
        self._max_snapshot_bytes = max_snapshot_bytes

    def save(self, snapshot: RuntimeInventorySnapshot) -> RuntimeInventorySnapshot:
        digest = canonical_digest(
            snapshot.model_dump(mode="json", exclude={"snapshot_digest"})
        )
        stored = RuntimeInventorySnapshot.model_validate(
            snapshot.model_dump(mode="python", exclude={"snapshot_digest"})
            | {"snapshot_digest": digest}
        )
        payload = canonical_json(stored)
        if len(payload) > self._max_snapshot_bytes:
            raise RuntimeInventoryStoreError()

        directory_fd: int | None = None
        temporary_fd: int | None = None
        temporary_name: str | None = None
        temporary_exists = False
        try:
            directory_fd = self._open_directory(create=True)
            assert directory_fd is not None
            self._require_safe_snapshot_target(directory_fd)
            temporary_name = f".{_SNAPSHOT_NAME}.{secrets.token_hex(16)}.tmp"
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            temporary_exists = True
            self._write_all(temporary_fd, payload)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None

            self._require_safe_snapshot_target(directory_fd)
            os.replace(
                temporary_name,
                _SNAPSHOT_NAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary_exists = False
            os.fsync(directory_fd)
        except Exception:
            raise RuntimeInventoryStoreError() from None
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass
            if temporary_exists and temporary_name is not None and directory_fd is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
            if directory_fd is not None:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
        return stored

    def read(self) -> RuntimeInventoryReadResult:
        directory_fd: int | None = None
        snapshot_fd: int | None = None
        try:
            directory_fd = self._open_directory(create=False)
            if directory_fd is None:
                return self._unavailable("unavailable")
            before = self._snapshot_stat(directory_fd)
            if before is None:
                return self._unavailable("unavailable")
            if not stat.S_ISREG(before.st_mode):
                return self._unavailable("invalid_snapshot")
            snapshot_fd = os.open(
                _SNAPSHOT_NAME,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            after = os.fstat(snapshot_fd)
            if (
                not stat.S_ISREG(after.st_mode)
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            ):
                return self._unavailable("invalid_snapshot")
            payload = self._read_limited(snapshot_fd)
            snapshot = RuntimeInventorySnapshot.model_validate_json(payload)
            expected = canonical_digest(
                snapshot.model_dump(mode="json", exclude={"snapshot_digest"})
            )
            if snapshot.snapshot_digest is None or snapshot.snapshot_digest != expected:
                return self._unavailable("invalid_snapshot")
            return RuntimeInventoryReadResult(
                available=True,
                snapshot=snapshot,
            )
        except (OSError, RuntimeInventoryStoreError, ValueError, ValidationError):
            return self._unavailable("invalid_snapshot")
        finally:
            if snapshot_fd is not None:
                try:
                    os.close(snapshot_fd)
                except OSError:
                    pass
            if directory_fd is not None:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass

    def _open_directory(self, *, create: bool) -> int | None:
        if create:
            try:
                self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError:
                raise RuntimeInventoryStoreError() from None
        try:
            before = self._directory.lstat()
        except FileNotFoundError:
            if create:
                raise RuntimeInventoryStoreError() from None
            return None
        except OSError:
            raise RuntimeInventoryStoreError() from None
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise RuntimeInventoryStoreError()
        try:
            directory_fd = os.open(
                self._directory,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            after = os.fstat(directory_fd)
        except OSError:
            raise RuntimeInventoryStoreError() from None
        if (
            not stat.S_ISDIR(after.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            os.close(directory_fd)
            raise RuntimeInventoryStoreError()
        return directory_fd

    @staticmethod
    def _snapshot_stat(directory_fd: int) -> os.stat_result | None:
        try:
            return os.stat(_SNAPSHOT_NAME, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @classmethod
    def _require_safe_snapshot_target(cls, directory_fd: int) -> None:
        target = cls._snapshot_stat(directory_fd)
        if target is not None and not stat.S_ISREG(target.st_mode):
            raise RuntimeInventoryStoreError()

    @staticmethod
    def _write_all(file_descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(file_descriptor, view[written:])
            if count <= 0:
                raise OSError()
            written += count

    def _read_limited(self, file_descriptor: int) -> bytes:
        payload = bytearray()
        while len(payload) <= self._max_snapshot_bytes:
            remaining = self._max_snapshot_bytes + 1 - len(payload)
            chunk = os.read(file_descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                return bytes(payload)
            payload.extend(chunk)
        raise ValueError("snapshot exceeds size limit")

    @staticmethod
    def _unavailable(error_code: str) -> RuntimeInventoryReadResult:
        return RuntimeInventoryReadResult(
            available=False,
            snapshot=None,
            error_code=error_code,
        )

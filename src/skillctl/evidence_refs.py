import hashlib
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple, cast

from pydantic import ValidationError

from skillctl.errors import SafetyViolation
from skillctl.models import DeploymentLedgerEntry, EvidenceRef, ResolvedEvidence


_NATIVE_OPEN = os.open


class _EvidenceRefSnapshot(NamedTuple):
    owner_type: str
    owner_id: str
    relative_path: str
    sha256: str
    media_type: str


def _open_supports_dir_fd() -> bool:
    supported: set[object] = getattr(os, "supports_dir_fd", set())
    return os.open is _NATIVE_OPEN and _NATIVE_OPEN in supported


def _capture_evidence_ref(ref: EvidenceRef) -> dict[str, object]:
    fields = cast(
        dict[str, object],
        object.__getattribute__(ref, "__dict__"),
    )
    return fields.copy()


def _validated_evidence_ref_snapshot(ref: EvidenceRef) -> _EvidenceRefSnapshot:
    captured = _capture_evidence_ref(ref)
    EvidenceRef.model_validate(captured)
    return _EvidenceRefSnapshot(
        owner_type=cast(str, captured["owner_type"]),
        owner_id=cast(str, captured["owner_id"]),
        relative_path=cast(str, captured["relative_path"]),
        sha256=cast(str, captured["sha256"]),
        media_type=cast(str, captured["media_type"]),
    )


class EvidenceResolver:
    def __init__(self, evidence_root: Path) -> None:
        self.evidence_root = evidence_root

    def resolve(self, ref: EvidenceRef) -> Path:
        """Return a locator-only Path after a one-time checksum check.

        The returned Path is not a continuing trusted-content promise and must not be
        used for an approval, deployment, Portal, or other security decision. Consumers
        that require trusted bytes must use an owner-specific hardened resolver such as
        DeploymentEvidenceResolver.
        """
        try:
            validated = EvidenceRef.model_validate(ref.model_dump())
        except ValidationError as error:
            raise SafetyViolation("relative evidence path is invalid") from error
        path = self.evidence_root / validated.owner_type / validated.owner_id / validated.relative_path
        if self.evidence_root.is_symlink():
            raise SafetyViolation("evidence symlink is forbidden")
        current = self.evidence_root
        for part in (validated.owner_type, validated.owner_id, *Path(validated.relative_path).parts):
            current = current / part
            if current.is_symlink():
                raise SafetyViolation("evidence symlink is forbidden")
        digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != validated.sha256:
            raise SafetyViolation("evidence checksum mismatch")
        return path


class DeploymentEvidenceResolver:
    def __init__(
        self,
        evidence_root: Path,
        *,
        max_evidence_bytes: int = 1_048_576,
        trusted_uid: int | None = None,
    ) -> None:
        self.evidence_root = evidence_root
        self.max_evidence_bytes = max_evidence_bytes
        self.trusted_uid = os.geteuid() if trusted_uid is None else trusted_uid
        self.before_leaf_open: Callable[[], None] = lambda: None
        self.after_leaf_open: Callable[[], None] = lambda: None

    def resolve(
        self, entry: DeploymentLedgerEntry, ref: EvidenceRef
    ) -> ResolvedEvidence:
        try:
            snapshot = _validated_evidence_ref_snapshot(ref)
            entry_snapshots = {
                _validated_evidence_ref_snapshot(candidate)
                for candidate in entry.evidence_refs
            }
        except (AttributeError, TypeError, ValidationError) as error:
            raise SafetyViolation("deployment evidence reference is invalid") from error
        if snapshot not in entry_snapshots:
            raise SafetyViolation("deployment evidence membership is required")
        if snapshot.owner_type != "deployment" or snapshot.owner_id != entry.deployment_id:
            raise SafetyViolation("deployment evidence owner is invalid")
        content = self._read_content(snapshot)
        return ResolvedEvidence(
            owner_type=snapshot.owner_type,
            owner_id=snapshot.owner_id,
            relative_path=snapshot.relative_path,
            sha256=snapshot.sha256,
            media_type=snapshot.media_type,
            byte_length=len(content),
            content=content,
        )

    def _read_content(self, ref: _EvidenceRefSnapshot) -> bytes:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if (
            not isinstance(nofollow, int)
            or nofollow == 0
            or not isinstance(directory, int)
            or directory == 0
            or not _open_supports_dir_fd()
        ):
            raise SafetyViolation(
                "deployment evidence platform lacks required safe-open capabilities"
            )
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | directory
            | nofollow
        )
        leaf_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
        directory_fds: list[int] = []
        leaf_fd: int | None = None
        primary_error: BaseException | None = None
        try:
            root_fd = _NATIVE_OPEN(self.evidence_root, directory_flags)
            directory_fds.append(root_fd)
            self._require_trusted_directory(os.fstat(root_fd))
            parts = (ref.owner_type, ref.owner_id, *Path(ref.relative_path).parts)
            for part in parts[:-1]:
                next_fd = _NATIVE_OPEN(
                    part, directory_flags, dir_fd=directory_fds[-1]
                )
                directory_fds.append(next_fd)
                self._require_trusted_directory(os.fstat(next_fd))
            self.before_leaf_open()
            leaf_fd = _NATIVE_OPEN(
                parts[-1], leaf_flags, dir_fd=directory_fds[-1]
            )
            self.after_leaf_open()
            before = os.fstat(leaf_fd)
            self._require_trusted_leaf(before)
            chunks: list[bytes] = []
            remaining = self.max_evidence_bytes + 1
            while remaining > 0:
                chunk = os.read(leaf_fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(leaf_fd)
            self._require_unchanged_leaf(before, after, len(content))
            if len(content) > self.max_evidence_bytes:
                raise SafetyViolation("deployment evidence size exceeds limit")
            if "sha256:" + hashlib.sha256(content).hexdigest() != ref.sha256:
                raise SafetyViolation("deployment evidence checksum mismatch")
            return content
        except SafetyViolation as error:
            primary_error = error
            raise
        except OSError as error:
            primary_error = SafetyViolation(
                "deployment evidence could not be read safely"
            )
            raise primary_error from error
        except BaseException as error:
            primary_error = error
            raise
        finally:
            close_errors: list[OSError] = []
            if leaf_fd is not None:
                try:
                    os.close(leaf_fd)
                except OSError as error:
                    close_errors.append(error)
            for directory_fd in reversed(directory_fds):
                try:
                    os.close(directory_fd)
                except OSError as error:
                    close_errors.append(error)
            if close_errors and primary_error is None:
                raise SafetyViolation(
                    "deployment evidence descriptor cleanup failed"
                ) from close_errors[0]

    def _require_trusted_directory(self, metadata: os.stat_result) -> None:
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != self.trusted_uid:
            raise SafetyViolation("deployment evidence directory is not trusted")

    def _require_trusted_leaf(self, metadata: os.stat_result) -> None:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.trusted_uid:
            raise SafetyViolation("deployment evidence file is not trusted")
        if metadata.st_size > self.max_evidence_bytes:
            raise SafetyViolation("deployment evidence size exceeds limit")

    def _require_unchanged_leaf(
        self, before: os.stat_result, after: os.stat_result, byte_length: int
    ) -> None:
        unchanged = (
            stat.S_IFMT(before.st_mode) == stat.S_IFMT(after.st_mode)
            and before.st_dev == after.st_dev
            and before.st_ino == after.st_ino
            and before.st_size == after.st_size
            and before.st_uid == after.st_uid == self.trusted_uid
            and byte_length == before.st_size
        )
        if not unchanged:
            raise SafetyViolation("deployment evidence changed while reading")

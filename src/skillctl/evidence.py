import argparse
import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from skillctl.redaction import redact_argv


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class EvidenceCleanupConflict(OSError):
    pass


class ArtifactChangedError(OSError):
    pass


class UnsupportedArtifactTypeError(OSError):
    pass


def _open_directory_chain(path: Path, *, create: bool) -> int:
    if path.is_absolute():
        current_fd = os.open("/", _DIRECTORY_OPEN_FLAGS)
        parts = path.parts[1:]
    else:
        current_fd = os.open(".", _DIRECTORY_OPEN_FLAGS)
        parts = path.parts

    try:
        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                raise ValueError("parent traversal is not allowed in evidence output paths")
            try:
                next_fd = os.open(part, _DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o755, dir_fd=current_fd)
                next_fd = os.open(part, _DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _require_trusted_output_parent(parent_fd: int) -> None:
    metadata = os.fstat(parent_fd)
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise PermissionError("evidence output parent must be owner-controlled")


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _verify_output_parent(path: Path, expected: tuple[int, int]) -> None:
    try:
        current_fd = _open_directory_chain(path, create=False)
    except OSError as error:
        raise OSError("evidence output parent changed during recording") from error
    try:
        if _identity(os.fstat(current_fd)) != expected:
            raise OSError("evidence output parent changed during recording")
    finally:
        os.close(current_fd)


def _require_owned_output_name(parent_fd: int, name: str, expected: tuple[int, int]) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise EvidenceCleanupConflict("evidence cleanup conflict: output name disappeared") from error
    if _identity(current) != expected:
        raise EvidenceCleanupConflict("evidence cleanup conflict: output name was replaced")


def _unlink_owned_output(parent_fd: int, name: str, expected: tuple[int, int]) -> None:
    _require_owned_output_name(parent_fd, name, expected)
    os.unlink(name, dir_fd=parent_fd)


def derive_passed(*, exit_code: int, expected_exit_code: int) -> bool:
    return exit_code == expected_exit_code


def _artifact_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_unchanged(
    before: os.stat_result,
    after: os.stat_result,
    relative_path: str,
) -> None:
    if _artifact_signature(before) != _artifact_signature(after):
        raise ArtifactChangedError(f"artifact changed while hashing: {relative_path}")


def _executable_mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode) & 0o111


def _read_regular_artifact(
    parent_fd: int,
    name: str,
    relative_path: str,
    before: os.stat_result,
) -> dict[str, object]:
    file_fd = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        opened = os.fstat(file_fd)
        _require_unchanged(before, opened, relative_path)
        digest = hashlib.sha256()
        byte_count = 0
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
        _require_unchanged(opened, os.fstat(file_fd), relative_path)
    finally:
        os.close(file_fd)
    _require_unchanged(
        before,
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False),
        relative_path,
    )
    return {
        "path": relative_path,
        "type": "file",
        "byte_count": byte_count,
        "sha256": digest.hexdigest(),
        "executable_mode": _executable_mode(before),
    }


def _walk_artifact_directory(
    directory_fd: int,
    relative_path: str,
    opened: os.stat_result,
    entries: list[dict[str, object]],
) -> None:
    entries.append(
        {
            "path": relative_path,
            "type": "directory",
            "executable_mode": _executable_mode(opened),
        }
    )
    before_list = os.fstat(directory_fd)
    _require_unchanged(opened, before_list, relative_path)
    names = sorted(os.listdir(directory_fd))
    for name in names:
        if name == ".git":
            continue
        child_path = name if relative_path == "." else f"{relative_path}/{name}"
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
            try:
                child_opened = os.fstat(child_fd)
                _require_unchanged(before, child_opened, child_path)
                _walk_artifact_directory(child_fd, child_path, child_opened, entries)
                _require_unchanged(child_opened, os.fstat(child_fd), child_path)
            finally:
                os.close(child_fd)
            _require_unchanged(
                before,
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                child_path,
            )
        elif stat.S_ISREG(before.st_mode):
            entries.append(_read_regular_artifact(directory_fd, name, child_path, before))
        elif stat.S_ISLNK(before.st_mode):
            target = os.readlink(name, dir_fd=directory_fd)
            _require_unchanged(
                before,
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                child_path,
            )
            entries.append({"path": child_path, "type": "symlink", "target": target})
        else:
            raise UnsupportedArtifactTypeError(f"unsupported artifact type: {child_path}")
    _require_unchanged(before_list, os.fstat(directory_fd), relative_path)


def artifact_digest(path: Path) -> str:
    absolute_path = path if path.is_absolute() else Path.cwd() / path
    parent_fd = _open_directory_chain(absolute_path.parent, create=False)
    try:
        before = os.stat(absolute_path.name, dir_fd=parent_fd, follow_symlinks=False)
        entries: list[dict[str, object]] = []
        if stat.S_ISDIR(before.st_mode):
            directory_fd = os.open(absolute_path.name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
            try:
                opened = os.fstat(directory_fd)
                _require_unchanged(before, opened, ".")
                _walk_artifact_directory(directory_fd, ".", opened, entries)
                _require_unchanged(opened, os.fstat(directory_fd), ".")
            finally:
                os.close(directory_fd)
            _require_unchanged(
                before,
                os.stat(absolute_path.name, dir_fd=parent_fd, follow_symlinks=False),
                ".",
            )
        elif stat.S_ISREG(before.st_mode):
            entries.append(_read_regular_artifact(parent_fd, absolute_path.name, ".", before))
        elif stat.S_ISLNK(before.st_mode):
            target = os.readlink(absolute_path.name, dir_fd=parent_fd)
            _require_unchanged(
                before,
                os.stat(absolute_path.name, dir_fd=parent_fd, follow_symlinks=False),
                ".",
            )
            entries.append({"path": ".", "type": "symlink", "target": target})
        else:
            raise UnsupportedArtifactTypeError("unsupported artifact type: .")
    finally:
        os.close(parent_fd)
    manifest = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(manifest).hexdigest()


def finalize_record(output_fd: int, encoded: bytes) -> None:
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(output_fd, remaining)
        if written <= 0:
            raise OSError("evidence write made no progress")
        remaining = remaining[written:]
    os.fchmod(output_fd, 0o444)
    os.fsync(output_fd)


def verify_record_digest(record: dict[str, object]) -> bool:
    claimed = record.get("record_sha256")
    if not isinstance(claimed, str):
        return False
    content = {key: value for key, value in record.items() if key != "record_sha256"}
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == claimed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m skillctl.evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--out", required=True, type=Path)
    run_parser.add_argument("--expected-exit-code", default=0, type=int)
    run_parser.add_argument("--artifact", action="append", default=[], type=Path)
    run_parser.add_argument("child_argv", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    child_argv = args.child_argv
    if child_argv[:1] == ["--"]:
        child_argv = child_argv[1:]
    if not child_argv:
        run_parser.error("child argv is required after --")

    parent_fd = _open_directory_chain(args.out.parent, create=True)
    try:
        _require_trusted_output_parent(parent_fd)
        parent_identity = _identity(os.fstat(parent_fd))
    except BaseException:
        os.close(parent_fd)
        raise
    try:
        output_fd = os.open(
            args.out.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
    except FileExistsError:
        os.close(parent_fd)
        return 2
    except BaseException:
        os.close(parent_fd)
        raise
    try:
        output_identity = _identity(os.fstat(output_fd))
    except BaseException:
        try:
            os.close(output_fd)
        finally:
            os.close(parent_fd)
        raise

    try:
        started_at = datetime.now(UTC)
        completed = subprocess.run(child_argv, check=False, capture_output=True)
        ended_at = datetime.now(UTC)
        passed = derive_passed(
            exit_code=completed.returncode,
            expected_exit_code=args.expected_exit_code,
        )
        record = {
            "schema_version": "1.0",
            "argv": redact_argv(child_argv),
            "cwd": os.getcwd(),
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "ended_at": ended_at.isoformat().replace("+00:00", "Z"),
            "exit_code": completed.returncode,
            "expected_exit_code": args.expected_exit_code,
            "passed": passed,
            "stdout": {
                "byte_count": len(completed.stdout),
                "sha256": hashlib.sha256(completed.stdout).hexdigest(),
            },
            "stderr": {
                "byte_count": len(completed.stderr),
                "sha256": hashlib.sha256(completed.stderr).hexdigest(),
            },
            "artifacts": [
                {"path": str(path), "sha256": artifact_digest(path)}
                for path in sorted(args.artifact, key=lambda item: str(item))
            ],
        }
        digest_input = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        record["record_sha256"] = hashlib.sha256(digest_input).hexdigest()
        encoded = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
        finalize_record(output_fd, encoded)
        _require_owned_output_name(parent_fd, args.out.name, output_identity)
        _verify_output_parent(args.out.parent, parent_identity)
    except BaseException as error:
        try:
            os.close(output_fd)
        finally:
            try:
                _unlink_owned_output(parent_fd, args.out.name, output_identity)
            except EvidenceCleanupConflict as cleanup_error:
                raise cleanup_error from error
            finally:
                os.close(parent_fd)
        raise
    else:
        os.close(output_fd)
        os.close(parent_fd)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

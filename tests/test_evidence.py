import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from skillctl.evidence import (
    ArtifactChangedError,
    UnsupportedArtifactTypeError,
    artifact_digest,
    derive_passed,
    finalize_record,
    main,
    verify_record_digest,
)


def run_recorder(output: Path, *child_argv: str, extra: list[str] | None = None):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "skillctl.evidence",
            "run",
            "--out",
            str(output),
            *(extra or []),
            "--",
            *child_argv,
        ],
        check=False,
    )


def test_evidence_pass_is_derived_only_from_expected_exit_code() -> None:
    assert derive_passed(exit_code=0, expected_exit_code=0) is True
    assert derive_passed(exit_code=1, expected_exit_code=0) is False


def test_run_records_exact_child_argv(tmp_path) -> None:
    output = tmp_path / "record.json"
    child_argv = [sys.executable, "-c", "print('hello')"]

    result = run_recorder(output, *child_argv)

    assert result.returncode == 0
    assert json.loads(output.read_text())["argv"] == child_argv


@pytest.mark.parametrize(
    ("sensitive_arguments", "expected_arguments"),
    (
        (("--token", "synthetic-credential-value"), ("--token", "<redacted>")),
        (
            ("--password=synthetic-credential-value",),
            ("--password=<redacted>",),
        ),
        (("ghp_" + "syntheticcredentialvalue",), ("<redacted>",)),
        (("Bearer synthetic-credential-value",), ("Bearer <redacted>",)),
    ),
    ids=("flag-value", "equals-value", "common-token", "bearer"),
)
def test_run_redacts_sensitive_child_argv(
    tmp_path: Path,
    sensitive_arguments: tuple[str, ...],
    expected_arguments: tuple[str, ...],
) -> None:
    output = tmp_path / "record.json"
    prefix = [sys.executable, "-c", "pass"]

    result = run_recorder(output, *prefix, *sensitive_arguments)

    assert result.returncode == 0
    assert json.loads(output.read_text())["argv"] == [*prefix, *expected_arguments]


def test_run_redacts_sensitive_environment_value_but_child_receives_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "record.json"
    child_output = tmp_path / "child-output.txt"
    synthetic_value = "synthetic-environment-credential"
    monkeypatch.setenv("SYNTHETIC_API_TOKEN", synthetic_value)
    child_argv = [
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text(sys.argv[2])",
        str(child_output),
        synthetic_value,
    ]

    result = run_recorder(output, *child_argv)

    assert result.returncode == 0
    assert child_output.read_text() == synthetic_value
    assert json.loads(output.read_text())["argv"] == [*child_argv[:-1], "<redacted>"]


def test_run_records_child_cwd(tmp_path) -> None:
    output = tmp_path / "record.json"

    result = run_recorder(output, sys.executable, "-c", "pass")

    assert result.returncode == 0
    assert json.loads(output.read_text())["cwd"] == str(Path.cwd())


def test_run_records_exit_derived_execution_metadata(tmp_path) -> None:
    output = tmp_path / "record.json"

    result = run_recorder(
        output,
        sys.executable,
        "-c",
        "raise SystemExit(7)",
        extra=["--expected-exit-code", "7"],
    )

    record = json.loads(output.read_text())
    assert result.returncode == 0
    assert record["schema_version"] == "1.0"
    assert record["exit_code"] == 7
    assert record["expected_exit_code"] == 7
    assert record["passed"] is True
    assert record["started_at"].endswith("Z")
    assert record["ended_at"].endswith("Z")
    assert record["started_at"] <= record["ended_at"]


def test_run_records_stdout_and_stderr_byte_digests(tmp_path) -> None:
    output = tmp_path / "record.json"
    stdout = b"hello\n"
    stderr = b"problem\n"

    result = run_recorder(
        output,
        sys.executable,
        "-c",
        "import sys; sys.stdout.buffer.write(b'hello\\n'); "
        "sys.stderr.buffer.write(b'problem\\n')",
    )

    record = json.loads(output.read_text())
    assert result.returncode == 0
    assert record["stdout"] == {
        "byte_count": len(stdout),
        "sha256": hashlib.sha256(stdout).hexdigest(),
    }
    assert record["stderr"] == {
        "byte_count": len(stderr),
        "sha256": hashlib.sha256(stderr).hexdigest(),
    }


def test_directory_artifact_digest_covers_content_mode_and_symlink_but_not_git(tmp_path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root in (first, second):
        root.mkdir()
        (root / "tool").write_bytes(b"payload")
        (root / "tool").chmod(0o755)
        (root / "link").symlink_to("tool")
        (root / ".git").mkdir()
        (root / ".git" / "ignored").write_bytes(b"different later")

    baseline = artifact_digest(first)
    assert baseline == artifact_digest(second)
    assert baseline

    (second / ".git" / "ignored").write_bytes(b"changed")
    assert artifact_digest(second) == baseline
    (second / "tool").chmod(0o644)
    assert artifact_digest(second) != baseline
    (second / "tool").chmod(0o755)
    (second / "link").unlink()
    (second / "link").symlink_to("other")
    assert artifact_digest(second) != baseline


def test_directory_artifact_digest_includes_root_empty_dirs_and_directory_modes(tmp_path) -> None:
    root = tmp_path / "artifact"
    nested = root / "nested"
    empty = nested / "empty"
    empty.mkdir(parents=True)
    root.chmod(0o755)
    nested.chmod(0o755)

    baseline = artifact_digest(root)
    root.chmod(0o700)
    assert artifact_digest(root) != baseline
    root.chmod(0o755)
    nested.chmod(0o700)
    assert artifact_digest(root) != baseline

    nested.chmod(0o755)
    empty.rmdir()
    assert artifact_digest(root) != baseline


def test_artifact_digest_rejects_fifo_and_socket_entries(tmp_path) -> None:
    fifo_root = tmp_path / "fifo-root"
    fifo_root.mkdir()
    os.mkfifo(fifo_root / "pipe")
    with pytest.raises(UnsupportedArtifactTypeError, match="pipe"):
        artifact_digest(fifo_root)

    with tempfile.TemporaryDirectory(prefix="skillctl-", dir="/private/tmp") as directory:
        socket_root = Path(directory)
        unix_socket = socket.socket(socket.AF_UNIX)
        try:
            unix_socket.bind(str(socket_root / "service.sock"))
            with pytest.raises(UnsupportedArtifactTypeError, match="service.sock"):
                artifact_digest(socket_root)
        finally:
            unix_socket.close()


def test_artifact_digest_does_not_follow_directory_symlinks(tmp_path) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    first_target = tmp_path / "first-target"
    first_target.mkdir()
    (first_target / "content").write_text("first")
    second_target = tmp_path / "second-target"
    second_target.mkdir()
    link = artifact / "linked-directory"
    link.symlink_to(first_target, target_is_directory=True)

    baseline = artifact_digest(artifact)
    (first_target / "added-later").write_text("must not be hashed")
    assert artifact_digest(artifact) == baseline

    link.unlink()
    link.symlink_to(second_target, target_is_directory=True)
    assert artifact_digest(artifact) != baseline


def test_artifact_digest_rejects_regular_file_mutation_during_read(tmp_path, monkeypatch) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"original")
    real_read = os.read
    mutated = False

    def mutating_read(fd: int, length: int) -> bytes:
        nonlocal mutated
        chunk = real_read(fd, length)
        if chunk and not mutated:
            mutated = True
            artifact.write_bytes(b"replacement")
        return chunk

    monkeypatch.setattr("skillctl.evidence.os.read", mutating_read)

    with pytest.raises(ArtifactChangedError, match="artifact changed"):
        artifact_digest(artifact)


def test_artifact_digest_rejects_directory_mutation_after_listing(tmp_path, monkeypatch) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "original").write_text("content")
    real_listdir = os.listdir
    mutated = False

    def mutating_listdir(path) -> list[str]:
        nonlocal mutated
        names = real_listdir(path)
        if not mutated:
            mutated = True
            (artifact / "added-later").write_text("content")
        return names

    monkeypatch.setattr("skillctl.evidence.os.listdir", mutating_listdir)

    with pytest.raises(ArtifactChangedError, match="artifact changed"):
        artifact_digest(artifact)


def test_run_records_multiple_artifacts_sorted_by_path(tmp_path) -> None:
    output = tmp_path / "record.json"
    later = tmp_path / "z.txt"
    earlier = tmp_path / "a.txt"
    later.write_text("later")
    earlier.write_text("earlier")

    result = run_recorder(
        output,
        sys.executable,
        "-c",
        "pass",
        extra=["--artifact", str(later), "--artifact", str(earlier)],
    )

    record = json.loads(output.read_text())
    assert result.returncode == 0
    assert record["artifacts"] == [
        {"path": str(earlier), "sha256": artifact_digest(earlier)},
        {"path": str(later), "sha256": artifact_digest(later)},
    ]


def test_run_rejects_existing_output_before_executing_child(tmp_path) -> None:
    output = tmp_path / "record.json"
    marker = tmp_path / "child-ran"
    output.write_text("original")

    result = run_recorder(
        output,
        sys.executable,
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
    )

    assert result.returncode != 0
    assert output.read_text() == "original"
    assert not marker.exists()


def test_finalize_record_fsyncs_and_sets_readonly_mode(tmp_path, monkeypatch) -> None:
    output = tmp_path / "record.json"
    output_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    fsynced: list[int] = []
    monkeypatch.setattr("skillctl.evidence.os.fsync", fsynced.append)

    try:
        finalize_record(output_fd, b"evidence")
        mode = os.fstat(output_fd).st_mode & 0o777
    finally:
        os.close(output_fd)

    assert fsynced == [output_fd]
    assert mode == 0o444


def test_finalize_record_retries_partial_writes(tmp_path, monkeypatch) -> None:
    output = tmp_path / "record.json"
    output_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    payload = b"partial-write-evidence"
    real_write = os.write
    write_sizes: list[int] = []

    def partial_write(fd, data):
        chunk = bytes(data[:3])
        write_sizes.append(len(chunk))
        return real_write(fd, chunk)

    monkeypatch.setattr("skillctl.evidence.os.write", partial_write)

    try:
        finalize_record(output_fd, payload)
    finally:
        os.close(output_fd)

    assert output.read_bytes() == payload
    assert len(write_sizes) > 1


def test_finalize_record_rejects_zero_length_write(tmp_path, monkeypatch) -> None:
    output = tmp_path / "record.json"
    output_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    calls = 0

    def zero_then_fail(fd, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return 0
        raise RuntimeError("write retried without progress")

    monkeypatch.setattr("skillctl.evidence.os.write", zero_then_fail)

    try:
        with pytest.raises(OSError, match="made no progress"):
            finalize_record(output_fd, b"evidence")
    finally:
        os.close(output_fd)


def test_run_records_a_verifiable_evidence_record_digest(tmp_path) -> None:
    output = tmp_path / "record.json"

    result = run_recorder(output, sys.executable, "-c", "pass")

    record = json.loads(output.read_text())
    assert result.returncode == 0
    assert len(record["record_sha256"]) == 64
    assert verify_record_digest(record) is True
    record["cwd"] = "/tampered"
    assert verify_record_digest(record) is False


def test_run_rejects_passed_input_without_executing_child(tmp_path) -> None:
    output = tmp_path / "record.json"
    marker = tmp_path / "child-ran"

    result = run_recorder(
        output,
        sys.executable,
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
        extra=["--passed", "true"],
    )

    assert result.returncode == 2
    assert not output.exists()
    assert not marker.exists()


def test_main_closes_fd_and_removes_placeholder_when_execution_raises(tmp_path, monkeypatch) -> None:
    output = tmp_path / "record.json"
    opened_fds: list[int] = []
    real_open = os.open

    def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        opened_fds.append(fd)
        return fd

    def fail_execution(*args, **kwargs):
        raise OSError("execution failed")

    monkeypatch.setattr("skillctl.evidence.os.open", tracking_open)
    monkeypatch.setattr("skillctl.evidence.subprocess.run", fail_execution)

    with pytest.raises(OSError, match="execution failed"):
        main(["run", "--out", str(output), "--", "child"])

    for fd in set(opened_fds):
        with pytest.raises(OSError):
            os.fstat(fd)
    assert not output.exists()


def test_main_closes_output_fd_and_preserves_placeholder_when_initial_fstat_fails(
    tmp_path, monkeypatch
) -> None:
    output = tmp_path / "record.json"
    output_fd: int | None = None
    real_open = os.open
    real_fstat = os.fstat

    def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal output_fd
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == output.name and flags & os.O_EXCL:
            output_fd = fd
        return fd

    def failing_fstat(fd: int):
        if fd == output_fd:
            raise OSError("initial output fstat failed")
        return real_fstat(fd)

    monkeypatch.setattr("skillctl.evidence.os.open", tracking_open)
    monkeypatch.setattr("skillctl.evidence.os.fstat", failing_fstat)

    with pytest.raises(OSError, match="initial output fstat failed"):
        main(["run", "--out", str(output), "--", "child"])

    assert output_fd is not None
    with pytest.raises(OSError):
        real_fstat(output_fd)
    assert output.read_bytes() == b""


def test_main_preserves_replacement_when_initial_output_fstat_fails(
    tmp_path, monkeypatch
) -> None:
    output = tmp_path / "record.json"
    replacement = b"replacement-owned-by-cooperating-process"
    output_fd: int | None = None
    real_open = os.open
    real_fstat = os.fstat

    def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal output_fd
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == output.name and flags & os.O_EXCL:
            output_fd = fd
        return fd

    def replacing_fstat(fd: int):
        if fd == output_fd:
            output.unlink()
            output.write_bytes(replacement)
            raise OSError("initial output fstat failed after replacement")
        return real_fstat(fd)

    monkeypatch.setattr("skillctl.evidence.os.open", tracking_open)
    monkeypatch.setattr("skillctl.evidence.os.fstat", replacing_fstat)

    with pytest.raises(OSError, match="initial output fstat failed after replacement"):
        main(["run", "--out", str(output), "--", "child"])

    assert output_fd is not None
    with pytest.raises(OSError):
        real_fstat(output_fd)
    assert output.read_bytes() == replacement


def test_run_rejects_symlinked_output_parent(tmp_path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    output = linked_parent / "record.json"

    result = run_recorder(output, sys.executable, "-c", "pass")

    assert result.returncode != 0
    assert not (real_parent / "record.json").exists()


def test_run_rejects_untrusted_output_parent(tmp_path) -> None:
    untrusted_parent = tmp_path / "untrusted"
    untrusted_parent.mkdir()
    untrusted_parent.chmod(0o777)
    output = untrusted_parent / "record.json"

    result = run_recorder(output, sys.executable, "-c", "pass")

    assert result.returncode != 0
    assert not output.exists()


def test_main_detects_output_parent_replacement(tmp_path, monkeypatch) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    displaced_parent = tmp_path / "displaced"
    output = parent / "record.json"

    def replace_parent(args, **kwargs):
        parent.rename(displaced_parent)
        parent.mkdir()
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr("skillctl.evidence.subprocess.run", replace_parent)

    with pytest.raises(OSError, match="output parent changed"):
        main(["run", "--out", str(output), "--", "child"])

    assert parent.is_dir()
    assert not output.exists()
    assert not (displaced_parent / "record.json").exists()


def test_main_preserves_replacement_when_exception_cleanup_conflicts(tmp_path, monkeypatch) -> None:
    output = tmp_path / "record.json"
    replacement = b"replacement-owned-by-someone-else"

    def replace_output_then_fail(*args, **kwargs):
        output.unlink()
        output.write_bytes(replacement)
        raise OSError("execution failed")

    monkeypatch.setattr("skillctl.evidence.subprocess.run", replace_output_then_fail)

    with pytest.raises(OSError, match="cleanup conflict"):
        main(["run", "--out", str(output), "--", "child"])

    assert output.read_bytes() == replacement

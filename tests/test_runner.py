from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

import pytest

from skillctl.errors import AdapterFailure, SafetyViolation
from skillctl.runner import CommandRunner


def _executable(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path.resolve()


def test_runner_uses_no_shell_and_an_isolated_controlled_environment(
    tmp_path: Path,
) -> None:
    executable = _executable(
        tmp_path,
        "safe-command",
        """import json, os
print(json.dumps({"environment": dict(os.environ)}))
""",
    )

    result = CommandRunner((executable,)).run(executable, (), cwd=tmp_path)

    environment = result.payload["environment"]
    environment.pop("__CF_USER_TEXT_ENCODING", None)
    assert environment == {
        "HOME": str(tmp_path / ".runtime-home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
        "TMPDIR": str(tmp_path / ".runtime-tmp"),
    }
    assert stat.S_IMODE((tmp_path / ".runtime-home").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / ".runtime-tmp").stat().st_mode) == 0o700


def test_runner_rejects_executable_outside_allowlist(tmp_path: Path) -> None:
    allowed = _executable(tmp_path, "allowed", "print('{}')\n")
    rejected = _executable(tmp_path, "rejected", "print('{}')\n")

    with pytest.raises(SafetyViolation, match="allowlist"):
        CommandRunner((allowed,)).run(rejected, (), cwd=tmp_path)


@pytest.mark.parametrize("token", (";", "|", "&&", "$(id)", "`id`", "\n"))
def test_runner_rejects_shell_tokens(tmp_path: Path, token: str) -> None:
    executable = _executable(tmp_path, "safe-command", "print('{}')\n")

    with pytest.raises(SafetyViolation, match="shell token"):
        CommandRunner((executable,)).run(executable, (token,), cwd=tmp_path)


def test_runner_rejects_secret_named_environment_entries(tmp_path: Path) -> None:
    executable = _executable(tmp_path, "safe-command", "print('{}')\n")

    with pytest.raises(SafetyViolation, match="environment"):
        CommandRunner((executable,), extra_environment={"API_TOKEN": "not-logged"})


def test_runner_converts_timeout_to_fail_closed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path, "safe-command", "print('{}')\n")

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="hidden", timeout=30)

    monkeypatch.setattr(subprocess, "run", timeout)

    with pytest.raises(AdapterFailure, match="timed out") as captured:
        CommandRunner((executable,)).run(executable, (), cwd=tmp_path)
    assert captured.value.__cause__ is None
    assert str(tmp_path) not in str(captured.value)


def test_runner_converts_os_error_without_retaining_sensitive_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path, "safe-command", "print('{}')\n")

    def fail(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError(f"secret stream at {tmp_path}")

    monkeypatch.setattr(subprocess, "run", fail)

    with pytest.raises(AdapterFailure, match="could not be executed") as captured:
        CommandRunner((executable,)).run(executable, (), cwd=tmp_path)
    assert captured.value.__cause__ is None
    assert "secret stream" not in str(captured.value)
    assert str(tmp_path) not in str(captured.value)


@pytest.mark.parametrize(
    ("body", "message"),
    (
        ("raise SystemExit(7)\n", "non-zero"),
        ("print('not json')\n", "valid JSON"),
        ("print('{} trailing garbage')\n", "valid JSON"),
    ),
)
def test_runner_rejects_failed_or_non_json_commands(
    tmp_path: Path, body: str, message: str
) -> None:
    executable = _executable(tmp_path, "safe-command", body)

    with pytest.raises(AdapterFailure, match=message) as captured:
        CommandRunner((executable,)).run(executable, (), cwd=tmp_path)
    assert captured.value.__cause__ is None
    assert str(tmp_path) not in str(captured.value)
    assert "not json" not in str(captured.value)


def test_runner_returns_parsed_json_without_raw_streams(tmp_path: Path) -> None:
    executable = _executable(
        tmp_path,
        "safe-command",
        f"print({json.dumps(json.dumps({'ok': True}))})\n",
    )

    assert CommandRunner((executable,)).run(executable, (), cwd=tmp_path).payload == {
        "ok": True
    }

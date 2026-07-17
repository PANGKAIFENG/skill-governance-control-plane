from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from pydantic import JsonValue

from skillctl.errors import AdapterFailure, SafetyViolation
from skillctl.models import is_sensitive_name

_TRUSTED_PATH = "/opt/homebrew/bin:/usr/bin:/bin"
_SHELL_TOKENS = (";", "|", "&", "`", "$", "<", ">", "\n", "\r")


@dataclass(frozen=True)
class CommandResult:
    payload: JsonValue


class Runner(Protocol):
    def run(
        self, executable: Path, args: tuple[str, ...], *, cwd: Path
    ) -> CommandResult: ...


class CommandRunner:
    def __init__(
        self,
        allowed_executables: tuple[Path, ...],
        *,
        extra_environment: Mapping[str, str] | None = None,
    ) -> None:
        if not allowed_executables:
            raise SafetyViolation("command executable allowlist is required")
        if extra_environment:
            if any(is_sensitive_name(name) for name in extra_environment):
                raise SafetyViolation("command environment contains a forbidden name")
            raise SafetyViolation("additional command environment is forbidden")
        self._allowed_executables = frozenset(
            path.resolve(strict=False) for path in allowed_executables
        )

    def run(
        self, executable: Path, args: tuple[str, ...], *, cwd: Path
    ) -> CommandResult:
        resolved_executable = executable.resolve(strict=False)
        if resolved_executable not in self._allowed_executables:
            raise SafetyViolation("command executable is not in the allowlist")
        if any(token in argument for argument in args for token in _SHELL_TOKENS):
            raise SafetyViolation("command argument contains a forbidden shell token")

        resolved_cwd = cwd.resolve(strict=False)
        if not resolved_cwd.is_dir():
            raise SafetyViolation("command working directory is invalid")
        runtime_home = resolved_cwd / ".runtime-home"
        runtime_tmp = resolved_cwd / ".runtime-tmp"
        for directory in (runtime_home, runtime_tmp):
            if directory.is_symlink():
                raise SafetyViolation("command runtime directory is invalid")
            directory.mkdir(mode=0o700, exist_ok=True)
            directory.chmod(0o700)

        environment = {
            "PATH": _TRUSTED_PATH,
            "HOME": str(runtime_home),
            "TMPDIR": str(runtime_tmp),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
        }
        try:
            completed = subprocess.run(
                (str(resolved_executable), *args),
                cwd=resolved_cwd,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            raise AdapterFailure("adapter command timed out") from None
        except OSError:
            raise AdapterFailure("adapter command could not be executed") from None
        if completed.returncode != 0:
            raise AdapterFailure("adapter command returned a non-zero exit status")
        try:
            payload = cast(JsonValue, json.loads(completed.stdout))
        except (json.JSONDecodeError, UnicodeError):
            raise AdapterFailure("adapter command did not return valid JSON") from None
        return CommandResult(payload=payload)

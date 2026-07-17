from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]
from pydantic import JsonValue

from skillctl.errors import AdapterFailure, SafetyViolation
from skillctl.runner import CommandResult, Runner
from skillctl.runtime_inventory.models import (
    RuntimeInventorySnapshot,
    RuntimeIgnoredSkill,
    RuntimeLocationKind,
    RuntimeSkillAsset,
    RuntimeSkillInstance,
    RuntimeSkillStatus,
    RuntimeTarget,
    ScanLimits,
)

VERSION = ("version",)
STATUS = ("status", "--json", "--no-tui")
LIST = ("list", "--json", "--no-tui")
TARGET_LIST = ("target", "list", "--json", "--no-tui")

_ALLOWED_COMMANDS = frozenset((VERSION, STATUS, LIST, TARGET_LIST))
_IGNORED_DIRECTORIES = frozenset((".git", "__pycache__"))
_IGNORED_FILES = frozenset((".DS_Store",))
_VERSION_PATTERN = re.compile(r"\bv?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b")
_TRUSTED_PATH = "/opt/homebrew/bin:/usr/bin:/bin"
_COMMAND_TIMEOUT_SECONDS = 30
_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class _ScannedSkill:
    name: str
    description: str | None
    instance: RuntimeSkillInstance


class SkillshareInventoryCommandRunner:
    def __init__(
        self,
        allowed_executables: tuple[Path, ...],
        *,
        trusted_home: Path | None = None,
    ) -> None:
        if not allowed_executables:
            raise SafetyViolation("Skillshare executable allowlist is required")
        self._allowed_executables = frozenset(
            executable.resolve(strict=False) for executable in allowed_executables
        )
        home = trusted_home if trusted_home is not None else Path.home()
        if not home.is_absolute() or home.is_symlink() or not home.is_dir():
            raise SafetyViolation("Skillshare trusted home is invalid")
        try:
            self._trusted_home = home.resolve(strict=True)
        except (OSError, RuntimeError):
            raise SafetyViolation("Skillshare trusted home is invalid") from None

    def run(
        self,
        executable: Path,
        args: tuple[str, ...],
        *,
        cwd: Path,
    ) -> CommandResult:
        if args not in _ALLOWED_COMMANDS:
            raise SafetyViolation("Skillshare inventory command is not allowed")
        resolved_executable = executable.resolve(strict=False)
        if (
            resolved_executable not in self._allowed_executables
            or not resolved_executable.is_file()
        ):
            raise SafetyViolation("Skillshare executable is not in the allowlist")
        resolved_cwd = cwd.resolve(strict=False)
        if not resolved_cwd.is_dir() or cwd.is_symlink():
            raise SafetyViolation("Skillshare command working directory is invalid")

        with tempfile.TemporaryDirectory(prefix="skillctl-inventory-") as runtime_tmp:
            environment = {
                "PATH": _TRUSTED_PATH,
                "HOME": str(self._trusted_home),
                "TMPDIR": runtime_tmp,
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
                    timeout=_COMMAND_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                raise AdapterFailure("Skillshare inventory command timed out") from None
            except (OSError, UnicodeError):
                raise AdapterFailure("Skillshare inventory command could not be executed") from None
        if completed.returncode != 0:
            raise AdapterFailure(
                "Skillshare inventory command returned a non-zero exit status"
            )
        if args == VERSION:
            return CommandResult(payload=completed.stdout)
        try:
            payload = cast(JsonValue, json.loads(completed.stdout))
        except (json.JSONDecodeError, UnicodeError):
            raise AdapterFailure(
                "Skillshare inventory command did not return valid JSON"
            ) from None
        return CommandResult(payload=payload)


class SkillshareInventoryDiscovery:
    def __init__(
        self,
        command_runner: Runner | None = None,
        *,
        skillshare_executable: Path = Path("skillshare"),
        cwd: Path | None = None,
        limits: ScanLimits = ScanLimits(),
    ) -> None:
        self._runner = (
            command_runner
            if command_runner is not None
            else SkillshareInventoryCommandRunner((skillshare_executable,))
        )
        self._executable = skillshare_executable
        self._cwd = cwd if cwd is not None else Path.cwd()
        self._limits = limits

    def discover(self) -> RuntimeInventorySnapshot:
        version_payload = self._run(VERSION)
        status_payload = self._run(STATUS)
        list_payload = self._run(LIST)
        target_list_payload = self._run(TARGET_LIST)

        status = _require_mapping(status_payload, "status")
        source = _require_mapping(status.get("source"), "status source")
        source_path = _require_absolute_directory(source.get("path"), "source path")
        targets = _parse_targets(target_list_payload)

        warnings: list[str] = []
        ignored = _parse_ignored(source_path, source, list_payload)
        shared_skills = self._scan_shared(source_path, list_payload, warnings)
        target_skills, targets = self._scan_targets(targets, warnings)
        ignored_names = frozenset(item.name for item in ignored)
        shared_skills = tuple(
            skill for skill in shared_skills if skill.name not in ignored_names
        )
        target_skills = tuple(
            skill for skill in target_skills if skill.name not in ignored_names
        )
        assets = _aggregate_assets(shared_skills, target_skills, targets)
        skillshare_version = _parse_version(version_payload, status.get("version"))

        return RuntimeInventorySnapshot(
            generated_at=datetime.now(UTC),
            skillshare_version=skillshare_version,
            source_path=str(source_path),
            targets=targets,
            assets=assets,
            ignored=ignored,
            warnings=tuple(warnings),
        )

    def _run(self, args: tuple[str, ...]) -> JsonValue:
        if args not in _ALLOWED_COMMANDS:
            raise SafetyViolation("Skillshare inventory command is not allowed")
        return self._runner.run(self._executable, args, cwd=self._cwd).payload

    def _scan_shared(
        self,
        source_path: Path,
        list_payload: JsonValue,
        warnings: list[str],
    ) -> tuple[_ScannedSkill, ...]:
        entries = _require_sequence(list_payload, "skill list")
        scanned: list[_ScannedSkill] = []
        for raw_entry in entries:
            entry = _require_mapping(raw_entry, "skill list entry")
            if entry.get("kind") != "skill" or entry.get("disabled") is True:
                continue
            relative_path = _require_relative_path(entry.get("relPath"), "skill relPath")
            skill_path = source_path.joinpath(*relative_path.parts)
            if _has_intermediate_symlink(source_path, relative_path):
                warnings.append(f"{skill_path}: shared skill path has an intermediate symlink")
                continue
            if not skill_path.is_dir():
                warnings.append(f"{skill_path}: shared skill directory is unavailable")
                continue
            skill = _scan_skill(
                skill_path,
                location_kind="shared",
                target_name=None,
                distribution_mode="shared",
                limits=self._limits,
            )
            scanned.append(skill)
            warnings.extend(skill.instance.scan_warnings)
        return tuple(scanned)

    def _scan_targets(
        self,
        targets: tuple[RuntimeTarget, ...],
        warnings: list[str],
    ) -> tuple[tuple[_ScannedSkill, ...], tuple[RuntimeTarget, ...]]:
        scanned: list[_ScannedSkill] = []
        scanned_targets: list[RuntimeTarget] = []
        for target in targets:
            root = Path(target.path)
            if not root.is_dir():
                warnings.append(f"{root}: target directory is unavailable")
                scanned_targets.append(target.model_copy(update={"readable": False}))
                continue
            try:
                children = sorted(root.iterdir(), key=lambda path: path.name)
            except OSError:
                warnings.append(f"{root}: target directory is unreadable")
                scanned_targets.append(target.model_copy(update={"readable": False}))
                continue
            scanned_targets.append(target)
            for skill_path in children:
                if (
                    skill_path.name in _IGNORED_DIRECTORIES
                    or not skill_path.is_dir()
                ):
                    continue
                skill_file = skill_path / "SKILL.md"
                if not skill_file.is_file() and not skill_file.is_symlink():
                    continue
                skill = _scan_skill(
                    skill_path,
                    location_kind="target",
                    target_name=target.name,
                    distribution_mode=target.mode,
                    limits=self._limits,
                )
                scanned.append(skill)
                warnings.extend(skill.instance.scan_warnings)
        return tuple(scanned), tuple(scanned_targets)


def discover_runtime_inventory(
    command_runner: Runner | None = None,
    *,
    skillshare_executable: Path = Path("skillshare"),
    cwd: Path | None = None,
    limits: ScanLimits = ScanLimits(),
) -> RuntimeInventorySnapshot:
    return SkillshareInventoryDiscovery(
        command_runner,
        skillshare_executable=skillshare_executable,
        cwd=cwd,
        limits=limits,
    ).discover()


def _parse_targets(payload: JsonValue) -> tuple[RuntimeTarget, ...]:
    document = _require_mapping(payload, "target list")
    entries = _require_sequence(document.get("targets"), "target list targets")
    targets: list[RuntimeTarget] = []
    for raw_entry in entries:
        entry = _require_mapping(raw_entry, "target list entry")
        name = _require_string(entry.get("name"), "target name")
        path = _require_absolute_path(entry.get("path"), "target path")
        mode = _require_string(entry.get("mode"), "target mode")
        targets.append(
            RuntimeTarget(
                name=name,
                path=str(path),
                mode=mode,
                include=_string_tuple(entry.get("include"), "target include"),
                exclude=_string_tuple(entry.get("exclude"), "target exclude"),
            )
        )
    return tuple(sorted(targets, key=lambda target: target.name))


def _parse_ignored(
    source_path: Path,
    source: Mapping[str, JsonValue],
    list_payload: JsonValue,
) -> tuple[RuntimeIgnoredSkill, ...]:
    ignored: dict[str, RuntimeIgnoredSkill] = {}

    skillignore = source.get("skillignore")
    if isinstance(skillignore, Mapping):
        entries = _require_sequence(
            skillignore.get("ignored_skills", []), "ignored skill list"
        )
        for raw_entry in entries:
            if isinstance(raw_entry, str):
                relative_path = _require_relative_path(raw_entry, "ignored skill relPath")
                name = relative_path.name
                reason = "skillignore"
            else:
                entry = _require_mapping(raw_entry, "ignored skill entry")
                name = _require_string(entry.get("name"), "ignored skill name")
                relative_path = _require_relative_path(
                    entry.get("relPath", name), "ignored skill relPath"
                )
                reason_value = entry.get("reason")
                reason = (
                    reason_value.strip()
                    if isinstance(reason_value, str) and reason_value.strip()
                    else "skillignore"
                )
            path = _normalized_source_path(source_path, relative_path)
            ignored[path] = RuntimeIgnoredSkill(
                name=name,
                path=path,
                reason=reason,
            )

    for raw_entry in _require_sequence(list_payload, "skill list"):
        entry = _require_mapping(raw_entry, "skill list entry")
        if entry.get("kind") != "skill" or entry.get("disabled") is not True:
            continue
        name = _require_string(entry.get("name"), "disabled skill name")
        relative_path = _require_relative_path(
            entry.get("relPath"), "disabled skill relPath"
        )
        path = _normalized_source_path(source_path, relative_path)
        ignored.setdefault(
            path,
            RuntimeIgnoredSkill(
                name=name,
                path=path,
                reason="disabled",
            ),
        )

    return tuple(sorted(ignored.values(), key=lambda item: (item.name, item.path)))


def _normalized_source_path(source_path: Path, relative_path: Path) -> str:
    return os.path.abspath(source_path.joinpath(*relative_path.parts))


def _has_intermediate_symlink(source_path: Path, relative_path: Path) -> bool:
    current = source_path
    for part in relative_path.parts[:-1]:
        current /= part
        if current.is_symlink():
            return True
    return False


def _scan_skill(
    path: Path,
    *,
    location_kind: RuntimeLocationKind,
    target_name: str | None,
    distribution_mode: str,
    limits: ScanLimits,
) -> _ScannedSkill:
    warnings: list[str] = []
    name, description = _read_frontmatter(path, limits.max_file_bytes, warnings)
    digest, readable = _directory_digest(path, limits, warnings)
    instance = RuntimeSkillInstance(
        location_kind=location_kind,
        target_name=target_name,
        path=str(path),
        distribution_mode=distribution_mode,
        digest=digest,
        is_symlink=path.is_symlink(),
        readable=readable,
        scan_warnings=tuple(warnings),
    )
    return _ScannedSkill(name=name, description=description, instance=instance)


def _read_frontmatter(
    path: Path, max_bytes: int, warnings: list[str]
) -> tuple[str, str | None]:
    fallback_name = path.name
    skill_file = path / "SKILL.md"
    prefix, failure = _read_regular_file(skill_file, max_bytes=max_bytes)
    if failure == "read limit exceeded":
        warnings.append(f"{skill_file}: frontmatter read limit exceeded")
        return fallback_name, None
    if failure is not None or prefix is None:
        warnings.append(f"{skill_file}: {failure or 'SKILL.md is unreadable'}")
        return fallback_name, None
    try:
        text = prefix.decode("utf-8")
    except UnicodeError:
        warnings.append(f"{skill_file}: SKILL.md is not valid UTF-8")
        return fallback_name, None
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        warnings.append(f"{skill_file}: YAML frontmatter is missing")
        return fallback_name, None
    try:
        closing_index = next(
            index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"
        )
    except StopIteration:
        warnings.append(f"{skill_file}: YAML frontmatter is incomplete")
        return fallback_name, None
    try:
        payload = yaml.safe_load("\n".join(lines[1:closing_index]))
    except yaml.YAMLError:
        warnings.append(f"{skill_file}: YAML frontmatter is invalid")
        return fallback_name, None
    if not isinstance(payload, Mapping):
        warnings.append(f"{skill_file}: YAML frontmatter must be a mapping")
        return fallback_name, None
    name = payload.get("name")
    description = payload.get("description")
    if not isinstance(name, str) or not name.strip():
        warnings.append(f"{skill_file}: frontmatter name is invalid")
        name = fallback_name
    if description is not None and not isinstance(description, str):
        warnings.append(f"{skill_file}: frontmatter description is invalid")
        description = None
    return name.strip(), description.strip() if description else None


def _directory_digest(
    root: Path, limits: ScanLimits, warnings: list[str]
) -> tuple[str | None, bool]:
    files: list[tuple[str, Path]] = []
    complete = True
    try:
        directories = [root]
        while directories:
            directory = directories.pop()
            entries = sorted(directory.iterdir(), key=lambda path: path.name, reverse=True)
            for entry in entries:
                relative_path = entry.relative_to(root).as_posix()
                if entry.is_symlink():
                    warnings.append(f"{entry}: internal symlink was skipped")
                    complete = False
                    continue
                if entry.is_dir():
                    if entry.name not in _IGNORED_DIRECTORIES:
                        directories.append(entry)
                    continue
                if not entry.is_file() or _ignore_file(entry):
                    continue
                files.append((relative_path, entry))
                if len(files) > limits.max_files:
                    warnings.append(f"{root}: file limit exceeded")
                    complete = False
                    break
            if len(files) > limits.max_files:
                break
    except OSError:
        warnings.append(f"{root}: directory scan failed")
        return None, False

    digest = hashlib.sha256()
    total_bytes = 0
    for relative_path, file_path in sorted(files[: limits.max_files]):
        remaining_total = limits.max_total_bytes - total_bytes
        read_limit = min(limits.max_file_bytes, remaining_total)
        content, failure = _read_regular_file(file_path, max_bytes=read_limit)
        if failure == "read limit exceeded":
            if remaining_total < limits.max_file_bytes:
                warnings.append(f"{root}: total byte limit exceeded")
                complete = False
                break
            warnings.append(f"{file_path}: file size limit exceeded")
            complete = False
            continue
        if failure is not None or content is None:
            warnings.append(f"{file_path}: {failure or 'file is unreadable'}")
            complete = False
            continue
        total_bytes += len(content)
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)
    return digest.hexdigest(), complete


def _read_regular_file(path: Path, *, max_bytes: int) -> tuple[bytes | None, str | None]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return None, "safe no-follow reads are unsupported"

    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    content: bytes | None = None
    failure: str | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            failure = "file is not a regular file"
        else:
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            candidate = b"".join(chunks)
            if len(candidate) > max_bytes:
                failure = "read limit exceeded"
            else:
                content = candidate
    except OSError:
        failure = "file could not be read safely"
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                content = None
                failure = "file descriptor could not be closed safely"
    return content, failure


def _aggregate_assets(
    shared_skills: tuple[_ScannedSkill, ...],
    target_skills: tuple[_ScannedSkill, ...],
    configured_targets: tuple[RuntimeTarget, ...],
) -> tuple[RuntimeSkillAsset, ...]:
    grouped: dict[str, list[_ScannedSkill]] = {}
    for skill in (*shared_skills, *target_skills):
        grouped.setdefault(skill.name, []).append(skill)

    assets: list[RuntimeSkillAsset] = []
    for name, skills in grouped.items():
        sources = sorted(
            (skill for skill in skills if skill.instance.location_kind == "shared"),
            key=lambda skill: skill.instance.path,
        )
        targets = sorted(
            (skill for skill in skills if skill.instance.location_kind == "target"),
            key=lambda skill: (skill.instance.target_name or "", skill.instance.path),
        )
        source = sources[0] if sources else None
        instances = tuple(skill.instance for skill in skills)
        missing_targets = _missing_targets(name, source, targets, configured_targets)
        status = _asset_status(source, targets, instances, missing_targets)
        description = source.description if source is not None else None
        if description is None:
            description = next(
                (skill.description for skill in targets if skill.description is not None),
                None,
            )
        assets.append(
            RuntimeSkillAsset(
                key=name,
                name=name,
                description=description,
                status=status,
                source_instance=source.instance if source is not None else None,
                target_instances=tuple(skill.instance for skill in targets),
                missing_targets=missing_targets,
            )
        )
    return tuple(sorted(assets, key=lambda asset: asset.name))


def _asset_status(
    source: _ScannedSkill | None,
    targets: list[_ScannedSkill],
    instances: tuple[RuntimeSkillInstance, ...],
    missing_targets: tuple[str, ...],
) -> RuntimeSkillStatus:
    if any(not instance.readable or instance.scan_warnings for instance in instances):
        return "scan_warning"
    if source is not None and any(
        target.instance.digest != source.instance.digest for target in targets
    ):
        return "diverged"
    if missing_targets:
        return "missing"
    if source is None:
        return "local_only"
    return "consistent"


def _missing_targets(
    name: str,
    source: _ScannedSkill | None,
    target_skills: list[_ScannedSkill],
    configured_targets: tuple[RuntimeTarget, ...],
) -> tuple[str, ...]:
    if source is None:
        return ()
    present = {
        skill.instance.target_name
        for skill in target_skills
        if skill.instance.target_name is not None
    }
    return tuple(
        target.name
        for target in configured_targets
        if _target_expects_skill(target, name) and target.name not in present
    )


def _target_expects_skill(target: RuntimeTarget, name: str) -> bool:
    included = not target.include or any(
        fnmatchcase(name, pattern) for pattern in target.include
    )
    return included and not any(fnmatchcase(name, pattern) for pattern in target.exclude)


def _parse_version(payload: JsonValue, fallback: JsonValue | None) -> str:
    if isinstance(payload, str):
        matches = _VERSION_PATTERN.findall(payload)
        if matches:
            version = matches[-1]
            return version if version.startswith("v") else f"v{version}"
    if isinstance(fallback, str) and fallback.strip():
        version = fallback.strip()
        return version if version.startswith("v") else f"v{version}"
    raise AdapterFailure("Skillshare version output is invalid")


def _require_mapping(value: object, label: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise AdapterFailure(f"Skillshare {label} output is invalid")
    return cast(Mapping[str, JsonValue], value)


def _require_sequence(value: object, label: str) -> Sequence[JsonValue]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AdapterFailure(f"Skillshare {label} output is invalid")
    return cast(Sequence[JsonValue], value)


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterFailure(f"Skillshare {label} output is invalid")
    return value.strip()


def _require_absolute_directory(value: object, label: str) -> Path:
    path = Path(_require_string(value, label))
    if not path.is_absolute() or not path.is_dir():
        raise AdapterFailure(f"Skillshare {label} is not an available absolute directory")
    return path


def _require_absolute_path(value: object, label: str) -> Path:
    path = Path(_require_string(value, label))
    if not path.is_absolute() or ".." in path.parts:
        raise AdapterFailure(f"Skillshare {label} is not a safe absolute path")
    return path


def _require_relative_path(value: object, label: str) -> Path:
    path = Path(_require_string(value, label))
    if path.is_absolute() or not path.parts or any(part in (".", "..") for part in path.parts):
        raise AdapterFailure(f"Skillshare {label} is not a safe relative path")
    return path


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    entries = _require_sequence(value, label)
    if not all(isinstance(entry, str) for entry in entries):
        raise AdapterFailure(f"Skillshare {label} output is invalid")
    return tuple(cast(str, entry) for entry in entries)


def _ignore_file(path: Path) -> bool:
    return path.name in _IGNORED_FILES or path.suffix == ".pyc"

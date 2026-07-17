from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from skillctl.canonical import canonical_digest
from skillctl.config import ControlPlaneConfig
from skillctl.errors import SafetyViolation
from skillctl.models import ProjectionDescriptor

def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _directory_manifest(root: Path) -> tuple[dict[str, str], ...]:
    manifest: list[dict[str, str]] = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                raise SafetyViolation("projection source symlink is forbidden")
        for name in files:
            path = current_path / name
            if path.is_symlink():
                raise SafetyViolation("projection source symlink is forbidden")
            if not path.is_file():
                raise SafetyViolation("projection source entry is invalid")
            manifest.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    return tuple(manifest)


def _manifest_digest(skills_root: Path) -> str:
    return canonical_digest(_directory_manifest(skills_root))


def _config_digest(config_path: Path, runtime_config_path: Path) -> str:
    return canonical_digest(
        {
            "control_plane": hashlib.sha256(config_path.read_bytes()).hexdigest(),
            "runtime": hashlib.sha256(runtime_config_path.read_bytes()).hexdigest(),
        }
    )


def _target_paths_digest(target_paths: tuple[str, ...]) -> str:
    return canonical_digest(target_paths)


def _cleanup_failed_projection(root: Path, projection_root: Path) -> None:
    if root.parent != projection_root or root.is_symlink():
        return
    try:
        if root.resolve(strict=False).parent != projection_root:
            return
        if root.exists():
            shutil.rmtree(root)
    except OSError:
        return


def _load_project_config(config_path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise SafetyViolation("projection config is invalid") from error
    if not isinstance(raw, dict):
        raise SafetyViolation("projection config is invalid")
    return raw


def _target_paths_from_config(raw: dict[str, Any]) -> tuple[str, ...]:
    try:
        targets = raw["targets"]
        if not isinstance(targets, dict) or set(targets) != {"target-a", "target-b"}:
            raise TypeError
        paths = tuple(targets[name]["skills"]["path"] for name in ("target-a", "target-b"))
    except (KeyError, TypeError) as error:
        raise SafetyViolation("projection target config is invalid") from error
    if not all(isinstance(path, str) for path in paths):
        raise SafetyViolation("projection target config is invalid")
    return paths


def _target_paths_from_runtime_config(raw: dict[str, Any]) -> tuple[str, ...]:
    try:
        targets = raw["targets"]
        if not isinstance(targets, list) or len(targets) != 2:
            raise TypeError
        entries = {entry["name"]: entry["skills"] for entry in targets}
        if set(entries) != {"target-a", "target-b"}:
            raise TypeError
        paths = tuple(entries[name]["path"] for name in ("target-a", "target-b"))
    except (KeyError, TypeError) as error:
        raise SafetyViolation("projection runtime target config is invalid") from error
    if not all(isinstance(path, str) for path in paths):
        raise SafetyViolation("projection runtime target config is invalid")
    return paths


class ProjectionBuilder:
    def __init__(self, config: ControlPlaneConfig) -> None:
        self._config = config

    def build(
        self, plan_id: str, source_skill: Path, target_paths: tuple[Path, ...]
    ) -> ProjectionDescriptor:
        if (
            not plan_id
            or plan_id in {".", ".."}
            or "/" in plan_id
            or "\\" in plan_id
        ):
            raise SafetyViolation("projection plan id is invalid")
        if len(target_paths) != 2:
            raise SafetyViolation("projection requires exactly two runtime targets")

        projection_root = self._config.projection_root.resolve(strict=False)
        if any(_is_within(projection_root, root) for root in self._config.authority_roots):
            raise SafetyViolation("projection root cannot reference an authority root")
        source = source_skill.resolve(strict=False)
        if not source.is_dir() or source.is_symlink():
            raise SafetyViolation("projection source skill is invalid")
        if not any(_is_within(source, root) for root in self._config.authority_roots):
            raise SafetyViolation("projection source skill must be under an authority root")

        resolved_targets = tuple(path.resolve(strict=False) for path in target_paths)
        if len(set(resolved_targets)) != 2 or resolved_targets != tuple(sorted(resolved_targets)):
            raise SafetyViolation("projection runtime targets must be distinct and sorted")
        for target in resolved_targets:
            if not any(_is_within(target, root) for root in self._config.allowed_runtime_roots):
                raise SafetyViolation("projection target is outside allowed runtime roots")
            if any(_is_within(target, root) for root in self._config.authority_roots):
                raise SafetyViolation("projection target cannot reference an authority root")

        root = projection_root / plan_id
        if root.exists() or root.is_symlink():
            raise SafetyViolation("projection root already exists")
        root.mkdir(parents=True, mode=0o700)
        try:
            skills_root = root / ".skillshare" / "skills"
            skills_root.mkdir(parents=True, mode=0o700)
            shutil.copytree(source, skills_root / source.name, symlinks=True)

            target_strings = tuple(str(path) for path in resolved_targets)
            project_config = {
                "sources": {"skills": str(skills_root)},
                "mode": "copy",
                "targets": {
                    "target-a": {
                        "skills": {"path": target_strings[0], "mode": "copy"}
                    },
                    "target-b": {
                        "skills": {"path": target_strings[1], "mode": "copy"}
                    },
                },
                "ignore": ["**/.git/**"],
            }
            config_path = root / "skillshare.config.yaml"
            config_bytes = yaml.safe_dump(project_config, sort_keys=False).encode("utf-8")
            config_path.write_bytes(config_bytes)
            runtime_config = {
                "sources": {"skills": str(skills_root)},
                "mode": "copy",
                "targets": [
                    {
                        "name": "target-a",
                        "skills": {"path": target_strings[0], "mode": "copy"},
                    },
                    {
                        "name": "target-b",
                        "skills": {"path": target_strings[1], "mode": "copy"},
                    },
                ],
                "ignore": ["**/.git/**"],
            }
            runtime_config_path = root / ".skillshare" / "config.yaml"
            runtime_config_path.write_text(
                yaml.safe_dump(runtime_config, sort_keys=False), encoding="utf-8"
            )
            return ProjectionDescriptor(
                plan_id=plan_id,
                root=str(root),
                manifest_digest=_manifest_digest(skills_root),
                config_digest=_config_digest(config_path, runtime_config_path),
                runtime_target_paths_digest=_target_paths_digest(target_strings),
            )
        except Exception:
            _cleanup_failed_projection(root, projection_root)
            raise


def validate_projection(
    config: ControlPlaneConfig, descriptor: ProjectionDescriptor
) -> tuple[str, ...]:
    root = Path(descriptor.root)
    expected_root = config.projection_root / descriptor.plan_id
    if root != expected_root or not root.is_dir() or root.is_symlink():
        raise SafetyViolation("projection descriptor root is invalid")
    skills_root = root / ".skillshare" / "skills"
    config_path = root / "skillshare.config.yaml"
    runtime_config_path = root / ".skillshare" / "config.yaml"
    raw = _load_project_config(config_path)
    runtime_raw = _load_project_config(runtime_config_path)
    target_paths = _target_paths_from_config(raw)
    runtime_target_paths = _target_paths_from_runtime_config(runtime_raw)
    expected_config = {
        "sources": {"skills": str(skills_root)},
        "mode": "copy",
        "targets": {
            "target-a": {"skills": {"path": target_paths[0], "mode": "copy"}},
            "target-b": {"skills": {"path": target_paths[1], "mode": "copy"}},
        },
        "ignore": ["**/.git/**"],
    }
    if raw != expected_config:
        raise SafetyViolation("projection config is invalid")
    expected_runtime_config = {
        "sources": {"skills": str(skills_root)},
        "mode": "copy",
        "targets": [
            {
                "name": "target-a",
                "skills": {"path": target_paths[0], "mode": "copy"},
            },
            {
                "name": "target-b",
                "skills": {"path": target_paths[1], "mode": "copy"},
            },
        ],
        "ignore": ["**/.git/**"],
    }
    if runtime_raw != expected_runtime_config or runtime_target_paths != target_paths:
        raise SafetyViolation("projection runtime config is invalid")
    resolved_targets = tuple(str(Path(path).resolve(strict=False)) for path in target_paths)
    if target_paths != resolved_targets or target_paths != tuple(sorted(target_paths)):
        raise SafetyViolation("projection target paths are invalid")
    for target in map(Path, target_paths):
        if not any(_is_within(target, allowed) for allowed in config.allowed_runtime_roots):
            raise SafetyViolation("projection target is outside allowed runtime roots")
        if any(_is_within(target, authority) for authority in config.authority_roots):
            raise SafetyViolation("projection target cannot reference an authority root")
    if descriptor.manifest_digest != _manifest_digest(skills_root):
        raise SafetyViolation("projection manifest digest mismatch")
    if descriptor.config_digest != _config_digest(config_path, runtime_config_path):
        raise SafetyViolation("projection config digest mismatch")
    if descriptor.runtime_target_paths_digest != _target_paths_digest(target_paths):
        raise SafetyViolation("projection target path digest mismatch")
    return target_paths

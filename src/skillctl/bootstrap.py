from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError

from skillctl.approvals import ApprovalService
from skillctl.canonical import canonical_digest, canonical_json
from skillctl.config import ControlPlaneConfig
from skillctl.adapters.skillshare import SkillshareAdapter
from skillctl.errors import GovernanceValidationError, SafetyViolation, StateCorruption
from skillctl.ledger import DeploymentLedger
from skillctl.models import Asset, Plan, ProjectionDescriptor, Target
from skillctl.planner import PlanService, calculate_changes, desired_assets
from skillctl.projection import ProjectionBuilder, validate_projection
from skillctl.read_service import GovernanceReadService
from skillctl.repository import DocumentRepository, GovernanceSnapshot
from skillctl.runner import CommandRunner
from skillctl.service import DeploymentService


_PLAN_ID = re.compile(r"plan-[0-9a-f]{32}")
_DEPLOYMENT_ID = re.compile(r"deployment-[0-9a-f]{32}")
_DESCRIPTOR_NAME = ".descriptor.json"
_SNAPSHOT_METADATA_NAME = ".snapshot.json"


@dataclass(frozen=True)
class _TreeEntry:
    path: str
    kind: str
    content: bytes | None


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _require_plan_id(plan_id: str) -> None:
    if _PLAN_ID.fullmatch(plan_id) is None:
        raise SafetyViolation("projection descriptor plan id is invalid")


def runtime_target_paths(
    config: ControlPlaneConfig, target: Target
) -> tuple[str, ...]:
    root = target.config.get("root")
    if not isinstance(root, str) or not root or not Path(root).is_absolute():
        raise SafetyViolation("runtime target root is invalid")
    try:
        paths = tuple(
            sorted(
                (Path(root) / name).resolve(strict=False)
                for name in ("target-a", "target-b")
            )
        )
    except (OSError, RuntimeError):
        raise SafetyViolation("runtime target root is invalid") from None
    if len(set(paths)) != 2 or any(
        not any(_is_within(path, allowed) for allowed in config.allowed_runtime_roots)
        for path in paths
    ):
        raise SafetyViolation("runtime target is outside allowed runtime roots")
    return tuple(str(path) for path in paths)


class ProjectionLocator:
    def __init__(self, config: ControlPlaneConfig) -> None:
        self._config = config

    def save(self, descriptor: ProjectionDescriptor) -> None:
        _require_plan_id(descriptor.plan_id)
        validate_projection(self._config, descriptor)
        directory = self._descriptor_directory(descriptor.plan_id)
        final_path = directory / _DESCRIPTOR_NAME
        temporary_path = directory / f".{_DESCRIPTOR_NAME}.{uuid4().hex}.tmp"
        payload = canonical_json(descriptor.model_dump(mode="json"))
        file_descriptor = -1
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            flags |= getattr(os, "O_NOFOLLOW", 0)
            file_descriptor = os.open(temporary_path, flags, 0o600)
            self._write_all(file_descriptor, payload)
            os.fsync(file_descriptor)
            os.close(file_descriptor)
            file_descriptor = -1
            os.link(temporary_path, final_path, follow_symlinks=False)
            os.unlink(temporary_path)
            self._fsync_directory(directory)
        except FileExistsError:
            self._cleanup(file_descriptor, temporary_path)
            raise SafetyViolation("projection descriptor already exists") from None
        except OSError:
            self._cleanup(file_descriptor, temporary_path)
            raise SafetyViolation("projection descriptor persistence failed") from None

    def for_plan_id(self, plan_id: str) -> ProjectionDescriptor:
        _require_plan_id(plan_id)
        file_descriptor = -1
        try:
            path = self._descriptor_directory(plan_id) / _DESCRIPTOR_NAME
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            file_descriptor = os.open(path, flags)
            with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
                raw = stream.read()
            payload = json.loads(raw)
            descriptor = ProjectionDescriptor.model_validate(payload)
            if (
                descriptor.plan_id != plan_id
                or canonical_json(descriptor.model_dump(mode="json")) != raw
            ):
                raise ValueError
            validate_projection(self._config, descriptor)
            return descriptor
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            ValueError,
            ValidationError,
            SafetyViolation,
        ):
            raise StateCorruption("projection descriptor is invalid") from None
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)

    def _descriptor_directory(self, plan_id: str) -> Path:
        directory = self._config.projection_root / plan_id
        expected = directory.resolve(strict=False)
        if (
            expected != directory
            or directory.is_symlink()
            or not directory.is_dir()
            or directory.parent != self._config.projection_root
        ):
            raise SafetyViolation("projection descriptor root is invalid")
        return directory

    @staticmethod
    def _write_all(file_descriptor: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(file_descriptor, payload[offset:])
            if written <= 0:
                raise OSError
            offset += written

    @staticmethod
    def _cleanup(file_descriptor: int, temporary_path: Path) -> None:
        if file_descriptor >= 0:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        try:
            os.unlink(temporary_path)
        except (FileNotFoundError, OSError):
            pass

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        file_descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            file_descriptor = os.open(directory, flags)
            os.fsync(file_descriptor)
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)


class FileRuntimeSnapshotStore:
    def __init__(
        self, config: ControlPlaneConfig, projections: ProjectionLocator
    ) -> None:
        self._config = config
        self._projections = projections

    def capture(
        self,
        deployment_id: str,
        target: Target,
        plan: Plan,
        projection: ProjectionDescriptor,
    ) -> None:
        del plan
        self._require_deployment_id(deployment_id)
        if projection.plan_id != Path(projection.root).name:
            raise SafetyViolation("runtime snapshot projection is invalid")
        projection_paths = validate_projection(self._config, projection)
        target_paths = runtime_target_paths(self._config, target)
        if projection_paths != target_paths:
            raise SafetyViolation("runtime snapshot target paths do not match")

        trees = tuple(self._scan_tree(Path(path)) for path in target_paths)
        if trees[0] != trees[1]:
            raise SafetyViolation("runtime target trees do not match")

        snapshots_root = self._snapshots_root(create=True)
        final_root = snapshots_root / deployment_id
        if final_root.exists() or final_root.is_symlink():
            raise SafetyViolation("runtime snapshot already exists")
        temporary_root = snapshots_root / f".{deployment_id}.{uuid4().hex}.tmp"
        try:
            temporary_root.mkdir(mode=0o700)
            skills_root = temporary_root / "skills"
            skills_root.mkdir(mode=0o700)
            self._write_tree(skills_root, trees[0])
            metadata = {
                "deployment_id": deployment_id,
                "target_id": target.id,
                "runtime_target_paths": target_paths,
                "tree_manifest": self._tree_manifest(trees[0]),
            }
            self._write_new_file(
                temporary_root / _SNAPSHOT_METADATA_NAME,
                canonical_json(metadata),
            )
            os.rename(temporary_root, final_root)
            ProjectionLocator._fsync_directory(snapshots_root)
        except SafetyViolation:
            self._cleanup_tree(temporary_root, snapshots_root)
            raise
        except OSError:
            self._cleanup_tree(temporary_root, snapshots_root)
            raise SafetyViolation("runtime snapshot persistence failed") from None

    def rollback_projection(
        self,
        deployment_id: str,
        rollback_plan_id: str,
        target: Target,
        runtime_paths: tuple[str, ...],
    ) -> ProjectionDescriptor:
        self._require_deployment_id(deployment_id)
        _require_plan_id(rollback_plan_id)
        expected_paths = runtime_target_paths(self._config, target)
        if runtime_paths != expected_paths:
            raise SafetyViolation("rollback runtime target paths do not match")

        snapshot_root = self._snapshot_root(deployment_id)
        metadata = self._load_snapshot_metadata(snapshot_root)
        tree = self._scan_tree(snapshot_root / "skills")
        if (
            metadata.get("deployment_id") != deployment_id
            or metadata.get("target_id") != target.id
            or metadata.get("runtime_target_paths") != list(expected_paths)
            or metadata.get("tree_manifest") != list(self._tree_manifest(tree))
        ):
            raise SafetyViolation("runtime snapshot is invalid")

        projection_root = self._config.projection_root / rollback_plan_id
        if projection_root.exists() or projection_root.is_symlink():
            raise SafetyViolation("rollback projection already exists")
        try:
            projection_root.mkdir(mode=0o700)
            skills_root = projection_root / ".skillshare" / "skills"
            skills_root.mkdir(parents=True, mode=0o700)
            self._write_tree(skills_root, tree)
            self._write_projection_configs(
                projection_root, skills_root, expected_paths
            )
            descriptor = self._descriptor(
                rollback_plan_id, projection_root, skills_root, expected_paths
            )
            validate_projection(self._config, descriptor)
            self._projections.save(descriptor)
            return descriptor
        except Exception:
            self._cleanup_tree(projection_root, self._config.projection_root)
            raise

    def _snapshots_root(self, *, create: bool) -> Path:
        projection_root = self._config.projection_root
        if (
            projection_root.is_symlink()
            or not projection_root.is_dir()
            or projection_root.resolve(strict=False) != projection_root
        ):
            raise SafetyViolation("runtime snapshot root is invalid")
        root = projection_root / ".runtime-snapshots"
        try:
            if create:
                root.mkdir(mode=0o700, exist_ok=True)
        except OSError:
            raise SafetyViolation("runtime snapshot root is invalid") from None
        if root.is_symlink() or not root.is_dir() or root.parent != projection_root:
            raise SafetyViolation("runtime snapshot root is invalid")
        return root

    def _snapshot_root(self, deployment_id: str) -> Path:
        root = self._snapshots_root(create=False) / deployment_id
        if root.is_symlink() or not root.is_dir():
            raise SafetyViolation("runtime snapshot is invalid")
        return root

    @staticmethod
    def _require_deployment_id(deployment_id: str) -> None:
        if _DEPLOYMENT_ID.fullmatch(deployment_id) is None:
            raise SafetyViolation("runtime snapshot deployment id is invalid")

    @classmethod
    def _scan_tree(cls, root: Path) -> tuple[_TreeEntry, ...]:
        if root.is_symlink():
            raise SafetyViolation("runtime tree symlink is forbidden")
        if not root.exists():
            return ()
        if not root.is_dir():
            raise SafetyViolation("runtime tree root is invalid")

        entries: list[_TreeEntry] = []
        cls._scan_directory(root, root, entries)
        return tuple(sorted(entries, key=lambda item: (item.path, item.kind)))

    @classmethod
    def _scan_directory(
        cls, root: Path, current: Path, entries: list[_TreeEntry]
    ) -> None:
        try:
            children = sorted(current.iterdir(), key=lambda path: path.name)
        except OSError:
            raise SafetyViolation("runtime tree could not be inspected") from None
        for path in children:
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise SafetyViolation("runtime tree symlink is forbidden")
            if path.is_dir():
                entries.append(_TreeEntry(relative, "directory", None))
                cls._scan_directory(root, path, entries)
            elif path.is_file():
                entries.append(_TreeEntry(relative, "file", cls._read_file(path)))
            else:
                raise SafetyViolation("runtime tree entry is invalid")

    @staticmethod
    def _read_file(path: Path) -> bytes:
        file_descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            file_descriptor = os.open(path, flags)
            if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
                raise OSError
            with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
                return stream.read()
        except OSError:
            raise SafetyViolation("runtime tree file is invalid") from None
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)

    @classmethod
    def _write_tree(cls, root: Path, tree: tuple[_TreeEntry, ...]) -> None:
        for entry in tree:
            destination = root / entry.path
            if destination != root and root not in destination.parents:
                raise SafetyViolation("runtime tree path is invalid")
            if entry.kind == "directory":
                destination.mkdir(mode=0o700, parents=True, exist_ok=False)
            elif entry.kind == "file" and entry.content is not None:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                cls._write_new_file(destination, entry.content)
            else:
                raise SafetyViolation("runtime tree entry is invalid")

    @staticmethod
    def _write_new_file(path: Path, payload: bytes) -> None:
        file_descriptor = -1
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            flags |= getattr(os, "O_NOFOLLOW", 0)
            file_descriptor = os.open(path, flags, 0o600)
            ProjectionLocator._write_all(file_descriptor, payload)
            os.fsync(file_descriptor)
        except OSError:
            raise SafetyViolation("runtime snapshot file write failed") from None
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)

    @staticmethod
    def _tree_manifest(tree: tuple[_TreeEntry, ...]) -> tuple[dict[str, str], ...]:
        return tuple(
            {
                "path": entry.path,
                "kind": entry.kind,
                **(
                    {"sha256": hashlib.sha256(entry.content).hexdigest()}
                    if entry.content is not None
                    else {}
                ),
            }
            for entry in tree
        )

    @staticmethod
    def _load_snapshot_metadata(snapshot_root: Path) -> dict[str, object]:
        raw = FileRuntimeSnapshotStore._read_file(
            snapshot_root / _SNAPSHOT_METADATA_NAME
        )
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or canonical_json(payload) != raw:
                raise ValueError
            return payload
        except (json.JSONDecodeError, UnicodeError, ValueError, TypeError):
            raise SafetyViolation("runtime snapshot is invalid") from None

    @classmethod
    def _write_projection_configs(
        cls,
        root: Path,
        skills_root: Path,
        target_paths: tuple[str, ...],
    ) -> None:
        project_config = {
            "sources": {"skills": str(skills_root)},
            "mode": "copy",
            "targets": {
                "target-a": {
                    "skills": {"path": target_paths[0], "mode": "copy"}
                },
                "target-b": {
                    "skills": {"path": target_paths[1], "mode": "copy"}
                },
            },
            "ignore": ["**/.git/**"],
        }
        runtime_config = {
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
        cls._write_new_file(
            root / "skillshare.config.yaml",
            yaml.safe_dump(project_config, sort_keys=False).encode("utf-8"),
        )
        cls._write_new_file(
            root / ".skillshare" / "config.yaml",
            yaml.safe_dump(runtime_config, sort_keys=False).encode("utf-8"),
        )

    @staticmethod
    def _descriptor(
        plan_id: str,
        root: Path,
        skills_root: Path,
        target_paths: tuple[str, ...],
    ) -> ProjectionDescriptor:
        file_manifest = FileRuntimeSnapshotStore._projection_file_manifest(
            skills_root
        )
        config_path = root / "skillshare.config.yaml"
        runtime_config_path = root / ".skillshare" / "config.yaml"
        return ProjectionDescriptor(
            plan_id=plan_id,
            root=str(root),
            manifest_digest=canonical_digest(file_manifest),
            config_digest=canonical_digest(
                {
                    "control_plane": hashlib.sha256(
                        FileRuntimeSnapshotStore._read_file(config_path)
                    ).hexdigest(),
                    "runtime": hashlib.sha256(
                        FileRuntimeSnapshotStore._read_file(runtime_config_path)
                    ).hexdigest(),
                }
            ),
            runtime_target_paths_digest=canonical_digest(target_paths),
        )

    @classmethod
    def _projection_file_manifest(
        cls, root: Path
    ) -> tuple[dict[str, str], ...]:
        manifest: list[dict[str, str]] = []
        try:
            for current, directories, files in os.walk(root, followlinks=False):
                directories.sort()
                files.sort()
                current_path = Path(current)
                for name in directories:
                    if (current_path / name).is_symlink():
                        raise SafetyViolation("runtime tree symlink is forbidden")
                for name in files:
                    path = current_path / name
                    if path.is_symlink():
                        raise SafetyViolation("runtime tree symlink is forbidden")
                    content = cls._read_file(path)
                    manifest.append(
                        {
                            "path": path.relative_to(root).as_posix(),
                            "sha256": hashlib.sha256(content).hexdigest(),
                        }
                    )
        except OSError:
            raise SafetyViolation("runtime tree could not be inspected") from None
        return tuple(manifest)

    @staticmethod
    def _cleanup_tree(root: Path, parent: Path) -> None:
        try:
            if (
                root.parent == parent
                and root.resolve(strict=False).parent == parent
                and not root.is_symlink()
                and root.exists()
            ):
                shutil.rmtree(root)
        except OSError:
            pass


class GovernanceRuntime:
    def __init__(
        self,
        config: ControlPlaneConfig,
        repository: DocumentRepository,
        projections: ProjectionLocator,
        projection_builder: ProjectionBuilder,
        runner: CommandRunner,
        approvals: ApprovalService,
        deployment: DeploymentService,
        read: GovernanceReadService,
        *,
        now: Callable[[], datetime],
        plan_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self.projections = projections
        self.approvals = approvals
        self.deployment = deployment
        self.read = read
        self._projection_builder = projection_builder
        self._runner = runner
        self._now = now
        self._plan_id_factory = plan_id_factory or (
            lambda: "plan-" + uuid4().hex
        )

    def create_plan(self, target_id: str, *, expires_in: timedelta) -> Plan:
        plan_id = self._plan_id_factory()
        _require_plan_id(plan_id)
        projection_root = self.config.projection_root / plan_id
        try:
            snapshot = self.repository.load_snapshot()
            target = self._target(snapshot, target_id)
            desired = desired_assets(snapshot, target.id)
            source = self._authority_source(desired)
            paths = runtime_target_paths(self.config, target)
            observations = tuple(
                item
                for item in snapshot.observations
                if item.target_id == target.id
            )
            changes = calculate_changes(desired, observations)
            projection = self._projection_builder.build(
                plan_id, source, tuple(Path(path) for path in paths)
            )
            adapter = SkillshareAdapter(
                self.config,
                runner=self._runner,
                manifest=target.capabilities,
            )
            evidence = adapter.plan(target, changes, plan_id, projection)
            self.projections.save(projection)
            planner = PlanService(
                self.repository,
                runtime_target_paths_resolver=lambda current: runtime_target_paths(
                    self.config, current
                ),
                id_factory=lambda: plan_id,
            )
            return planner.create(
                target.id,
                adapter_evidence=evidence,
                now=self._now(),
                expires_in=expires_in,
            )
        except Exception:
            self._cleanup_projection(projection_root)
            raise

    @staticmethod
    def _target(snapshot: GovernanceSnapshot, target_id: str) -> Target:
        target = next(
            (item for item in snapshot.targets if item.id == target_id), None
        )
        if target is None:
            raise GovernanceValidationError("plan: unknown target")
        return target

    def _authority_source(self, desired: tuple[Asset, ...]) -> Path:
        skills = tuple(asset for asset in desired if asset.asset_type == "skill")
        if len(skills) != 1 or not skills[0].source_path:
            raise GovernanceValidationError(
                "plan: exactly one authority skill source is required"
            )
        source_path = Path(skills[0].source_path)
        candidates: set[Path] = set()
        roots = self.config.authority_roots
        possible_paths = (
            (source_path,) if source_path.is_absolute() else tuple(root / source_path for root in roots)
        )
        try:
            for possible in possible_paths:
                resolved = possible.resolve(strict=False)
                if (
                    resolved.is_dir()
                    and not resolved.is_symlink()
                    and any(_is_within(resolved, root) for root in roots)
                ):
                    candidates.add(resolved)
        except (OSError, RuntimeError):
            raise GovernanceValidationError(
                "plan: authority skill source is invalid"
            ) from None
        if len(candidates) != 1:
            raise GovernanceValidationError(
                "plan: exactly one authority skill source is required"
            )
        return candidates.pop()

    def _cleanup_projection(self, root: Path) -> None:
        FileRuntimeSnapshotStore._cleanup_tree(root, self.config.projection_root)


def _load_config(path: Path) -> ControlPlaneConfig:
    file_descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(path, flags)
        with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
            raw = yaml.safe_load(stream.read())
        return ControlPlaneConfig.model_validate(raw)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError, TypeError):
        raise GovernanceValidationError("control-plane config is invalid") from None
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def build_runtime(
    config_path: Path,
    *,
    now: Callable[[], datetime] | None = None,
) -> GovernanceRuntime:
    config = _load_config(config_path)
    repository = DocumentRepository(config.registry_root, config.state_root)
    runner = CommandRunner(tuple(config.trusted_cli_paths.values()))
    projections = ProjectionLocator(config)
    ledger = DeploymentLedger(config.state_root / "deployment-ledger.jsonl")
    snapshot_store = FileRuntimeSnapshotStore(config, projections)
    clock = now or (lambda: datetime.now(timezone.utc))

    def adapter_for_target(target: Target) -> SkillshareAdapter:
        return SkillshareAdapter(
            config,
            runner=runner,
            manifest=target.capabilities,
        )

    def projection_for_plan(plan: Plan) -> ProjectionDescriptor:
        return projections.for_plan_id(plan.id)

    deployment = DeploymentService(
        repository,
        ledger=ledger,
        adapter_for_target=adapter_for_target,
        projection_for_plan=projection_for_plan,
        runtime_target_paths_resolver=lambda target: runtime_target_paths(
            config, target
        ),
        snapshot_store=snapshot_store,
        now=clock,
    )
    read = GovernanceReadService(
        repository,
        ledger=ledger,
        adapter_for_target=adapter_for_target,
        projection_for_plan=projection_for_plan,
        now=clock,
    )
    return GovernanceRuntime(
        config,
        repository,
        projections,
        ProjectionBuilder(config),
        runner,
        ApprovalService(repository),
        deployment,
        read,
        now=clock,
    )

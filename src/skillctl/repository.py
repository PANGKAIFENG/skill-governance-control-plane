import json
import os
import re
from pathlib import Path
from typing import Any, TypeVar
from uuid import uuid4

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ValidationError

from skillctl.canonical import canonical_digest, canonical_json
from skillctl.errors import (
    GovernanceValidationError,
    PolicyDenied,
    StalePlan,
    StateCorruption,
)
from skillctl.models import (
    Approval,
    Asset,
    AssetDocument,
    ConsumerBinding,
    ConsumerBindingDocument,
    DeploymentProfile,
    DeploymentProfileDocument,
    ObservedState,
    Plan,
    ProfileMembership,
    ProfileMembershipDocument,
    SchemaVersion,
    StrictModel,
    Target,
    TargetDocument,
)

DocumentT = TypeVar("DocumentT", bound=BaseModel)

_DOCUMENT_KINDS = {
    "AssetDocument": "assets",
    "TargetDocument": "targets",
    "DeploymentProfileDocument": "profiles",
    "ProfileMembershipDocument": "profile-memberships",
    "ConsumerBindingDocument": "consumer-bindings",
    "ObservedStateDocument": "observed-states",
}


class _RecordAlreadyExists(Exception):
    pass


class _RecordPersistenceFailed(Exception):
    pass


class GovernanceSnapshot(StrictModel):
    assets: tuple[Asset, ...]
    targets: tuple[Target, ...]
    profiles: tuple[DeploymentProfile, ...]
    memberships: tuple[ProfileMembership, ...]
    bindings: tuple[ConsumerBinding, ...]
    observations: tuple[ObservedState, ...]


class ObservedStateDocument(StrictModel):
    schema_version: SchemaVersion
    items: tuple[ObservedState, ...]


def load_document(path: Path, model: type[DocumentT]) -> DocumentT:
    try:
        payload: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        return model.model_validate(payload)
    except (OSError, ValidationError, yaml.YAMLError):
        document_kind = _DOCUMENT_KINDS.get(model.__name__, "governance-document")
        raise GovernanceValidationError(f"{document_kind}: invalid document") from None


class DocumentRepository:
    def __init__(self, registry_root: Path, state_root: Path) -> None:
        self.registry_root = registry_root
        self.state_root = state_root

    def load_snapshot(self) -> GovernanceSnapshot:
        assets = tuple(
            sorted(
                load_document(self.registry_root / "assets.yaml", AssetDocument).items,
                key=lambda item: item.id,
            )
        )
        targets = tuple(
            sorted(
                load_document(self.registry_root / "targets.yaml", TargetDocument).items,
                key=lambda item: item.id,
            )
        )
        profiles = tuple(
            sorted(
                load_document(
                    self.registry_root / "profiles.yaml", DeploymentProfileDocument
                ).items,
                key=lambda item: item.id,
            )
        )
        memberships = tuple(
            sorted(
                load_document(
                    self.registry_root / "profile-memberships.yaml",
                    ProfileMembershipDocument,
                ).items,
                key=lambda item: item.id,
            )
        )
        bindings = tuple(
            sorted(
                load_document(
                    self.registry_root / "consumer-bindings.yaml",
                    ConsumerBindingDocument,
                ).items,
                key=lambda item: item.id,
            )
        )
        observations = tuple(
            sorted(
                load_document(
                    self.state_root / "observed-states.yaml", ObservedStateDocument
                ).items,
                key=lambda item: item.id,
            )
        )
        for document_kind, items in (
            ("assets", assets),
            ("targets", targets),
            ("profiles", profiles),
            ("profile-memberships", memberships),
            ("consumer-bindings", bindings),
            ("observed-states", observations),
        ):
            self._reject_duplicate_ids(document_kind, items)
        asset_ids = {asset.id for asset in assets}
        assets_by_id = {asset.id: asset for asset in assets}
        profile_ids = {profile.id for profile in profiles}
        target_ids = {target.id for target in targets}
        for membership in memberships:
            if membership.asset_id not in asset_ids:
                raise GovernanceValidationError(
                    "profile-memberships: unknown asset " + membership.asset_id
                )
            if membership.profile_id not in profile_ids:
                raise GovernanceValidationError(
                    "profile-memberships: unknown profile " + membership.profile_id
                )
            self._reject_disallowed_relationship_asset(
                "profile-memberships", membership.asset_id, assets_by_id
            )
        for binding in bindings:
            if binding.asset_id not in asset_ids:
                raise GovernanceValidationError(
                    "consumer-bindings: unknown asset " + binding.asset_id
                )
            if binding.target_id not in target_ids:
                raise GovernanceValidationError(
                    "consumer-bindings: unknown target " + binding.target_id
                )
            if not binding.consumer_id.strip():
                raise GovernanceValidationError(
                    "consumer-bindings: blank consumer id " + binding.id
                )
            self._reject_disallowed_relationship_asset(
                "consumer-bindings", binding.asset_id, assets_by_id
            )
        for observation in observations:
            if observation.asset_id not in asset_ids:
                raise GovernanceValidationError(
                    "observed-states: unknown asset " + observation.asset_id
                )
            if observation.target_id not in target_ids:
                raise GovernanceValidationError(
                    "observed-states: unknown target " + observation.target_id
                )
        return GovernanceSnapshot(
            assets=assets,
            targets=targets,
            profiles=profiles,
            memberships=memberships,
            bindings=bindings,
            observations=observations,
        )

    def create_plan(self, plan: Plan) -> None:
        if not re.fullmatch(r"plan-[0-9a-f]{32}", plan.id):
            raise GovernanceValidationError("plan: invalid id")
        directory = self._record_directory("plans")
        try:
            self._publish_exclusive_record(
                directory,
                f"{plan.id}.json",
                canonical_json(plan.model_dump(mode="json")),
            )
        except _RecordAlreadyExists:
            raise GovernanceValidationError("plan: immutable record already exists") from None
        except _RecordPersistenceFailed:
            raise GovernanceValidationError("plan: persistence failed") from None

    def get_plan(self, plan_id: str) -> Plan:
        if not re.fullmatch(r"plan-[0-9a-f]{32}", plan_id):
            raise StalePlan("plan: invalid stored record")
        path = self.state_root / "plans" / f"{plan_id}.json"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read()
            payload = json.loads(raw)
            plan = Plan.model_validate(payload)
            if plan.id != plan_id:
                raise ValueError
            if canonical_json(plan.model_dump(mode="json")) != raw:
                raise ValueError
            expected_digest = canonical_digest(
                plan.model_dump(mode="json", exclude={"plan_digest"})
            )
            if plan.plan_digest != expected_digest:
                raise ValueError
            return plan
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, ValidationError):
            raise StalePlan("plan: invalid stored record") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def list_plans(self) -> tuple[Plan, ...]:
        directory = self.state_root / "plans"
        if not directory.exists():
            return ()
        try:
            if directory.is_symlink() or not directory.is_dir():
                raise OSError
            plan_ids = tuple(
                sorted(
                    path.stem
                    for path in directory.iterdir()
                    if path.is_file()
                    and not path.is_symlink()
                    and re.fullmatch(r"plan-[0-9a-f]{32}\.json", path.name)
                )
            )
            if len(plan_ids) != len(tuple(directory.iterdir())):
                raise OSError
            return tuple(self.get_plan(plan_id) for plan_id in plan_ids)
        except (OSError, StalePlan):
            raise StalePlan("plan: invalid stored record") from None

    def create_approval(self, approval: Approval) -> None:
        if (
            not re.fullmatch(r"plan-[0-9a-f]{32}", approval.plan_id)
            or approval.id != f"approval-{approval.plan_id}"
        ):
            raise PolicyDenied("approval: invalid record")
        directory = self._record_directory("approvals")
        try:
            self._publish_exclusive_record(
                directory,
                f"approval-{approval.plan_id}.json",
                canonical_json(approval.model_dump(mode="json")),
            )
        except _RecordAlreadyExists:
            raise PolicyDenied("approval: terminal decision already recorded") from None
        except _RecordPersistenceFailed:
            raise PolicyDenied("approval: persistence failed") from None

    def get_approval(self, plan_id: str) -> Approval | None:
        if not re.fullmatch(r"plan-[0-9a-f]{32}", plan_id):
            raise PolicyDenied("approval: invalid stored record")
        path = self.state_root / "approvals" / f"approval-{plan_id}.json"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError:
            raise StateCorruption("approval: invalid stored record") from None
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read()
            payload = json.loads(raw)
            approval = Approval.model_validate(payload)
            if (
                approval.id != f"approval-{plan_id}"
                or approval.plan_id != plan_id
                or canonical_json(approval.model_dump(mode="json")) != raw
            ):
                raise ValueError
            return approval
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, ValidationError):
            raise StateCorruption("approval: invalid stored record") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _record_directory(self, name: str) -> Path:
        directory = self.state_root / name
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.is_symlink() or not directory.is_dir():
                raise OSError
        except OSError:
            raise GovernanceValidationError("record storage unavailable") from None
        return directory

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError
            offset += written

    @classmethod
    def _publish_exclusive_record(cls, directory: Path, final_name: str, payload: bytes) -> None:
        final_path = directory / final_name
        temporary_path = directory / f".{final_name}.{uuid4().hex}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(temporary_path, flags, 0o600)
            cls._write_all(descriptor, payload)
            os.fsync(descriptor)
        except OSError:
            cls._close_and_remove_temporary(descriptor, temporary_path)
            raise _RecordPersistenceFailed from None
        try:
            os.close(descriptor)
        except OSError:
            cls._remove_temporary(temporary_path)
            raise _RecordPersistenceFailed from None

        try:
            os.link(temporary_path, final_path, follow_symlinks=False)
        except FileExistsError:
            cls._remove_temporary(temporary_path)
            raise _RecordAlreadyExists from None
        except OSError:
            cls._remove_temporary(temporary_path)
            raise _RecordPersistenceFailed from None

        cls._remove_temporary(temporary_path)
        try:
            cls._fsync_directory(directory, "record persistence failed")
        except GovernanceValidationError:
            raise _RecordPersistenceFailed from None

    @classmethod
    def _close_and_remove_temporary(cls, descriptor: int, path: Path) -> None:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        cls._remove_temporary(path)

    @staticmethod
    def _remove_temporary(path: Path) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            raise _RecordPersistenceFailed from None

    @staticmethod
    def _fsync_directory(directory: Path, public_message: str) -> None:
        descriptor = -1
        try:
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            os.fsync(descriptor)
        except OSError:
            raise GovernanceValidationError(public_message) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _reject_duplicate_ids(document_kind: str, items: tuple[Any, ...]) -> None:
        seen: set[str] = set()
        for item in items:
            if item.id in seen:
                raise GovernanceValidationError(f"{document_kind}: duplicate id {item.id}")
            seen.add(item.id)

    @staticmethod
    def _reject_disallowed_relationship_asset(
        document_kind: str,
        asset_id: str,
        assets_by_id: dict[str, Asset],
    ) -> None:
        if assets_by_id[asset_id].lifecycle in {"quarantined", "deferred"}:
            raise GovernanceValidationError(f"{document_kind}: disallowed asset {asset_id}")

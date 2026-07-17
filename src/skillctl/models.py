from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping, Sequence
from copy import deepcopy
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal, Never, Self, TypeAlias, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    JsonValue,
    ModelWrapValidatorHandler,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)


SchemaVersion: TypeAlias = Literal["1.0"]
CapabilityState: TypeAlias = Literal["supported", "unsupported", "unverified"]
ChangeType: TypeAlias = Literal[
    "create", "update", "bind", "unbind", "deprecate", "prune", "publish"
]
RiskLevel: TypeAlias = Literal["low", "medium", "high", "critical"]
ApprovalDecision: TypeAlias = Literal["approved", "rejected"]


_SENSITIVE_NAME_TOKENS = {
    "AUTH",
    "AUTHORIZATION",
    "COOKIE",
    "CREDENTIAL",
    "DSN",
    "KEY",
    "PASSWD",
    "PASSWORD",
    "PAT",
    "PWD",
    "SECRET",
    "TOKEN",
}
_SENSITIVE_COMPOUND_NAMES = {
    "ACCESSTOKEN",
    "APIKEY",
    "CLIENTSECRET",
    "DATABASEURL",
    "MONGODBURI",
    "PGPASSWORD",
    "PRIVATEKEY",
    "REDISURL",
    "SECRETKEY",
}
_CREDENTIAL_URL_PREFIXES = {"DATABASE", "DB", "MONGODB", "REDIS"}


def is_sensitive_name(name: str) -> bool:
    camel_separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    normalized = re.sub(r"[^A-Z0-9]+", "_", camel_separated.upper()).strip("_")
    if normalized == "CREDENTIAL_REF":
        return False
    tokens = tuple(token for token in normalized.split("_") if token)
    return (
        bool(_SENSITIVE_COMPOUND_NAMES.intersection(tokens))
        or bool(_SENSITIVE_NAME_TOKENS.intersection(tokens))
        or (
            tokens[-1:] in (("URL",), ("URI",))
            and bool(_CREDENTIAL_URL_PREFIXES.intersection(tokens[:-1]))
        )
    )


class _FrozenContainer:
    __slots__ = ()

    def __setattr__(self, name: str, value: Any) -> None:
        if hasattr(self, name):
            raise TypeError("frozen container attributes cannot be modified")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> Never:
        raise TypeError("frozen container attributes cannot be deleted")


class _FrozenMapping(_FrozenContainer, Mapping[Any, Any]):
    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[Any, Any]]) -> None:
        self._items = tuple(items)

    def __getitem__(self, key: Any) -> Any:
        for candidate, value in self._items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[Any]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)


class _FrozenSequence(_FrozenContainer, Sequence[Any]):
    __slots__ = ("_items",)

    def __init__(self, items: Iterable[Any]) -> None:
        self._items = tuple(items)

    def __getitem__(self, index: int | slice) -> Any:
        return self._items[index]

    def __len__(self) -> int:
        return len(self._items)

    def append(self, value: Any) -> Never:
        raise TypeError("frozen sequence does not support mutation")


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _FrozenMapping(
            (key, _deep_freeze(child)) for key, child in value.items()
        )
    if isinstance(value, list):
        return _FrozenSequence(_deep_freeze(child) for child in value)
    if isinstance(value, tuple):
        return tuple(_deep_freeze(child) for child in value)
    return value


def _deep_thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _deep_thaw(child) for key, child in value.items()}
    if isinstance(value, _FrozenSequence):
        return [_deep_thaw(child) for child in value]
    if isinstance(value, tuple):
        return tuple(_deep_thaw(child) for child in value)
    return value


def _nested_validation_payload(value: Any, *, deep: bool) -> Any:
    if isinstance(value, BaseModel):
        return {
            name: _nested_validation_payload(getattr(value, name), deep=deep)
            for name in type(value).model_fields
            if name in value.__dict__
        }
    if isinstance(value, Mapping):
        return {
            deepcopy(key) if deep else key: _nested_validation_payload(child, deep=deep)
            for key, child in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        children = [_nested_validation_payload(child, deep=deep) for child in value]
        return tuple(children) if isinstance(value, tuple) else children
    return deepcopy(value) if deep else value


def _restore_nested_fields_set(validated: Any, source: Any) -> None:
    if isinstance(validated, BaseModel) and isinstance(source, BaseModel):
        object.__setattr__(
            validated,
            "__pydantic_fields_set__",
            set(source.model_fields_set).intersection(type(validated).model_fields),
        )
        for name in type(validated).model_fields:
            if hasattr(source, name):
                _restore_nested_fields_set(getattr(validated, name), getattr(source, name))
        return
    if isinstance(validated, Mapping) and isinstance(source, Mapping):
        for key in validated.keys() & source.keys():
            _restore_nested_fields_set(validated[key], source[key])
        return
    if (
        isinstance(validated, Sequence)
        and isinstance(source, Sequence)
        and not isinstance(validated, (str, bytes, bytearray))
        and not isinstance(source, (str, bytes, bytearray))
    ):
        for validated_child, source_child in zip(validated, source, strict=False):
            _restore_nested_fields_set(validated_child, source_child)


def _is_canonical_copy_source(source: Any, validated: Any) -> bool:
    if isinstance(source, BaseModel):
        if type(source) is not type(validated):
            return False
        field_names = set(type(source).model_fields)
        if (
            set(source.__dict__) != field_names
            or bool(getattr(source, "__pydantic_extra__", None))
            or getattr(source, "__pydantic_private__", None) not in (None, {})
            or not source.model_fields_set <= field_names
        ):
            return False
        return all(
            _is_canonical_copy_source(
                getattr(source, name),
                getattr(validated, name),
            )
            for name in type(source).model_fields
        )
    if isinstance(source, Mapping):
        if not isinstance(source, _FrozenMapping) or not isinstance(
            validated, Mapping
        ):
            return False
        source_keys = tuple(source)
        validated_keys = tuple(validated)
        return source_keys == validated_keys and all(
            _is_canonical_copy_source(source[key], validated[key])
            for key in source_keys
        )
    if isinstance(source, _FrozenSequence):
        return (
            isinstance(validated, _FrozenSequence)
            and len(source) == len(validated)
            and all(
                _is_canonical_copy_source(source_child, validated_child)
                for source_child, validated_child in zip(
                    source, validated, strict=True
                )
            )
        )
    if isinstance(source, tuple):
        return (
            isinstance(validated, tuple)
            and len(source) == len(validated)
            and all(
                _is_canonical_copy_source(source_child, validated_child)
                for source_child, validated_child in zip(
                    source, validated, strict=True
                )
            )
        )
    if isinstance(source, Sequence) and not isinstance(
        source, (str, bytes, bytearray)
    ):
        return False
    return type(source) is type(validated) and source == validated


def _contains_unicode_control(value: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)


def _require_target_paths(value: tuple[str, ...]) -> tuple[str, ...]:
    if value != tuple(sorted(value)) or any(
        not Path(item).is_absolute() or str(Path(item).resolve(strict=False)) != item
        for item in value
    ):
        raise ValueError("target paths must be sorted resolved absolute strings")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
    )

    @model_validator(mode="wrap")
    @classmethod
    def revalidate_model_instance(
        cls,
        value: Any,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, cls):
            return handler(value)
        validated = handler(_nested_validation_payload(value, deep=False))
        _restore_nested_fields_set(validated, value)
        return validated

    @model_validator(mode="after")
    def freeze_mutable_containers(self) -> "StrictModel":
        for name in type(self).model_fields:
            object.__setattr__(self, name, _deep_freeze(getattr(self, name)))
        return self

    def _serialization_clone(self) -> Self:
        values = {
            name: _deep_thaw(getattr(self, name)) for name in type(self).model_fields
        }
        return cast(
            Self,
            type(self).model_construct(
                _fields_set=set(self.model_fields_set),
                **values,
            ),
        )

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return BaseModel.model_dump(self._serialization_clone(), **kwargs)

    def model_dump_json(self, **kwargs: Any) -> str:
        return BaseModel.model_dump_json(self._serialization_clone(), **kwargs)

    @model_serializer(mode="wrap")
    def serialize_standard(self, handler: SerializerFunctionWrapHandler) -> Any:
        return handler(self._serialization_clone())

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is None:
            validated = type(self).model_validate(
                _nested_validation_payload(self, deep=False)
            )
            _restore_nested_fields_set(validated, self)
            if not _is_canonical_copy_source(self, validated):
                return BaseModel.model_copy(validated, deep=deep)
            return BaseModel.model_copy(self, deep=deep)

        merged = {
            name: self.__dict__[name]
            for name in type(self).model_fields
            if name in self.__dict__
        }
        merged.update(update)
        payload = {
            name: _nested_validation_payload(value, deep=deep)
            for name, value in merged.items()
        }
        copied = type(self).model_validate(payload)
        for name in type(self).model_fields:
            if name in merged:
                _restore_nested_fields_set(getattr(copied, name), merged[name])
        object.__setattr__(
            copied,
            "__pydantic_fields_set__",
            set(self.model_fields_set)
            .intersection(type(self).model_fields)
            .union(set(update).intersection(type(self).model_fields)),
        )
        return copied


class Asset(StrictModel):
    id: str
    name: str
    asset_type: str
    owner: str
    visibility: str
    lifecycle: str
    authority_class: str
    source_uri: str | None
    source_path: str | None
    source_revision: str
    source_checksum: str
    license_state: str
    revision_policy: str


class CapabilityManifest(StrictModel):
    discover: CapabilityState
    plan: CapabilityState
    apply: CapabilityState
    verify: CapabilityState
    rollback: CapabilityState
    bindings: CapabilityState = "unsupported"
    delete: CapabilityState = "unsupported"


class Target(StrictModel):
    id: str
    adapter_id: str
    protocol: Literal["filesystem", "api-import", "plugin", "package", "manual-assisted"]
    credential_ref: str | None = None
    config: dict[str, JsonValue]
    capabilities: CapabilityManifest

    @field_validator("credential_ref")
    @classmethod
    def require_credential_env_name(cls, value: str | None) -> str | None:
        if value is not None and (
            not value
            or value[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
            or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for character in value)
        ):
            raise ValueError("credential_ref must be an environment variable name")
        return value

    @model_validator(mode="after")
    def reject_secret_like_config_keys(self) -> "Target":
        def contains_sensitive_name(value: Any) -> bool:
            if isinstance(value, Mapping):
                return any(
                    is_sensitive_name(str(key))
                    or contains_sensitive_name(child)
                    for key, child in value.items()
                )
            if isinstance(value, Sequence) and not isinstance(
                value, (str, bytes, bytearray)
            ):
                return any(contains_sensitive_name(child) for child in value)
            return False

        if contains_sensitive_name(self.config):
            raise ValueError("secret-like config key is forbidden; use credential_ref")
        return self


class DeploymentProfile(StrictModel):
    id: str
    name: str
    selector: dict[str, JsonValue]
    policy_id: str


class ProfileMembership(StrictModel):
    id: str
    asset_id: str
    profile_id: str
    approved_at: datetime
    approval_ref: str


class ConsumerBinding(StrictModel):
    id: str
    asset_id: str
    target_id: str
    consumer_type: str
    consumer_id: str
    approved_at: datetime
    approval_ref: str


class PlanChange(StrictModel):
    change_type: ChangeType
    asset_id: str
    before_revision: str | None
    after_revision: str | None
    before_visibility: str | None
    after_visibility: str | None
    binding_id: str | None
    permission_delta: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]


class AdapterPlanEvidence(StrictModel):
    adapter_id: str
    target_id: str
    changes_digest: str
    resolved_target_paths: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    raw_evidence_digest: str

    @field_validator("resolved_target_paths")
    @classmethod
    def require_resolved_target_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_target_paths(value)

    @model_validator(mode="after")
    def require_plan_evidence_owner(self) -> "AdapterPlanEvidence":
        if any(ref.owner_type != "plan" for ref in self.evidence_refs):
            raise ValueError("plan evidence owner type is required")
        return self


class Plan(StrictModel):
    id: str
    operation: Literal["deploy", "rollback"]
    target_id: str
    parent_deployment_id: str | None
    changes: tuple[PlanChange, ...]
    risk: RiskLevel
    policy_decision: str
    policy_reasons: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    source_state_digest: str
    desired_state_digest: str
    observed_state_digest: str
    adapter_manifest_digest: str
    adapter_evidence_digest: str
    runtime_target_paths: tuple[str, ...]
    runtime_target_paths_digest: str
    evidence_refs: tuple[EvidenceRef, ...]
    plan_digest: str

    @field_validator("runtime_target_paths")
    @classmethod
    def require_runtime_target_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_target_paths(value)

    @model_validator(mode="after")
    def require_rollback_parent(self) -> "Plan":
        if self.operation == "rollback" and self.parent_deployment_id is None:
            raise ValueError("parent_deployment_id is required for rollback")
        if self.operation == "deploy" and self.parent_deployment_id is not None:
            raise ValueError("parent_deployment_id is only valid for rollback")
        refs = self.evidence_refs + tuple(
            ref for change in self.changes for ref in change.evidence_refs
        )
        if any(ref.owner_type != "plan" or ref.owner_id != self.id for ref in refs):
            raise ValueError("plan evidence owner must match plan id")
        return self


class Approval(StrictModel):
    id: str
    plan_id: str
    plan_digest: str
    decision: ApprovalDecision
    approver: str
    reason: str
    decided_at: datetime


class ObservedState(StrictModel):
    id: str
    target_id: str
    asset_id: str
    revision: str
    checksum: str
    discovered_at: datetime
    evidence_refs: tuple[EvidenceRef, ...]

    @model_validator(mode="after")
    def require_observation_evidence_owner(self) -> "ObservedState":
        if any(
            ref.owner_type != "observation" or ref.owner_id != self.id
            for ref in self.evidence_refs
        ):
            raise ValueError("observation evidence owner must match observation id")
        return self


class ProjectionDescriptor(StrictModel):
    plan_id: str
    root: str
    manifest_digest: str
    config_digest: str
    runtime_target_paths_digest: str

    @field_validator("root")
    @classmethod
    def require_resolved_root(cls, value: str) -> str:
        if not Path(value).is_absolute() or str(Path(value).resolve(strict=False)) != value:
            raise ValueError("projection root must be a resolved absolute string")
        return value


class DeploymentResult(StrictModel):
    deployment_id: str
    target_id: str
    resolved_target_paths: tuple[str, ...]
    changed_asset_ids: tuple[str, ...]
    result: str
    evidence_refs: tuple[EvidenceRef, ...]

    @field_validator("resolved_target_paths")
    @classmethod
    def require_resolved_target_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_target_paths(value)

    @model_validator(mode="after")
    def require_deployment_evidence_owner(self) -> "DeploymentResult":
        if any(
            ref.owner_type != "deployment" or ref.owner_id != self.deployment_id
            for ref in self.evidence_refs
        ):
            raise ValueError("deployment evidence owner must match deployment id")
        return self


class VerificationResult(StrictModel):
    deployment_id: str
    target_id: str
    resolved_target_paths: tuple[str, ...]
    healthy: bool
    drift: dict[str, JsonValue]
    evidence_refs: tuple[EvidenceRef, ...]

    @field_validator("resolved_target_paths")
    @classmethod
    def require_resolved_target_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_target_paths(value)

    @model_validator(mode="after")
    def require_deployment_evidence_owner(self) -> "VerificationResult":
        if any(
            ref.owner_type != "deployment" or ref.owner_id != self.deployment_id
            for ref in self.evidence_refs
        ):
            raise ValueError("deployment evidence owner must match deployment id")
        return self


class AssetDocument(StrictModel):
    schema_version: SchemaVersion
    items: tuple[Asset, ...]


class TargetDocument(StrictModel):
    schema_version: SchemaVersion
    items: tuple[Target, ...]


class DeploymentProfileDocument(StrictModel):
    schema_version: SchemaVersion
    items: tuple[DeploymentProfile, ...]


class ProfileMembershipDocument(StrictModel):
    schema_version: SchemaVersion
    items: tuple[ProfileMembership, ...]


class ConsumerBindingDocument(StrictModel):
    schema_version: SchemaVersion
    items: tuple[ConsumerBinding, ...]


class EvidenceRef(StrictModel):
    owner_type: Literal["command", "plan", "observation", "deployment", "review"]
    owner_id: str
    relative_path: str
    sha256: str
    media_type: str

    @field_validator("owner_id")
    @classmethod
    def require_owner_id(cls, value: str) -> str:
        if (
            not value
            or value in {".", ".."}
            or "/" in value
            or "\\" in value
            or _contains_unicode_control(value)
        ):
            raise ValueError("owner_id must be one safe path component")
        return value

    @field_validator("relative_path")
    @classmethod
    def require_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not value
            or value == "."
            or path.is_absolute()
            or "\\" in value
            or ".." in path.parts
            or bool(PureWindowsPath(value).drive)
            or _contains_unicode_control(value)
            or path.as_posix() != value
        ):
            raise ValueError("relative evidence path is invalid")
        return value

    @field_validator("sha256")
    @classmethod
    def require_sha256(cls, value: str) -> str:
        prefix, separator, digest = value.partition(":")
        if separator != ":" or prefix != "sha256" or len(digest) != 64:
            raise ValueError("sha256 digest is invalid")
        if any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("sha256 digest is invalid")
        return value


class DeploymentLedgerEntry(StrictModel):
    schema_version: SchemaVersion
    deployment_id: str
    plan_id: str
    parent_deployment_id: str | None
    target_id: str
    asset_ids: tuple[str, ...]
    source_revisions: dict[str, str]
    change_types: tuple[ChangeType, ...]
    approval_ref: str
    started_at: datetime
    finished_at: datetime
    result: str
    evidence_refs: tuple[EvidenceRef, ...]
    previous_entry_hash: str | None
    entry_hash: str

    @model_validator(mode="after")
    def require_deployment_evidence_owner(self) -> "DeploymentLedgerEntry":
        if any(
            ref.owner_type != "deployment" or ref.owner_id != self.deployment_id
            for ref in self.evidence_refs
        ):
            raise ValueError("deployment evidence owner must match deployment id")
        return self


class StatusReport(StrictModel):
    generated_at: datetime
    target_id: str | None
    target_health: dict[str, JsonValue]
    observed_revisions: dict[str, str]
    drift_count: int
    evidence_refs: tuple[EvidenceRef, ...]


class DriftReport(StrictModel):
    generated_at: datetime
    target_id: str | None
    changes: tuple[dict[str, JsonValue], ...]
    has_drift: bool
    evidence_refs: tuple[EvidenceRef, ...]


class ResolvedEvidence(StrictModel):
    owner_type: str
    owner_id: str
    relative_path: str
    sha256: str
    media_type: str
    byte_length: int
    content: bytes

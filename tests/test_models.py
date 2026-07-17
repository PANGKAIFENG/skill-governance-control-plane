import copy
import json
import pickle
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import get_args

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

import skillctl.models as models
from skillctl.config import ControlPlaneConfig
from skillctl.errors import SafetyViolation
from skillctl.models import (
    AdapterPlanEvidence,
    Approval,
    Asset,
    AssetDocument,
    ConsumerBinding,
    DeploymentLedgerEntry,
    DeploymentProfile,
    DeploymentResult,
    EvidenceRef,
    ObservedState,
    Plan,
    PlanChange,
    ProfileMembership,
    ProjectionDescriptor,
    ResolvedEvidence,
    Target,
    TargetDocument,
    VerificationResult,
)


def test_asset_document_rejects_unknown_schema_version() -> None:
    with pytest.raises(ValidationError, match="schema_version"):
        AssetDocument.model_validate({"schema_version": "2.0", "items": []})


def test_stable_aliases_expose_exact_literal_values() -> None:
    expected = {
        "SchemaVersion": ("1.0",),
        "CapabilityState": ("supported", "unsupported", "unverified"),
        "ChangeType": ("create", "update", "bind", "unbind", "deprecate", "prune", "publish"),
        "RiskLevel": ("low", "medium", "high", "critical"),
        "ApprovalDecision": ("approved", "rejected"),
    }
    assert {name: get_args(getattr(models, name)) for name in expected} == expected


def test_entity_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Asset.model_validate({"unexpected": True})


def test_target_has_typed_capabilities_and_safe_defaults() -> None:
    target = Target.model_validate(
        {
            "id": "local",
            "adapter_id": "filesystem",
            "protocol": "filesystem",
            "credential_ref": "DEPLOY_TOKEN",
            "config": {},
            "capabilities": {
                "discover": "supported",
                "plan": "supported",
                "apply": "supported",
                "verify": "supported",
                "rollback": "unsupported",
            },
        }
    )
    assert target.capabilities.bindings == "unsupported"
    assert target.capabilities.delete == "unsupported"


def test_target_rejects_secret_like_config_keys() -> None:
    payload = {
        "schema_version": "1.0",
        "items": [
            {
                "id": "github",
                "adapter_id": "github",
                "protocol": "package",
                "credential_ref": "GH_TOKEN",
                "config": {"token": "must-not-be-stored"},
                "capabilities": {
                    "discover": "supported",
                    "plan": "supported",
                    "apply": "supported",
                    "verify": "supported",
                    "rollback": "unsupported",
                },
            }
        ],
    }
    with pytest.raises(ValidationError, match="secret-like config key"):
        TargetDocument.model_validate(payload)


def test_domain_entities_expose_exact_required_fields() -> None:
    expected = {
        Asset: "id name asset_type owner visibility lifecycle authority_class source_uri source_path source_revision source_checksum license_state revision_policy",
        Target: "id adapter_id protocol credential_ref config capabilities",
        DeploymentProfile: "id name selector policy_id",
        ProfileMembership: "id asset_id profile_id approved_at approval_ref",
        ConsumerBinding: "id asset_id target_id consumer_type consumer_id approved_at approval_ref",
        EvidenceRef: "owner_type owner_id relative_path sha256 media_type",
        PlanChange: "change_type asset_id before_revision after_revision before_visibility after_visibility binding_id permission_delta evidence_refs",
        AdapterPlanEvidence: "adapter_id target_id changes_digest resolved_target_paths evidence_refs raw_evidence_digest",
        Plan: "id operation target_id parent_deployment_id changes risk policy_decision policy_reasons created_at expires_at source_state_digest desired_state_digest observed_state_digest adapter_manifest_digest adapter_evidence_digest runtime_target_paths runtime_target_paths_digest evidence_refs plan_digest",
        Approval: "id plan_id plan_digest decision approver reason decided_at",
        ObservedState: "id target_id asset_id revision checksum discovered_at evidence_refs",
        ProjectionDescriptor: "plan_id root manifest_digest config_digest runtime_target_paths_digest",
        ResolvedEvidence: "owner_type owner_id relative_path sha256 media_type byte_length content",
        DeploymentResult: "deployment_id target_id resolved_target_paths changed_asset_ids result evidence_refs",
        VerificationResult: "deployment_id target_id resolved_target_paths healthy drift evidence_refs",
        DeploymentLedgerEntry: "schema_version deployment_id plan_id parent_deployment_id target_id asset_ids source_revisions change_types approval_ref started_at finished_at result evidence_refs previous_entry_hash entry_hash",
    }
    for model, field_names in expected.items():
        assert set(model.model_fields) == set(field_names.split())


def plan_payload(**updates: object) -> dict[str, object]:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "id": "plan-1",
        "operation": "deploy",
        "target_id": "target-1",
        "parent_deployment_id": None,
        "changes": (),
        "risk": "low",
        "policy_decision": "allow",
        "policy_reasons": (),
        "created_at": now,
        "expires_at": now + timedelta(minutes=5),
        "source_state_digest": "source",
        "desired_state_digest": "desired",
        "observed_state_digest": "observed",
        "adapter_manifest_digest": "manifest",
        "adapter_evidence_digest": "adapter-evidence",
        "runtime_target_paths": ("/private/tmp/runtime",),
        "runtime_target_paths_digest": "paths",
        "evidence_refs": (),
        "plan_digest": "plan",
    }
    payload.update(updates)
    return payload


def test_rollback_plan_requires_parent_deployment() -> None:
    with pytest.raises(ValidationError, match="parent_deployment_id"):
        Plan.model_validate(plan_payload(operation="rollback"))


def test_deploy_plan_rejects_parent_deployment() -> None:
    with pytest.raises(ValidationError, match="parent_deployment_id"):
        Plan.model_validate(plan_payload(parent_deployment_id="deployment-0"))


def test_plan_rejects_unsorted_runtime_target_paths() -> None:
    with pytest.raises(ValidationError, match="sorted resolved absolute"):
        Plan.model_validate(
            plan_payload(runtime_target_paths=("/private/tmp/z", "/private/tmp/a"))
        )


def test_adapter_evidence_rejects_relative_target_paths() -> None:
    with pytest.raises(ValidationError, match="sorted resolved absolute"):
        AdapterPlanEvidence(
            adapter_id="filesystem",
            target_id="target-1",
            changes_digest="changes",
            resolved_target_paths=("relative/runtime",),
            evidence_refs=(),
            raw_evidence_digest="raw",
        )


def test_deployment_and_verification_reject_unsorted_target_paths() -> None:
    paths = ("/private/tmp/z", "/private/tmp/a")
    with pytest.raises(ValidationError, match="sorted resolved absolute"):
        DeploymentResult(
            deployment_id="deployment-1",
            target_id="target-1",
            resolved_target_paths=paths,
            changed_asset_ids=(),
            result="succeeded",
            evidence_refs=(),
        )
    with pytest.raises(ValidationError, match="sorted resolved absolute"):
        VerificationResult(
            deployment_id="deployment-1",
            target_id="target-1",
            resolved_target_paths=paths,
            healthy=True,
            drift={},
            evidence_refs=(),
        )


def test_projection_descriptor_requires_resolved_absolute_root() -> None:
    with pytest.raises(ValidationError, match="resolved absolute"):
        ProjectionDescriptor(
            plan_id="plan-1",
            root="relative/projection",
            manifest_digest="manifest",
            config_digest="config",
            runtime_target_paths_digest="paths",
        )


def test_target_credential_ref_must_be_environment_variable_name() -> None:
    with pytest.raises(ValidationError, match="credential_ref"):
        Target(
            id="target-1",
            adapter_id="filesystem",
            protocol="filesystem",
            credential_ref="actual-secret-value",
            config={},
            capabilities={
                "discover": "supported",
                "plan": "supported",
                "apply": "supported",
                "verify": "supported",
                "rollback": "unsupported",
            },
        )


def test_plan_evidence_refs_must_match_plan_owner() -> None:
    ref = EvidenceRef(
        owner_type="plan",
        owner_id="plan-2",
        relative_path="diff.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    with pytest.raises(ValidationError, match="plan evidence owner"):
        Plan.model_validate(plan_payload(evidence_refs=(ref,)))


def test_observation_evidence_refs_must_match_observation_owner() -> None:
    ref = EvidenceRef(
        owner_type="plan",
        owner_id="observation-1",
        relative_path="state.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    with pytest.raises(ValidationError, match="observation evidence owner"):
        ObservedState(
            id="observation-1",
            target_id="target-1",
            asset_id="asset-1",
            revision="revision-1",
            checksum="checksum-1",
            discovered_at=datetime.now(UTC),
            evidence_refs=(ref,),
        )


def test_deployment_result_evidence_refs_must_match_deployment_owner() -> None:
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-2",
        relative_path="result.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    with pytest.raises(ValidationError, match="deployment evidence owner"):
        DeploymentResult(
            deployment_id="deployment-1",
            target_id="target-1",
            resolved_target_paths=("/private/tmp/runtime",),
            changed_asset_ids=(),
            result="succeeded",
            evidence_refs=(ref,),
        )


def test_control_plane_config_resolves_all_roots(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    trusted_cli_paths = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        trusted_cli_paths[name] = executable
    config = ControlPlaneConfig(
        registry_root="registry",
        state_root="state",
        evidence_root="evidence",
        projection_root="projections",
        authority_roots=("authority",),
        allowed_runtime_roots=("runtime",),
        trusted_cli_paths=trusted_cli_paths,
    )
    assert config.registry_root == (tmp_path / "registry").resolve()
    assert config.authority_roots == ((tmp_path / "authority").resolve(),)
    assert config.allowed_runtime_roots == ((tmp_path / "runtime").resolve(),)
    assert config.trusted_path == "/opt/homebrew/bin:/usr/bin:/bin"


def test_control_plane_config_rejects_relative_executable(tmp_path) -> None:
    with pytest.raises(ValidationError, match="absolute executable"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths={"skillshare": Path("skillshare"), "gh": Path("gh")},
        )


def test_control_plane_config_rejects_executable_outside_allowlist(tmp_path) -> None:
    with pytest.raises(ValidationError, match="executable allowlist"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths={"wget": tmp_path / "wget"},
        )


def test_control_plane_config_rejects_mismatched_executable_name(tmp_path) -> None:
    with pytest.raises(ValidationError, match="executable allowlist"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths={"skillshare": tmp_path / "rm", "gh": tmp_path / "gh"},
        )


def test_control_plane_config_rejects_missing_executable(tmp_path) -> None:
    with pytest.raises(ValidationError, match="missing executable"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths={
                "skillshare": tmp_path / "skillshare",
                "gh": tmp_path / "gh",
            },
        )


def test_control_plane_config_validates_default_cli_paths(tmp_path, monkeypatch) -> None:
    canonical_default_paths = {
        Path("/opt/homebrew/bin/skillshare").resolve(strict=False),
        Path("/opt/homebrew/bin/gh").resolve(strict=False),
    }
    real_stat = Path.stat

    def unavailable(path: Path, *, follow_symlinks: bool = True):
        if path in canonical_default_paths:
            raise FileNotFoundError(path)
        return real_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", unavailable)
    with pytest.raises(ValidationError, match="missing executable"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
        )


def test_control_plane_config_rejects_nonregular_executable(tmp_path) -> None:
    skillshare = tmp_path / "skillshare"
    gh = tmp_path / "gh"
    skillshare.mkdir()
    gh.mkdir()
    with pytest.raises(ValidationError, match="regular executable"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths={"skillshare": skillshare, "gh": gh},
        )


def test_control_plane_config_rejects_nonexecutable_file(tmp_path) -> None:
    skillshare = tmp_path / "skillshare"
    gh = tmp_path / "gh"
    skillshare.write_text("#!/bin/sh\n")
    gh.write_text("#!/bin/sh\n")
    with pytest.raises(ValidationError, match="executable permission"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths={"skillshare": skillshare, "gh": gh},
        )


def test_control_plane_config_requires_current_user_execute_access(tmp_path) -> None:
    skillshare = tmp_path / "skillshare"
    gh = tmp_path / "gh"
    skillshare.write_text("#!/bin/sh\n")
    gh.write_text("#!/bin/sh\n")
    skillshare.chmod(0o001)
    gh.chmod(0o755)

    with pytest.raises(ValidationError, match="executable permission"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths={"skillshare": skillshare, "gh": gh},
        )


def test_control_plane_config_rejects_resolved_authority_runtime_overlap(tmp_path) -> None:
    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    trusted_cli_paths = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        trusted_cli_paths[name] = executable
    with pytest.raises(ValidationError, match="authority.*runtime.*overlap"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            state_root=tmp_path / "state",
            evidence_root=tmp_path / "evidence",
            projection_root=tmp_path / "projections",
            authority_roots=(tmp_path / "authority",),
            allowed_runtime_roots=(tmp_path / "other" / ".." / "authority" / "runtime",),
            trusted_cli_paths=trusted_cli_paths,
        )


@pytest.mark.parametrize("writable_field", ("state_root", "evidence_root", "projection_root"))
@pytest.mark.parametrize("relationship", ("equal", "writable_parent", "authority_parent"))
def test_control_plane_config_rejects_writable_root_authority_overlap(
    tmp_path: Path,
    writable_field: str,
    relationship: str,
) -> None:
    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    trusted_cli_paths = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        trusted_cli_paths[name] = executable
    if relationship == "equal":
        writable_root = authority_root = tmp_path / "overlap"
    elif relationship == "writable_parent":
        writable_root = tmp_path / "overlap"
        authority_root = writable_root / "authority"
    else:
        authority_root = tmp_path / "overlap"
        writable_root = authority_root / "writable"
    roots = {
        "state_root": tmp_path / "state",
        "evidence_root": tmp_path / "evidence",
        "projection_root": tmp_path / "projections",
    }
    roots[writable_field] = writable_root

    with pytest.raises(ValidationError, match="writable.*authority.*overlap"):
        ControlPlaneConfig(
            registry_root=tmp_path / "registry",
            **roots,
            authority_roots=(authority_root,),
            allowed_runtime_roots=(tmp_path / "runtime",),
            trusted_cli_paths=trusted_cli_paths,
        )


def test_control_plane_errors_redact_environment_secret_values(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "actual-environment-secret")
    error = SafetyViolation("adapter failed: actual-environment-secret")
    assert "actual-environment-secret" not in str(error)
    assert "<redacted>" in str(error)


def test_control_plane_errors_redact_short_environment_values(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "abc")
    error = SafetyViolation("adapter failed: abc")
    assert "abc" not in str(error)
    assert str(error) == "adapter failed: <redacted>"


def test_control_plane_errors_use_sensitive_names_and_value_boundaries(
    monkeypatch,
) -> None:
    monkeypatch.setenv("API_TOKEN", "a")
    monkeypatch.setenv("DISPLAY_NAME", "failed")

    assert str(SafetyViolation("a")) == "<redacted>"
    assert str(SafetyViolation("adapter failed safely")) == "request rejected"


def test_control_plane_errors_redact_common_names_and_embedded_long_values(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SERVICE_APIKEY", "embedded-api-key-value")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@db/service")
    monkeypatch.setenv("TRACE_DSN", "https://public:private@example.invalid/1")

    message = (
        "adapter embedded-api-key-value failed for "
        "postgresql://user:password@db/service and "
        "https://public:private@example.invalid/1"
    )
    assert str(SafetyViolation(message)) == (
        "adapter <redacted> failed for <redacted> and <redacted>"
    )
    monkeypatch.setenv("API_TOKEN", "a")
    assert str(SafetyViolation("a")) == "<redacted>"
    assert str(SafetyViolation("token a rejected")) == "token <redacted> rejected"
    assert str(SafetyViolation("adapter failed safely")) == "request rejected"


def test_control_plane_errors_redact_pat_and_authorization_values(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_PAT", "github-personal-access-value")
    monkeypatch.setenv("HTTP_AUTHORIZATION", "Bearer authorization-value")

    error = SafetyViolation(
        "adapter github-personal-access-value rejected Bearer authorization-value"
    )

    assert str(error) == "adapter <redacted> rejected <redacted>"


def test_control_plane_errors_fail_safe_for_embedded_short_secrets(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "abc")

    error = SafetyViolation("adapter abcfailed")

    assert str(error) == "control-plane operation failed safely"


def test_control_plane_errors_share_sensitive_name_classification(
    monkeypatch,
) -> None:
    sensitive = {
        "PGPASSWORD": "postgres-password-value",
        "MYSQL_PWD": "mysql-password-value",
        "REDIS_URL": "redis://credential@example.invalid/1",
        "MONGODB_URI": "mongodb://credential@example.invalid/1",
        "COOKIE": "session-cookie-value",
    }
    for name, value in sensitive.items():
        monkeypatch.setenv(name, value)
    message = " | ".join(sensitive.values())
    assert str(SafetyViolation(message)) == " | ".join(
        "<redacted>" for _ in sensitive
    )

    ordinary = {
        "MONKEY": "ordinary-monkey-value",
        "DISPLAY_NAME": "ordinary-display-name",
        "CREDENTIAL_REF": "ordinary-credential-reference",
    }
    for name, value in ordinary.items():
        monkeypatch.setenv(name, value)
    ordinary_message = " | ".join(ordinary.values())
    assert str(SafetyViolation(ordinary_message)) == ordinary_message


def test_verification_evidence_refs_must_match_deployment_owner() -> None:
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-2",
        relative_path="verify.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    with pytest.raises(ValidationError, match="deployment evidence owner"):
        VerificationResult(
            deployment_id="deployment-1",
            target_id="target-1",
            resolved_target_paths=("/private/tmp/runtime",),
            healthy=True,
            drift={},
            evidence_refs=(ref,),
        )


def test_ledger_evidence_refs_must_match_deployment_owner() -> None:
    ref = EvidenceRef(
        owner_type="review",
        owner_id="deployment-1",
        relative_path="result.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="deployment evidence owner"):
        DeploymentLedgerEntry(
            schema_version="1.0",
            deployment_id="deployment-1",
            plan_id="plan-1",
            parent_deployment_id=None,
            target_id="target-1",
            asset_ids=("asset-1",),
            source_revisions={"asset-1": "rev-1"},
            change_types=("update",),
            approval_ref="approval-1",
            started_at=now,
            finished_at=now,
            result="succeeded",
            evidence_refs=(ref,),
            previous_entry_hash=None,
            entry_hash="sha256:" + "1" * 64,
        )


def test_adapter_plan_evidence_references_plan_owner_type() -> None:
    ref = EvidenceRef(
        owner_type="review",
        owner_id="review-1",
        relative_path="dry-run.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    with pytest.raises(ValidationError, match="plan evidence owner"):
        AdapterPlanEvidence(
            adapter_id="filesystem",
            target_id="target-1",
            changes_digest="changes",
            resolved_target_paths=("/private/tmp/runtime",),
            evidence_refs=(ref,),
            raw_evidence_digest="raw",
        )


def test_projection_descriptor_is_frozen() -> None:
    descriptor = ProjectionDescriptor(
        plan_id="plan-1",
        root="/private/tmp/projection",
        manifest_digest="manifest",
        config_digest="config",
        runtime_target_paths_digest="paths",
    )
    with pytest.raises(ValidationError, match="frozen"):
        descriptor.root = "/private/tmp/changed"


def test_security_model_mappings_are_deeply_frozen_and_serializable() -> None:
    nested_config = {"nested": {"items": ["one", {"enabled": True}]}}
    target = Target(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config=nested_config,
        capabilities={
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    )
    profile = DeploymentProfile(
        id="profile-1",
        name="Profile",
        selector={"labels": ["approved"]},
        policy_id="policy-1",
    )
    verification = VerificationResult(
        deployment_id="deployment-1",
        target_id="target-1",
        resolved_target_paths=("/private/tmp/runtime",),
        healthy=False,
        drift={"assets": [{"id": "asset-1"}]},
        evidence_refs=(),
    )
    now = datetime.now(UTC)
    ledger = DeploymentLedgerEntry(
        schema_version="1.0",
        deployment_id="deployment-1",
        plan_id="plan-1",
        parent_deployment_id=None,
        target_id="target-1",
        asset_ids=("asset-1",),
        source_revisions={"asset-1": "rev-1"},
        change_types=("update",),
        approval_ref="approval-1",
        started_at=now,
        finished_at=now,
        result="succeeded",
        evidence_refs=(),
        previous_entry_hash=None,
        entry_hash="sha256:" + "1" * 64,
    )

    with pytest.raises(TypeError):
        target.config["new"] = True
    with pytest.raises(TypeError):
        target.config["nested"]["items"].append("two")
    with pytest.raises(TypeError):
        profile.selector["labels"].append("other")
    with pytest.raises(TypeError):
        verification.drift["assets"][0]["id"] = "changed"
    with pytest.raises(TypeError):
        ledger.source_revisions["asset-1"] = "rev-2"

    dumped = target.model_dump(mode="json")
    assert dumped["config"] == nested_config
    assert json.loads(target.model_dump_json())["config"] == nested_config


def test_security_models_prevent_base_bypasses_and_revalidate_model_copy() -> None:
    target = Target(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config={"nested": {"items": ["one", {"enabled": True}]}},
        capabilities={
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    )

    assert isinstance(target.config, Mapping)
    assert not isinstance(target.config, dict)
    nested_items = target.config["nested"]["items"]
    assert isinstance(nested_items, Sequence)
    assert not isinstance(nested_items, list)
    with pytest.raises(TypeError):
        dict.__setitem__(target.config, "bypass", True)
    with pytest.raises(TypeError):
        list.append(nested_items, "bypass")

    updated = target.model_copy(
        update={"config": {"nested": {"items": ["updated"]}}}
    )
    assert not isinstance(updated.config, dict)
    with pytest.raises(TypeError):
        updated.config["nested"]["items"].append("bypass")
    with pytest.raises(ValidationError, match="secret-like config key"):
        target.model_copy(update={"config": {"nested": {"api_key": "secret"}}})

    for clone in (
        target.model_copy(deep=True),
        copy.deepcopy(target),
        pickle.loads(pickle.dumps(target)),
    ):
        assert clone.model_dump(mode="json") == target.model_dump(mode="json")
        assert not isinstance(clone.config, dict)
        with pytest.raises(TypeError):
            clone.config["nested"]["items"].append("bypass")


def test_model_copy_preserves_fields_set_and_validates_explicit_updates() -> None:
    target = Target.model_validate(
        {
            "id": "target-1",
            "adapter_id": "filesystem",
            "protocol": "filesystem",
            "config": {"nested": {"items": ["one"]}},
            "capabilities": {
                "discover": "supported",
                "plan": "supported",
                "apply": "supported",
                "verify": "supported",
                "rollback": "unsupported",
            },
        }
    )
    expected_dump = target.model_dump(exclude_unset=True)
    expected_fields = target.model_fields_set
    expected_capability_fields = target.capabilities.model_fields_set

    shallow = target.model_copy()
    deep = target.model_copy(deep=True)
    for clone in (shallow, deep):
        assert clone.model_fields_set == expected_fields
        assert clone.capabilities.model_fields_set == expected_capability_fields
        assert clone.model_dump(exclude_unset=True) == expected_dump
    assert shallow.capabilities is target.capabilities
    assert shallow.config is target.config
    assert deep.capabilities is not target.capabilities
    assert deep.config is not target.config

    updated = target.model_copy(update={"credential_ref": "DEPLOY_TOKEN"})
    assert updated.model_fields_set == expected_fields | {"credential_ref"}
    assert updated.capabilities.model_fields_set == expected_capability_fields
    assert updated.model_dump(exclude_unset=True)["credential_ref"] == "DEPLOY_TOKEN"
    with pytest.raises(ValidationError, match="secret-like config key"):
        target.model_copy(update={"config": {"api_key": "secret"}})

    deep_updated = target.model_copy(
        update={"credential_ref": "DEPLOY_TOKEN"},
        deep=True,
    )
    assert deep_updated.model_fields_set == expected_fields | {"credential_ref"}
    assert deep_updated.capabilities.model_fields_set == expected_capability_fields
    assert deep_updated.capabilities is not target.capabilities
    assert deep_updated.config is not target.config

    update_config = {"nested": {"items": ["updated"]}}
    update_capabilities = models.CapabilityManifest.model_validate(
        {
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        }
    )
    deep_container_updated = target.model_copy(
        update={
            "config": update_config,
            "capabilities": update_capabilities,
        },
        deep=True,
    )
    update_config["nested"]["items"].append("mutated-after-copy")
    assert deep_container_updated.model_fields_set == expected_fields
    assert deep_container_updated.capabilities.model_fields_set == (
        update_capabilities.model_fields_set
    )
    assert deep_container_updated.capabilities is not update_capabilities
    assert deep_container_updated.model_dump(mode="json")["config"] == {
        "nested": {"items": ["updated"]}
    }


@pytest.mark.parametrize("deep", (False, True))
def test_model_copy_revalidates_constructed_nested_model_updates(deep: bool) -> None:
    target = Target(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config={},
        capabilities={
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    )
    invalid_capabilities = models.CapabilityManifest.model_construct(
        discover="supported",
        plan="supported",
        apply="INVALID",
        verify="supported",
        rollback="unsupported",
        bindings="unsupported",
        delete="unsupported",
    )
    with pytest.raises(ValidationError, match="apply"):
        target.model_copy(
            update={"capabilities": invalid_capabilities},
            deep=deep,
        )

    class EvidenceContainers(models.StrictModel):
        item_tuple: tuple[EvidenceRef, ...]
        item_list: list[EvidenceRef]
        item_map: dict[str, EvidenceRef]

    valid_ref = EvidenceRef(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="valid.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    containers = EvidenceContainers(
        item_tuple=(valid_ref,),
        item_list=[valid_ref],
        item_map={"valid": valid_ref},
    )
    invalid_ref = EvidenceRef.model_construct(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="../escape.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    invalid_updates = (
        {"item_tuple": (invalid_ref,)},
        {"item_list": [invalid_ref]},
        {"item_map": {"invalid": invalid_ref}},
    )
    for update in invalid_updates:
        with pytest.raises(ValidationError, match="relative evidence path"):
            containers.model_copy(update=update, deep=deep)


@pytest.mark.parametrize("deep", (False, True))
def test_model_copy_reports_missing_constructed_nested_model_fields(
    deep: bool,
) -> None:
    target = Target(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config={},
        capabilities={
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    )
    incomplete = models.CapabilityManifest.model_construct(discover="supported")

    with pytest.raises(ValidationError, match="plan"):
        target.model_copy(update={"capabilities": incomplete}, deep=deep)


@pytest.mark.parametrize("deep", (False, True))
def test_model_copy_revalidates_existing_nested_models_on_unrelated_update(
    deep: bool,
) -> None:
    polluted_capabilities = models.CapabilityManifest.model_construct(
        discover="supported",
        plan="supported",
        apply="INVALID",
        verify="supported",
        rollback="unsupported",
        bindings="unsupported",
        delete="unsupported",
    )
    polluted_target = Target.model_construct(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config={},
        capabilities=polluted_capabilities,
    )
    with pytest.raises(ValidationError, match="apply"):
        polluted_target.model_copy(
            update={"credential_ref": "DEPLOY_TOKEN"},
            deep=deep,
        )

    class EvidenceContainers(models.StrictModel):
        marker: str
        item_tuple: tuple[EvidenceRef, ...]
        item_list: list[EvidenceRef]
        item_map: dict[str, EvidenceRef]

    invalid_ref = EvidenceRef.model_construct(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="../escape.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    polluted_containers = EvidenceContainers.model_construct(
        marker="before",
        item_tuple=(invalid_ref,),
        item_list=[invalid_ref],
        item_map={"invalid": invalid_ref},
    )
    with pytest.raises(ValidationError, match="relative evidence path"):
        polluted_containers.model_copy(update={"marker": "after"}, deep=deep)


def test_strict_models_support_pydantic_standard_serialization_boundaries() -> None:
    target = Target(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config={"nested": {"items": ["one", "two"]}},
        capabilities={
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    )
    expected = target.model_dump(mode="json")
    adapter = TypeAdapter(Target)

    assert adapter.dump_python(target, mode="json") == expected
    assert json.loads(adapter.dump_json(target)) == expected

    class TargetEnvelope(BaseModel):
        target: Target

    envelope = TargetEnvelope(target=target)
    assert envelope.model_dump(mode="json")["target"] == expected
    assert json.loads(envelope.model_dump_json())["target"] == expected


def test_strict_models_revalidate_instances_and_fail_closed_on_noop_copy() -> None:
    polluted_capabilities = models.CapabilityManifest.model_construct(
        discover="supported",
        plan="supported",
        apply="INVALID",
        verify="supported",
        rollback="unsupported",
        bindings="unsupported",
        delete="unsupported",
    )
    polluted_target = Target.model_construct(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config={},
        capabilities=polluted_capabilities,
    )
    with pytest.raises(ValidationError, match="apply"):
        Target.model_validate(polluted_target)
    with pytest.raises(ValidationError, match="apply"):
        TargetDocument.model_validate(
            {"schema_version": "1.0", "items": [polluted_target]}
        )
    for deep in (False, True):
        with pytest.raises(ValidationError, match="apply"):
            polluted_target.model_copy(deep=deep)

    invalid_ref = EvidenceRef.model_construct(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="../escape.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    with pytest.raises(ValidationError, match="relative evidence path"):
        Plan.model_validate(plan_payload(evidence_refs=(invalid_ref,)))

    target = Target.model_validate(
        {
            "id": "target-1",
            "adapter_id": "filesystem",
            "protocol": "filesystem",
            "config": {"nested": {"items": ["one"]}},
            "capabilities": {
                "discover": "supported",
                "plan": "supported",
                "apply": "supported",
                "verify": "supported",
                "rollback": "unsupported",
            },
        }
    )
    expected_fields_set = set(target.model_fields_set)
    revalidated = Target.model_validate(target)
    assert revalidated.model_dump(mode="json") == target.model_dump(mode="json")
    assert revalidated.model_fields_set == expected_fields_set

    shallow = target.model_copy()
    deep = target.model_copy(deep=True)
    assert shallow.model_fields_set == deep.model_fields_set == expected_fields_set
    assert shallow.config is target.config
    assert shallow.capabilities is target.capabilities
    assert deep.config is not target.config
    assert deep.capabilities is not target.capabilities
    assert json.loads(TypeAdapter(Target).dump_json(shallow)) == target.model_dump(
        mode="json"
    )


@pytest.mark.parametrize("deep", (False, True))
def test_noop_model_copy_returns_canonical_output_for_polluted_valid_source(
    deep: bool,
) -> None:
    target = Target.model_validate(
        {
            "id": "target-1",
            "adapter_id": "filesystem",
            "protocol": "filesystem",
            "config": {"nested": {"items": ["one"]}},
            "capabilities": {
                "discover": "supported",
                "plan": "supported",
                "apply": "supported",
                "verify": "supported",
                "rollback": "unsupported",
            },
        }
    )
    expected_fields_set = set(target.model_fields_set)
    expected_capability_fields_set = set(target.capabilities.model_fields_set)
    polluted_config = {"nested": {"items": ["one"]}}
    object.__setattr__(target, "config", polluted_config)
    target.__dict__["unexpected"] = "polluted-state"

    copied = target.model_copy(deep=deep)

    assert target.config is polluted_config
    assert not isinstance(copied.config, dict)
    assert "unexpected" not in copied.__dict__
    assert not hasattr(copied, "unexpected")
    assert copied.model_fields_set == expected_fields_set
    assert copied.capabilities.model_fields_set == expected_capability_fields_set
    with pytest.raises(TypeError):
        copied.config["nested"]["items"].append("bypass")


@pytest.mark.parametrize("deep", (False, True))
def test_noop_model_copy_sanitizes_unknown_root_and_nested_fields_set(
    deep: bool,
) -> None:
    target = Target.model_validate(
        {
            "id": "target-1",
            "adapter_id": "filesystem",
            "protocol": "filesystem",
            "config": {"nested": {"items": ["one"]}},
            "capabilities": {
                "discover": "supported",
                "plan": "supported",
                "apply": "supported",
                "verify": "supported",
                "rollback": "unsupported",
            },
        }
    )
    expected_root_fields_set = set(target.model_fields_set)
    expected_nested_fields_set = set(target.capabilities.model_fields_set)
    target.__pydantic_fields_set__.add("unexpected_root")
    target.capabilities.__pydantic_fields_set__.add("unexpected_nested")

    copied = target.model_copy(deep=deep)

    assert copied.model_fields_set == expected_root_fields_set
    assert copied.capabilities.model_fields_set == expected_nested_fields_set
    assert "unexpected_root" not in copied.model_fields_set
    assert "unexpected_nested" not in copied.capabilities.model_fields_set


@pytest.mark.parametrize("deep", (False, True))
def test_update_model_copy_sanitizes_unknown_root_and_nested_fields_set(
    deep: bool,
) -> None:
    target = Target.model_validate(
        {
            "id": "target-1",
            "adapter_id": "filesystem",
            "protocol": "filesystem",
            "config": {"nested": {"items": ["one"]}},
            "capabilities": {
                "discover": "supported",
                "plan": "supported",
                "apply": "supported",
                "verify": "supported",
                "rollback": "unsupported",
            },
        }
    )
    expected_root_fields_set = set(target.model_fields_set)
    expected_nested_fields_set = set(target.capabilities.model_fields_set)
    source_capabilities = target.capabilities
    source_config = target.config
    target.__pydantic_fields_set__.add("unexpected_root")
    target.capabilities.__pydantic_fields_set__.add("unexpected_nested")

    copied = target.model_copy(
        update={"credential_ref": "DEPLOY_TOKEN"},
        deep=deep,
    )

    assert copied.model_fields_set == expected_root_fields_set | {"credential_ref"}
    assert copied.capabilities.model_fields_set == expected_nested_fields_set
    assert "unexpected_root" not in copied.model_fields_set
    assert "unexpected_nested" not in copied.capabilities.model_fields_set
    assert copied.capabilities is not source_capabilities
    assert copied.config is not source_config
    assert "unexpected_root" in target.model_fields_set
    assert "unexpected_nested" in target.capabilities.model_fields_set


@pytest.mark.parametrize(
    "sensitive_name",
    (
        "access_token",
        "client_secret",
        "authorization",
        "apikey",
        "password_file",
        "database_url",
    ),
)
def test_target_classifies_credential_bearing_config_keys(
    sensitive_name: str,
) -> None:
    payload = {
        "id": "target-1",
        "adapter_id": "filesystem",
        "protocol": "filesystem",
        "credential_ref": "DEPLOY_TOKEN",
        "config": {"nested": {sensitive_name: "must-not-be-stored"}},
        "capabilities": {
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    }
    with pytest.raises(ValidationError, match="secret-like config key"):
        Target.model_validate(payload)

    payload["config"] = {"monkey": "capuchin", "display_name": "Production"}
    target = Target.model_validate(payload)
    assert target.credential_ref == "DEPLOY_TOKEN"


@pytest.mark.parametrize(
    "sensitive_name",
    (
        "clientSecret",
        "accessToken",
        "databaseUrl",
        "mongodbUri",
        "redisUrl",
        "CLIENTSECRET",
        "ACCESSTOKEN",
        "DATABASEURL",
    ),
)
def test_sensitive_name_classifier_handles_camel_and_compact_names(
    sensitive_name: str,
    monkeypatch,
) -> None:
    payload = {
        "id": "target-1",
        "adapter_id": "filesystem",
        "protocol": "filesystem",
        "credential_ref": "DEPLOY_TOKEN",
        "config": {"nested": {sensitive_name: "must-not-be-stored"}},
        "capabilities": {
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    }
    with pytest.raises(ValidationError, match="secret-like config key"):
        Target.model_validate(payload)

    secret_value = f"sensitive-value-for-{sensitive_name}"
    monkeypatch.setenv(sensitive_name, secret_value)
    assert str(SafetyViolation(secret_value)) == "<redacted>"

    ordinary = {
        "MONKEY": "ordinary-monkey-value",
        "DISPLAY_NAME": "ordinary-display-name",
        "CREDENTIAL_REF": "ordinary-credential-reference",
    }
    payload["config"] = {name: value for name, value in ordinary.items()}
    assert Target.model_validate(payload).credential_ref == "DEPLOY_TOKEN"
    for name, value in ordinary.items():
        monkeypatch.setenv(name, value)
    ordinary_message = " | ".join(ordinary.values())
    assert str(SafetyViolation(ordinary_message)) == ordinary_message


@pytest.mark.parametrize(
    "sensitive_name",
    ("privatekey", "PRIVATEKEY", "secretkey", "SECRETKEY"),
)
def test_sensitive_name_classifier_handles_private_and_secret_key_compounds(
    sensitive_name: str,
    monkeypatch,
) -> None:
    payload = {
        "id": "target-1",
        "adapter_id": "filesystem",
        "protocol": "filesystem",
        "credential_ref": "DEPLOY_TOKEN",
        "config": {"nested": {sensitive_name: "must-not-be-stored"}},
        "capabilities": {
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    }
    with pytest.raises(ValidationError, match="secret-like config key"):
        Target.model_validate(payload)

    secret_value = f"sensitive-value-for-{sensitive_name}"
    monkeypatch.setenv(sensitive_name, secret_value)
    assert str(SafetyViolation(secret_value)) == "<redacted>"

    ordinary = {
        "MONKEY": "ordinary-monkey-value",
        "DISPLAY_NAME": "ordinary-display-name",
        "CREDENTIAL_REF": "ordinary-credential-reference",
    }
    payload["config"] = ordinary
    assert Target.model_validate(payload).credential_ref == "DEPLOY_TOKEN"
    for name, value in ordinary.items():
        monkeypatch.setenv(name, value)
    ordinary_message = " | ".join(ordinary.values())
    assert str(SafetyViolation(ordinary_message)) == ordinary_message


@pytest.mark.parametrize(
    "clone_kind",
    ("original", "model-copy-deep", "deepcopy", "pickle"),
)
def test_frozen_container_slots_reject_ordinary_rebinding_and_deletion(
    clone_kind: str,
) -> None:
    target = Target(
        id="target-1",
        adapter_id="filesystem",
        protocol="filesystem",
        credential_ref=None,
        config={"nested": {"items": ["one"]}},
        capabilities={
            "discover": "supported",
            "plan": "supported",
            "apply": "supported",
            "verify": "supported",
            "rollback": "unsupported",
        },
    )
    clones = {
        "original": target,
        "model-copy-deep": target.model_copy(deep=True),
        "deepcopy": copy.deepcopy(target),
        "pickle": pickle.loads(pickle.dumps(target)),
    }
    clone = clones[clone_kind]
    frozen_mapping = clone.config
    frozen_sequence = clone.config["nested"]["items"]

    with pytest.raises(TypeError):
        frozen_mapping._items = (("api_key", "leaked"),)
    with pytest.raises(TypeError):
        del frozen_mapping._items
    with pytest.raises(TypeError):
        frozen_sequence._items = ("leaked",)
    with pytest.raises(TypeError):
        del frozen_sequence._items

    assert clone.model_dump(mode="json") == target.model_dump(mode="json")


def test_control_plane_config_trusted_cli_paths_are_frozen_and_serializable(
    tmp_path,
) -> None:
    trusted_cli_paths = {}
    for name in ("skillshare", "gh"):
        executable = tmp_path / name
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        trusted_cli_paths[name] = executable
    config = ControlPlaneConfig(
        registry_root=tmp_path / "registry",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(tmp_path / "authority",),
        allowed_runtime_roots=(tmp_path / "runtime",),
        trusted_cli_paths=trusted_cli_paths,
    )

    with pytest.raises(TypeError):
        config.trusted_cli_paths["gh"] = tmp_path / "other-gh"

    dumped = config.model_dump(mode="json")
    assert dumped["trusted_cli_paths"] == {
        name: str(path) for name, path in trusted_cli_paths.items()
    }
    assert json.loads(config.model_dump_json())["trusted_cli_paths"] == dumped[
        "trusted_cli_paths"
    ]


def test_control_plane_config_canonicalizes_trusted_cli_paths_before_validation(
    tmp_path,
) -> None:
    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    executables = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        executables[name] = executable

    config = ControlPlaneConfig(
        registry_root=tmp_path / "registry",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(tmp_path / "authority",),
        allowed_runtime_roots=(tmp_path / "runtime",),
        trusted_cli_paths={
            name: bin_root / ".." / "bin" / name for name in executables
        },
    )
    assert dict(config.trusted_cli_paths) == {
        name: executable.resolve(strict=True)
        for name, executable in executables.items()
    }

    canonical_root = tmp_path / "canonical"
    canonical_root.mkdir()
    canonical_skillshare = canonical_root / "skillshare"
    canonical_skillshare.write_text("#!/bin/sh\n")
    canonical_skillshare.chmod(0o755)
    same_name_alias_root = tmp_path / "aliases"
    same_name_alias_root.mkdir()
    same_name_alias = same_name_alias_root / "skillshare"
    same_name_alias.symlink_to(canonical_skillshare)
    symlink_config = config.model_copy(
        update={
            "trusted_cli_paths": {
                "skillshare": same_name_alias,
                "gh": executables["gh"],
            }
        }
    )
    assert symlink_config.trusted_cli_paths["skillshare"] == canonical_skillshare

    renamed_executable = canonical_root / "renamed-skillshare"
    renamed_executable.write_text("#!/bin/sh\n")
    renamed_executable.chmod(0o755)
    bad_alias_root = tmp_path / "bad-aliases"
    bad_alias_root.mkdir()
    bad_skillshare_alias = bad_alias_root / "skillshare"
    bad_skillshare_alias.symlink_to(renamed_executable)
    with pytest.raises(ValidationError, match="allowlist name mismatch"):
        config.model_copy(
            update={
                "trusted_cli_paths": {
                    "skillshare": bad_skillshare_alias,
                    "gh": executables["gh"],
                }
            }
        )


def test_control_plane_config_prevents_base_bypass_and_revalidates_model_copy(
    tmp_path,
) -> None:
    trusted_cli_paths = {}
    for name in ("skillshare", "gh"):
        executable = tmp_path / name
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        trusted_cli_paths[name] = executable
    config = ControlPlaneConfig(
        registry_root=tmp_path / "registry",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(tmp_path / "authority",),
        allowed_runtime_roots=(tmp_path / "runtime",),
        trusted_cli_paths=trusted_cli_paths,
    )

    assert isinstance(config.trusted_cli_paths, Mapping)
    assert not isinstance(config.trusted_cli_paths, dict)
    with pytest.raises(TypeError):
        dict.__setitem__(config.trusted_cli_paths, "gh", tmp_path / "other")
    with pytest.raises(ValidationError, match="allowlist is fixed"):
        config.model_copy(update={"trusted_cli_paths": {"gh": trusted_cli_paths["gh"]}})

    for clone in (
        config.model_copy(deep=True),
        copy.deepcopy(config),
        pickle.loads(pickle.dumps(config)),
    ):
        assert clone.model_dump(mode="json") == config.model_dump(mode="json")
        assert not isinstance(clone.trusted_cli_paths, dict)
        with pytest.raises(TypeError):
            clone.trusted_cli_paths["gh"] = tmp_path / "other"


def test_status_and_drift_reports_are_strict_deeply_frozen_and_serializable() -> None:
    generated_at = datetime.now(UTC)
    evidence = EvidenceRef(
        owner_type="observation",
        owner_id="observation-1",
        relative_path="state.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    status = models.StatusReport(
        generated_at=generated_at,
        target_id="target-1",
        target_health={"target-1": {"healthy": True}},
        observed_revisions={"asset-1": "rev-1"},
        drift_count=1,
        evidence_refs=(evidence,),
    )
    drift = models.DriftReport(
        generated_at=generated_at,
        target_id="target-1",
        changes=({"asset_id": "asset-1", "reasons": ["revision_mismatch"]},),
        has_drift=True,
        evidence_refs=(evidence,),
    )

    assert set(models.StatusReport.model_fields) == {
        "generated_at",
        "target_id",
        "target_health",
        "observed_revisions",
        "drift_count",
        "evidence_refs",
    }
    assert set(models.DriftReport.model_fields) == {
        "generated_at",
        "target_id",
        "changes",
        "has_drift",
        "evidence_refs",
    }
    with pytest.raises(ValidationError, match="frozen"):
        status.drift_count = 2
    with pytest.raises(TypeError):
        status.target_health["target-1"]["healthy"] = False
    with pytest.raises(TypeError):
        status.observed_revisions["asset-1"] = "rev-2"
    with pytest.raises(TypeError):
        drift.changes[0]["reasons"].append("missing")

    status_dump = status.model_dump(mode="json")
    drift_dump = drift.model_dump(mode="json")
    assert json.loads(status.model_dump_json()) == status_dump
    assert json.loads(drift.model_dump_json()) == drift_dump
    assert status_dump["target_health"] == {"target-1": {"healthy": True}}
    assert drift_dump["changes"] == [
        {"asset_id": "asset-1", "reasons": ["revision_mismatch"]}
    ]

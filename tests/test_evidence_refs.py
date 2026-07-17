import hashlib
import os
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from skillctl.models import DeploymentLedgerEntry, EvidenceRef
from skillctl.evidence_refs import DeploymentEvidenceResolver, EvidenceResolver
from skillctl.errors import SafetyViolation


def digest_bytes(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def make_entry(deployment_id: str, refs: tuple[EvidenceRef, ...]) -> DeploymentLedgerEntry:
    now = datetime.now(UTC)
    return DeploymentLedgerEntry(
        schema_version="1.0",
        deployment_id=deployment_id,
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
        evidence_refs=refs,
        previous_entry_hash=None,
        entry_hash="sha256:" + "1" * 64,
    )


def test_evidence_ref_rejects_absolute_relative_path() -> None:
    with pytest.raises(ValidationError, match="relative evidence path"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path="/tmp/evidence.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_backslash_path() -> None:
    with pytest.raises(ValidationError, match="relative evidence path"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path=r"nested\evidence.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_parent_traversal() -> None:
    with pytest.raises(ValidationError, match="relative evidence path"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path="../deployment/evidence.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_control_characters() -> None:
    with pytest.raises(ValidationError, match="relative evidence path"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path="evidence\x00.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_non_normalized_path() -> None:
    with pytest.raises(ValidationError, match="relative evidence path"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path="nested//evidence.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_drive_qualified_path() -> None:
    with pytest.raises(ValidationError, match="relative evidence path"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path="C:/evidence.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_all_windows_drive_forms() -> None:
    for value in ("C:/x", "C:x", "z:folder/file"):
        with pytest.raises(ValidationError, match="relative evidence path"):
            EvidenceRef(
                owner_type="plan",
                owner_id="plan-1",
                relative_path=value,
                sha256="sha256:" + "0" * 64,
                media_type="application/json",
            )


def test_evidence_ref_rejects_owner_directory_as_path() -> None:
    with pytest.raises(ValidationError, match="relative evidence path"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path=".",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_unknown_owner_type() -> None:
    with pytest.raises(ValidationError, match="owner_type"):
        EvidenceRef(
            owner_type="portal",
            owner_id="portal-1",
            relative_path="evidence.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


def test_evidence_ref_rejects_malformed_sha256() -> None:
    with pytest.raises(ValidationError, match="sha256"):
        EvidenceRef(
            owner_type="plan",
            owner_id="plan-1",
            relative_path="evidence.json",
            sha256="not-a-digest",
            media_type="application/json",
        )


def test_evidence_ref_resolves_from_its_owner_base_only(tmp_path) -> None:
    content = b"{}\n"
    ref = EvidenceRef(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="diff.json",
        sha256=digest_bytes(content),
        media_type="application/json",
    )
    path = tmp_path / "plan" / "plan-1" / "diff.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    assert EvidenceResolver(tmp_path).resolve(ref) == path


def test_evidence_resolver_documents_locator_only_security_boundary() -> None:
    documentation = EvidenceResolver.resolve.__doc__ or ""
    assert "locator-only" in documentation
    assert "approval" in documentation
    assert "deployment" in documentation
    assert "Portal" in documentation
    assert "security decision" in documentation
    assert "DeploymentEvidenceResolver" in documentation


def test_evidence_resolver_rejects_cross_owner_traversal(tmp_path) -> None:
    ref = EvidenceRef.model_construct(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="../deployment/evidence.json",
        sha256="sha256:" + "0" * 64,
        media_type="application/json",
    )
    with pytest.raises(SafetyViolation, match="relative evidence path"):
        EvidenceResolver(tmp_path).resolve(ref)


def test_evidence_resolver_rejects_checksum_mismatch(tmp_path) -> None:
    path = tmp_path / "plan" / "plan-1" / "diff.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"actual\n")
    ref = EvidenceRef(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="diff.json",
        sha256=digest_bytes(b"expected\n"),
        media_type="application/json",
    )
    with pytest.raises(SafetyViolation, match="checksum"):
        EvidenceResolver(tmp_path).resolve(ref)


def test_evidence_resolver_rejects_symlink_escape(tmp_path) -> None:
    content = b"outside\n"
    outside = tmp_path / "outside.json"
    outside.write_bytes(content)
    path = tmp_path / "plan" / "plan-1" / "diff.json"
    path.parent.mkdir(parents=True)
    path.symlink_to(outside)
    ref = EvidenceRef(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="diff.json",
        sha256=digest_bytes(content),
        media_type="application/json",
    )
    with pytest.raises(SafetyViolation, match="symlink"):
        EvidenceResolver(tmp_path).resolve(ref)


def test_evidence_ref_rejects_path_like_owner_id() -> None:
    with pytest.raises(ValidationError, match="owner_id"):
        EvidenceRef(
            owner_type="plan",
            owner_id="../deployment",
            relative_path="evidence.json",
            sha256="sha256:" + "0" * 64,
            media_type="application/json",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("owner_id", "plan\u0085id"),
        ("owner_id", "plan\u202eid"),
        ("relative_path", "evidence\u0085.json"),
        ("relative_path", "evidence\u202e.json"),
    ),
)
def test_evidence_ref_rejects_unicode_control_and_format_characters(
    field, value
) -> None:
    payload = {
        "owner_type": "plan",
        "owner_id": "plan-1",
        "relative_path": "evidence.json",
        "sha256": "sha256:" + "0" * 64,
        "media_type": "application/json",
    }
    payload[field] = value
    with pytest.raises(ValidationError, match=field):
        EvidenceRef(**payload)


def test_deployment_evidence_requires_entry_membership(tmp_path) -> None:
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(b"verified\n"),
        media_type="text/plain",
    )
    other_entry = make_entry("deployment-2", ())
    with pytest.raises(SafetyViolation, match="deployment evidence membership"):
        DeploymentEvidenceResolver(tmp_path).resolve(other_entry, ref)


def test_deployment_evidence_requires_deployment_owner_type(tmp_path) -> None:
    ref = EvidenceRef(
        owner_type="plan",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(b"verified\n"),
        media_type="text/plain",
    )
    entry = make_entry("deployment-1", ())
    object.__setattr__(entry, "evidence_refs", (ref,))
    with pytest.raises(SafetyViolation, match="deployment evidence owner"):
        DeploymentEvidenceResolver(tmp_path).resolve(entry, ref)


def test_deployment_evidence_requires_matching_deployment_id(tmp_path) -> None:
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-2",
        relative_path="result.txt",
        sha256=digest_bytes(b"verified\n"),
        media_type="text/plain",
    )
    entry = make_entry("deployment-1", ())
    object.__setattr__(entry, "evidence_refs", (ref,))
    with pytest.raises(SafetyViolation, match="deployment evidence owner"):
        DeploymentEvidenceResolver(tmp_path).resolve(entry, ref)


def test_deployment_evidence_captures_ref_before_membership_and_owner_checks(
    tmp_path,
    monkeypatch,
) -> None:
    content = b"verified\n"
    digest = digest_bytes(content)
    legitimate_path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    attacker_path = tmp_path / "deployment" / "deployment-2" / "attacker.txt"
    legitimate_path.parent.mkdir(parents=True)
    attacker_path.parent.mkdir(parents=True)
    legitimate_path.write_bytes(content)
    attacker_path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest,
        media_type="text/plain",
    )
    entry_ref = EvidenceRef.model_validate(
        {
            "owner_type": "deployment",
            "owner_id": "deployment-1",
            "relative_path": "result.txt",
            "sha256": digest,
            "media_type": "text/plain",
        }
    )
    original_getattribute = EvidenceRef.__getattribute__
    primitive_fields = {
        "owner_type",
        "owner_id",
        "relative_path",
        "sha256",
        "media_type",
    }
    reads = 0

    def mutate_after_three_primitive_reads(self, name):
        nonlocal reads
        value = original_getattribute(self, name)
        if self is ref and name in primitive_fields:
            reads += 1
            if reads == 3:
                object.__setattr__(ref, "owner_id", "deployment-2")
                object.__setattr__(ref, "relative_path", "attacker.txt")
        return value

    monkeypatch.setattr(EvidenceRef, "__getattribute__", mutate_after_three_primitive_reads)
    resolved = DeploymentEvidenceResolver(tmp_path).resolve(
        make_entry("deployment-1", (entry_ref,)), ref
    )

    assert resolved.owner_id == "deployment-1"
    assert resolved.relative_path == "result.txt"
    assert resolved.content == content


def test_deployment_evidence_primitive_snapshot_resists_validated_clone_redirect(
    tmp_path,
    monkeypatch,
) -> None:
    legitimate_content = b"verified\n"
    redirected_content = b"CAPTURED_CLONE_REDIRECTED\n"
    legitimate_path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    redirected_path = tmp_path / "deployment" / "deployment-2" / "stolen.txt"
    legitimate_path.parent.mkdir(parents=True)
    redirected_path.parent.mkdir(parents=True)
    legitimate_path.write_bytes(legitimate_content)
    redirected_path.write_bytes(redirected_content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(legitimate_content),
        media_type="text/plain",
    )
    entry_ref = EvidenceRef.model_validate(
        {
            "owner_type": "deployment",
            "owner_id": "deployment-1",
            "relative_path": "result.txt",
            "sha256": digest_bytes(legitimate_content),
            "media_type": "text/plain",
        }
    )
    entry = make_entry("deployment-1", (entry_ref,))
    original_getattribute = EvidenceRef.__getattribute__
    primitive_fields = {
        "owner_type",
        "owner_id",
        "relative_path",
        "sha256",
        "media_type",
    }
    captured_query_ref = None
    captured_reads = 0

    def redirect_validated_clone_after_owner_check(self, name):
        nonlocal captured_query_ref, captured_reads
        value = original_getattribute(self, name)
        if name not in primitive_fields or self is ref or self is entry_ref:
            return value
        if captured_query_ref is None:
            captured_query_ref = self
        if self is captured_query_ref:
            captured_reads += 1
            if captured_reads == 12:
                object.__setattr__(self, "owner_id", "deployment-2")
                object.__setattr__(self, "relative_path", "stolen.txt")
                object.__setattr__(self, "sha256", digest_bytes(redirected_content))
        return value

    monkeypatch.setattr(
        EvidenceRef,
        "__getattribute__",
        redirect_validated_clone_after_owner_check,
    )
    resolved = DeploymentEvidenceResolver(tmp_path).resolve(entry, ref)

    assert resolved.owner_id == "deployment-1"
    assert resolved.relative_path == "result.txt"
    assert resolved.content == legitimate_content
    assert b"CAPTURED_CLONE_REDIRECTED" not in resolved.content


def test_deployment_evidence_snapshot_construction_ignores_validated_clone_mutation(
    tmp_path,
    monkeypatch,
) -> None:
    legitimate_content = b"verified\n"
    redirected_content = b"SNAPSHOT_CONSTRUCTION_REDIRECTED\n"
    legitimate_path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    redirected_path = tmp_path / "deployment" / "deployment-1" / "stolen.txt"
    legitimate_path.parent.mkdir(parents=True)
    legitimate_path.write_bytes(legitimate_content)
    redirected_path.write_bytes(redirected_content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(legitimate_content),
        media_type="text/plain",
    )
    entry = make_entry("deployment-1", (ref,))
    entry_ref = entry.evidence_refs[0]
    original_getattribute = EvidenceRef.__getattribute__
    primitive_fields = {
        "owner_type",
        "owner_id",
        "relative_path",
        "sha256",
        "media_type",
    }
    validated_reads: dict[int, int] = {}
    validated_objects: list[EvidenceRef] = []

    def redirect_unread_snapshot_fields(self, name):
        value = original_getattribute(self, name)
        if name not in primitive_fields or self is ref or self is entry_ref:
            return value
        identity = id(self)
        if identity not in validated_reads:
            validated_objects.append(self)
        validated_reads[identity] = validated_reads.get(identity, 0) + 1
        if validated_reads[identity] == 7:
            object.__setattr__(self, "relative_path", "stolen.txt")
            object.__setattr__(self, "sha256", digest_bytes(redirected_content))
        return value

    monkeypatch.setattr(
        EvidenceRef,
        "__getattribute__",
        redirect_unread_snapshot_fields,
    )
    resolved = DeploymentEvidenceResolver(tmp_path).resolve(entry, ref)

    assert resolved.relative_path == "result.txt"
    assert resolved.content == legitimate_content
    assert b"SNAPSHOT_CONSTRUCTION_REDIRECTED" not in resolved.content


def test_deployment_evidence_capture_resists_query_and_ledger_mixed_snapshot(
    tmp_path,
    monkeypatch,
) -> None:
    legitimate_content = b"verified\n"
    redirected_content = b"MIXED_SNAPSHOT_REDIRECTED\n"
    legitimate_path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    redirected_path = tmp_path / "deployment" / "deployment-1" / "stolen.txt"
    legitimate_path.parent.mkdir(parents=True)
    legitimate_path.write_bytes(legitimate_content)
    redirected_path.write_bytes(redirected_content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(legitimate_content),
        media_type="text/plain",
    )
    entry = make_entry("deployment-1", (ref,))
    entry_ref = entry.evidence_refs[0]
    assert entry_ref is not ref
    original_getattribute = EvidenceRef.__getattribute__

    def redirect_unread_fields_after_owner(self, name):
        value = original_getattribute(self, name)
        if name == "owner_id" and (self is ref or self is entry_ref):
            object.__setattr__(self, "relative_path", "stolen.txt")
            object.__setattr__(self, "sha256", digest_bytes(redirected_content))
        return value

    monkeypatch.setattr(
        EvidenceRef,
        "__getattribute__",
        redirect_unread_fields_after_owner,
    )
    resolved = DeploymentEvidenceResolver(tmp_path).resolve(entry, ref)

    assert resolved.relative_path == "result.txt"
    assert resolved.content == legitimate_content
    assert b"MIXED_SNAPSHOT_REDIRECTED" not in resolved.content


@pytest.mark.parametrize("failure_kind", ("missing-field", "wrong-type"))
def test_deployment_evidence_invalid_constructed_ref_fails_closed(
    tmp_path,
    failure_kind: str,
) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    valid_ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    invalid_payload = valid_ref.model_dump()
    if failure_kind == "missing-field":
        invalid_payload.pop("relative_path")
    else:
        invalid_payload["relative_path"] = 42
    invalid_ref = EvidenceRef.model_construct(**invalid_payload)

    with pytest.raises(
        SafetyViolation,
        match="^deployment evidence reference is invalid$",
    ):
        DeploymentEvidenceResolver(tmp_path).resolve(
            make_entry("deployment-1", (valid_ref,)),
            invalid_ref,
        )


def test_deployment_evidence_returns_frozen_verified_bytes(tmp_path) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    resolved = DeploymentEvidenceResolver(tmp_path).resolve(
        make_entry("deployment-1", (ref,)), ref
    )
    assert resolved is not None
    assert resolved.content == content
    assert resolved.byte_length == len(content)
    with pytest.raises(ValidationError, match="frozen"):
        resolved.content = b"changed"


def test_deployment_evidence_rejects_oversize_content(tmp_path) -> None:
    content = b"12345"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    with pytest.raises(SafetyViolation, match="size"):
        DeploymentEvidenceResolver(tmp_path, max_evidence_bytes=4).resolve(
            make_entry("deployment-1", (ref,)), ref
        )


def test_deployment_evidence_rejects_checksum_mismatch(tmp_path) -> None:
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"actual\n")
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(b"expected\n"),
        media_type="text/plain",
    )
    with pytest.raises(SafetyViolation, match="checksum"):
        DeploymentEvidenceResolver(tmp_path).resolve(make_entry("deployment-1", (ref,)), ref)


def test_deployment_evidence_rejects_symlink_leaf(tmp_path) -> None:
    content = b"outside\n"
    outside = tmp_path / "outside.txt"
    outside.write_bytes(content)
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.symlink_to(outside)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    with pytest.raises(SafetyViolation, match="deployment evidence"):
        DeploymentEvidenceResolver(tmp_path).resolve(make_entry("deployment-1", (ref,)), ref)


def test_deployment_evidence_rejects_symlink_directory(tmp_path) -> None:
    content = b"outside\n"
    outside = tmp_path / "outside" / "deployment-1"
    outside.mkdir(parents=True)
    (outside / "result.txt").write_bytes(content)
    (tmp_path / "deployment").symlink_to(tmp_path / "outside", target_is_directory=True)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    with pytest.raises(SafetyViolation, match="deployment evidence"):
        DeploymentEvidenceResolver(tmp_path).resolve(make_entry("deployment-1", (ref,)), ref)


def test_deployment_evidence_reads_open_fd_when_path_is_replaced(tmp_path) -> None:
    original = b"verified\n"
    replacement = b"replacement\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(original)
    replacement_path = tmp_path / "replacement.txt"
    replacement_path.write_bytes(replacement)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(original),
        media_type="text/plain",
    )
    resolver = DeploymentEvidenceResolver(tmp_path)
    resolver.after_leaf_open = lambda: os.replace(replacement_path, path)
    resolved = resolver.resolve(make_entry("deployment-1", (ref,)), ref)
    assert resolved.content == original
    assert path.read_bytes() == replacement


def test_deployment_evidence_returns_metadata_from_captured_validated_ref(
    tmp_path,
) -> None:
    content = b"verified\n"
    digest = digest_bytes(content)
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest,
        media_type="text/plain",
    )
    resolver = DeploymentEvidenceResolver(tmp_path)

    def pollute_original_ref() -> None:
        object.__setattr__(ref, "relative_path", "attacker.txt")
        object.__setattr__(ref, "sha256", "sha256:" + "0" * 64)
        object.__setattr__(ref, "media_type", "application/octet-stream")

    resolver.after_leaf_open = pollute_original_ref
    resolved = resolver.resolve(make_entry("deployment-1", (ref,)), ref)

    assert resolved.relative_path == "result.txt"
    assert resolved.sha256 == digest
    assert resolved.media_type == "text/plain"
    assert resolved.content == content


def test_deployment_evidence_rejects_replacement_before_leaf_open(tmp_path) -> None:
    original = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(original)
    attacker = tmp_path / "attacker.txt"
    attacker.write_bytes(b"attacker\n")
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(original),
        media_type="text/plain",
    )
    resolver = DeploymentEvidenceResolver(tmp_path)
    resolver.before_leaf_open = lambda: os.replace(attacker, path)
    with pytest.raises(SafetyViolation, match="checksum"):
        resolver.resolve(make_entry("deployment-1", (ref,)), ref)


def test_deployment_evidence_rejects_replaced_open_before_opening_content(
    tmp_path, monkeypatch
) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    real_open = os.open
    calls = []

    def malicious_open(path_arg, flags, mode=0o777, *, dir_fd=None):
        calls.append((path_arg, dir_fd))
        return real_open(path_arg, flags, mode)

    monkeypatch.setattr("skillctl.evidence_refs.os.open", malicious_open)
    with pytest.raises(SafetyViolation, match="platform.*safe-open"):
        DeploymentEvidenceResolver(tmp_path).resolve(make_entry("deployment-1", (ref,)), ref)
    assert calls == []


@pytest.mark.parametrize("missing_capability", ("O_NOFOLLOW", "O_DIRECTORY", "dir_fd"))
def test_deployment_evidence_fails_closed_without_safe_open_capabilities(
    tmp_path, monkeypatch, missing_capability
) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    if missing_capability == "dir_fd":
        monkeypatch.setattr("skillctl.evidence_refs.os.supports_dir_fd", set())
    else:
        monkeypatch.delattr(f"skillctl.evidence_refs.os.{missing_capability}")

    with pytest.raises(SafetyViolation, match="platform.*safe-open"):
        DeploymentEvidenceResolver(tmp_path).resolve(make_entry("deployment-1", (ref,)), ref)


@pytest.mark.parametrize("case", ("trusted_uid", "regular_leaf"))
def test_deployment_evidence_requires_trusted_uid_and_regular_leaf(
    tmp_path, case
) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    if case == "regular_leaf":
        path.mkdir()
    else:
        path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    trusted_uid = os.geteuid() + 1 if case == "trusted_uid" else os.geteuid()

    with pytest.raises(SafetyViolation, match="not trusted"):
        DeploymentEvidenceResolver(tmp_path, trusted_uid=trusted_uid).resolve(
            make_entry("deployment-1", (ref,)), ref
        )


@pytest.mark.parametrize("mutation", ("growth", "truncation"))
def test_deployment_evidence_rejects_growth_and_truncation_after_read(
    tmp_path, monkeypatch, mutation
) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content),
        media_type="text/plain",
    )
    real_read = os.read
    mutated = False

    def mutating_read(descriptor, byte_count):
        nonlocal mutated
        chunk = real_read(descriptor, byte_count)
        if not chunk and not mutated:
            mutated = True
            if mutation == "growth":
                with path.open("ab") as stream:
                    stream.write(b"attacker\n")
            else:
                path.write_bytes(b"")
        return chunk

    monkeypatch.setattr("skillctl.evidence_refs.os.read", mutating_read)
    with pytest.raises(SafetyViolation, match="changed while reading"):
        DeploymentEvidenceResolver(tmp_path).resolve(make_entry("deployment-1", (ref,)), ref)


@pytest.mark.parametrize("success", (True, False))
def test_deployment_evidence_closes_all_opened_descriptors(
    tmp_path, monkeypatch, success
) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(content if success else b"different\n"),
        media_type="text/plain",
    )
    real_close = os.close
    closed = []

    def tracking_close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr("skillctl.evidence_refs.os.close", tracking_close)
    resolver = DeploymentEvidenceResolver(tmp_path)
    if success:
        resolver.resolve(make_entry("deployment-1", (ref,)), ref)
    else:
        with pytest.raises(SafetyViolation, match="checksum"):
            resolver.resolve(make_entry("deployment-1", (ref,)), ref)
    assert len(closed) == 4


@pytest.mark.parametrize("primary_failure", (False, True))
def test_deployment_evidence_cleanup_attempts_all_fds_without_masking_primary_error(
    tmp_path, monkeypatch, primary_failure
) -> None:
    content = b"verified\n"
    path = tmp_path / "deployment" / "deployment-1" / "result.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    ref = EvidenceRef(
        owner_type="deployment",
        owner_id="deployment-1",
        relative_path="result.txt",
        sha256=digest_bytes(b"different\n") if primary_failure else digest_bytes(content),
        media_type="text/plain",
    )
    real_close = os.close
    attempts = []

    def failing_first_close(descriptor):
        attempts.append(descriptor)
        real_close(descriptor)
        if len(attempts) == 1:
            raise OSError("simulated close failure with sensitive detail")

    monkeypatch.setattr("skillctl.evidence_refs.os.close", failing_first_close)
    expected = "checksum" if primary_failure else "descriptor cleanup failed"
    with pytest.raises(SafetyViolation, match=expected) as captured:
        DeploymentEvidenceResolver(tmp_path).resolve(make_entry("deployment-1", (ref,)), ref)
    assert len(attempts) == 4
    assert "sensitive detail" not in str(captured.value)


def test_evidence_resolver_rejects_symlink_evidence_root(tmp_path) -> None:
    content = b"{}\n"
    outside = tmp_path / "outside"
    path = outside / "plan" / "plan-1" / "diff.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    evidence_root = tmp_path / "evidence"
    evidence_root.symlink_to(outside, target_is_directory=True)
    ref = EvidenceRef(
        owner_type="plan",
        owner_id="plan-1",
        relative_path="diff.json",
        sha256=digest_bytes(content),
        media_type="application/json",
    )
    with pytest.raises(SafetyViolation, match="symlink"):
        EvidenceResolver(evidence_root).resolve(ref)

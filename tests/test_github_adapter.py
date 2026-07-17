from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from pydantic import JsonValue, ValidationError

from skillctl.adapters.github import GitHubAdapter
from skillctl.errors import PolicyDenied
from skillctl.models import Asset, CapabilityManifest, Target


def _manifest() -> CapabilityManifest:
    return CapabilityManifest(
        discover="supported",
        plan="supported",
        apply="unsupported",
        verify="unsupported",
        rollback="unsupported",
        bindings="unsupported",
        delete="unsupported",
    )


def _asset(
    *,
    visibility: str = "public",
    authority_class: str = "public",
    source_revision: str = "sha256:asset-1",
    revision_policy: str = "pinned",
) -> Asset:
    return Asset(
        id="asset-1",
        name="governed-skill",
        asset_type="skill",
        owner="governance",
        visibility=visibility,
        lifecycle="canonical",
        authority_class=authority_class,
        source_uri="https://github.com/example/governed-skill",
        source_path=None,
        source_revision=source_revision,
        source_checksum="sha256:content-1",
        license_state="approved",
        revision_policy=revision_policy,
    )


def _target(
    *,
    visibility: str = "public",
    config_update: dict[str, JsonValue] | None = None,
) -> Target:
    config: dict[str, JsonValue] = {
        "repository": "example/governed-skill",
        "visibility": visibility,
        "default_branch": "main",
    }
    if config_update is not None:
        config.update(config_update)
    return Target(
        id="github-publication",
        adapter_id="github",
        protocol="api-import",
        credential_ref=None,
        config=config,
        capabilities=_manifest(),
    )


@pytest.mark.parametrize("asset_visibility", ("private", "internal"))
def test_private_asset_cannot_publish_to_public_target(asset_visibility: str) -> None:
    with pytest.raises(PolicyDenied, match="public"):
        GitHubAdapter().plan_publication(
            _asset(visibility=asset_visibility, authority_class="private"),
            _target(visibility="public"),
        )


def test_public_publication_matches_reviewable_fixture() -> None:
    adapter = GitHubAdapter()
    planned = adapter.plan_publication(_asset(), _target())
    fixture_path = (
        Path(__file__).parent / "fixtures" / "mvp" / "expected" / "github-publication-diff.json"
    )

    expected = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert planned.model_dump(mode="json") == expected
    assert adapter.plan_publication(_asset(), _target()) == planned


@pytest.mark.parametrize("asset_visibility", ("private", "internal"))
def test_authority_model_maps_public_to_public_and_nonpublic_to_private(
    asset_visibility: str,
) -> None:
    adapter = GitHubAdapter()

    public_plan = adapter.plan_publication(
        _asset(visibility="public"),
        _target(visibility="public"),
    )
    private_plan = adapter.plan_publication(
        _asset(visibility=asset_visibility, authority_class="private"),
        _target(visibility="private"),
    )

    assert public_plan.repository_visibility == "public"
    assert private_plan.repository_visibility == "private"

    with pytest.raises(PolicyDenied, match="visibility"):
        adapter.plan_publication(
            _asset(visibility="public"),
            _target(visibility="private"),
        )


@pytest.mark.parametrize(
    ("asset_visibility", "authority_class", "target_visibility"),
    (
        ("public", "private", "public"),
        ("private", "public", "private"),
        ("internal", "public", "private"),
    ),
)
def test_visibility_authority_mismatch_fails_closed(
    asset_visibility: str,
    authority_class: str,
    target_visibility: str,
) -> None:
    with pytest.raises(PolicyDenied, match="authority"):
        GitHubAdapter().plan_publication(
            _asset(
                visibility=asset_visibility,
                authority_class=authority_class,
            ),
            _target(visibility=target_visibility),
        )


@pytest.mark.parametrize(
    ("asset_visibility", "target_visibility"),
    (("partner", "private"), ("public", "internal")),
)
def test_unknown_visibility_values_fail_closed(
    asset_visibility: str,
    target_visibility: str,
) -> None:
    with pytest.raises(PolicyDenied, match="visibility"):
        GitHubAdapter().plan_publication(
            _asset(visibility=asset_visibility),
            _target(visibility=target_visibility),
        )


@pytest.mark.parametrize("source_revision", ("", "   "))
def test_missing_immutable_source_revision_fails_closed(
    source_revision: str,
) -> None:
    with pytest.raises(PolicyDenied, match="revision"):
        GitHubAdapter().plan_publication(
            _asset(source_revision=source_revision),
            _target(),
        )


def test_tracking_revision_policy_fails_closed() -> None:
    with pytest.raises(PolicyDenied, match="revision"):
        GitHubAdapter().plan_publication(
            _asset(source_revision="main", revision_policy="tracking"),
            _target(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("dirty_worktree", True),
        ("worktree_path", "/private/tmp/authority"),
        ("metadata", "unreviewed"),
    ),
)
def test_target_config_rejects_every_extra_field(
    field: str,
    value: JsonValue,
) -> None:
    with pytest.raises(PolicyDenied, match="config"):
        GitHubAdapter().plan_publication(
            _asset(),
            _target(config_update={field: value}),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("repository", ""),
        ("repository", 42),
        ("repository", "/private/tmp/worktree"),
        ("repository", "/repository"),
        ("repository", "owner/"),
        ("default_branch", "   "),
        ("default_branch", False),
    ),
)
def test_target_config_rejects_invalid_allowed_field_values(
    field: str,
    value: JsonValue,
) -> None:
    with pytest.raises(PolicyDenied, match="config"):
        GitHubAdapter().plan_publication(
            _asset(),
            _target(config_update={field: value}),
        )


@pytest.mark.parametrize("contract_violation", ("adapter", "protocol", "capability"))
def test_target_must_match_github_dry_run_contract(
    contract_violation: str,
) -> None:
    target = _target()
    if contract_violation == "adapter":
        target = target.model_copy(update={"adapter_id": "filesystem"})
    elif contract_violation == "protocol":
        target = target.model_copy(update={"protocol": "filesystem"})
    else:
        target = target.model_copy(
            update={"capabilities": target.capabilities.model_copy(update={"apply": "supported"})}
        )

    with pytest.raises(PolicyDenied, match="target"):
        GitHubAdapter().plan_publication(_asset(), target)


@pytest.mark.parametrize("missing_field", ("repository", "visibility", "default_branch"))
def test_target_config_requires_all_three_fields(missing_field: str) -> None:
    config: dict[str, JsonValue] = {
        "repository": "example/governed-skill",
        "visibility": "public",
        "default_branch": "main",
    }
    del config[missing_field]
    target = _target().model_copy(update={"config": config})

    with pytest.raises(PolicyDenied, match="config"):
        GitHubAdapter().plan_publication(_asset(), target)


def test_secret_like_config_is_rejected_at_target_model_boundary() -> None:
    with pytest.raises(ValidationError, match="secret-like"):
        _target(config_update={"api_token": "placeholder"})


def test_manifest_is_dry_run_only_and_apply_is_not_implemented() -> None:
    adapter = GitHubAdapter()

    assert adapter.manifest.model_dump() == {
        "discover": "supported",
        "plan": "supported",
        "apply": "unsupported",
        "verify": "unsupported",
        "rollback": "unsupported",
        "bindings": "unsupported",
        "delete": "unsupported",
    }
    assert not hasattr(adapter, "apply")


def test_dry_run_source_has_no_runner_network_or_mutating_commands() -> None:
    source_path = Path(__file__).parents[1] / "src" / "skillctl" / "adapters" / "github.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])

    assert "runner" not in source.lower()
    assert imported_roots.isdisjoint({"aiohttp", "httpx", "requests", "socket", "urllib"})
    for forbidden in (
        "gh pr create",
        "gh api --method",
        "git push",
        "git commit",
        "git add",
    ):
        assert forbidden not in source.lower()

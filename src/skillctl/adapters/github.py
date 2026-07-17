from __future__ import annotations

from typing import Literal, cast

from skillctl.errors import PolicyDenied
from skillctl.models import Asset, CapabilityManifest, StrictModel, Target

_TARGET_CONFIG_FIELDS = frozenset({"repository", "visibility", "default_branch"})


class GitHubPublicationDiff(StrictModel):
    target_id: str
    repository: str
    repository_visibility: Literal["public", "private"]
    asset_id: str
    source_revision: str
    action: Literal["create", "update", "noop"]
    allowed: bool
    reasons: tuple[str, ...]


class GitHubAdapter:
    manifest = CapabilityManifest(
        discover="supported",
        plan="supported",
        apply="unsupported",
        verify="unsupported",
        rollback="unsupported",
        bindings="unsupported",
        delete="unsupported",
    )

    def plan_publication(
        self,
        asset: Asset,
        target: Target,
    ) -> GitHubPublicationDiff:
        if (
            target.adapter_id != "github"
            or target.protocol != "api-import"
            or target.capabilities != self.manifest
        ):
            raise PolicyDenied("GitHub target contract is invalid")
        if set(target.config) != _TARGET_CONFIG_FIELDS:
            raise PolicyDenied("GitHub target config is invalid")
        repository = target.config["repository"]
        visibility = target.config["visibility"]
        default_branch = target.config["default_branch"]
        if not all(isinstance(value, str) for value in (repository, visibility, default_branch)):
            raise PolicyDenied("GitHub target config is invalid")
        repository = cast(str, repository)
        visibility = cast(str, visibility)
        default_branch = cast(str, default_branch)
        if any(
            not value or value != value.strip()
            for value in (repository, visibility, default_branch)
        ):
            raise PolicyDenied("GitHub target config is invalid")
        owner, separator, name = repository.partition("/")
        if (
            not owner
            or not separator
            or not name
            or "/" in name
            or owner in {".", ".."}
            or name in {".", ".."}
        ):
            raise PolicyDenied("GitHub target config is invalid")
        if asset.revision_policy != "pinned" or not asset.source_revision.strip():
            raise PolicyDenied("immutable source revision is required")
        if visibility not in {"public", "private"} or asset.visibility not in {
            "public",
            "private",
            "internal",
        }:
            raise PolicyDenied("asset or target visibility is invalid")
        required_authority = "public" if asset.visibility == "public" else "private"
        if asset.authority_class != required_authority:
            raise PolicyDenied("asset visibility and authority class mismatch")
        if visibility == "public" and asset.visibility in {"private", "internal"}:
            raise PolicyDenied("private asset cannot publish publicly")
        if asset.visibility == "public" and visibility != "public":
            raise PolicyDenied("asset and target visibility mismatch")
        return GitHubPublicationDiff(
            target_id=target.id,
            repository=repository,
            repository_visibility=cast(Literal["public", "private"], visibility),
            asset_id=asset.id,
            source_revision=asset.source_revision,
            action="create",
            allowed=True,
            reasons=(),
        )

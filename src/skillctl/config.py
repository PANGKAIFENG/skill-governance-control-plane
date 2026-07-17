import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from skillctl.models import StrictModel


_TRUSTED_PATH: Literal["/opt/homebrew/bin:/usr/bin:/bin"] = (
    "/opt/homebrew/bin:/usr/bin:/bin"
)


class ControlPlaneConfig(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    registry_root: Path
    state_root: Path
    evidence_root: Path
    projection_root: Path
    authority_roots: tuple[Path, ...]
    allowed_runtime_roots: tuple[Path, ...]
    trusted_cli_paths: dict[str, Path] = Field(
        default_factory=lambda: {
            "skillshare": Path("/opt/homebrew/bin/skillshare"),
            "gh": Path("/opt/homebrew/bin/gh"),
        }
    )
    trusted_path: Literal["/opt/homebrew/bin:/usr/bin:/bin"] = _TRUSTED_PATH

    @field_validator("registry_root", "state_root", "evidence_root", "projection_root")
    @classmethod
    def resolve_root(cls, value: Path) -> Path:
        return value.resolve(strict=False)

    @field_validator("authority_roots", "allowed_runtime_roots")
    @classmethod
    def resolve_roots(cls, value: tuple[Path, ...]) -> tuple[Path, ...]:
        return tuple(path.resolve(strict=False) for path in value)

    @field_validator("trusted_cli_paths")
    @classmethod
    def require_absolute_executables(cls, value: dict[str, Path]) -> dict[str, Path]:
        if set(value) != {"skillshare", "gh"}:
            raise ValueError("trusted CLI executable allowlist is fixed")
        if any(not path.is_absolute() for path in value.values()):
            raise ValueError("trusted CLI path must be an absolute executable")
        try:
            canonical = {
                name: path.resolve(strict=False) for name, path in value.items()
            }
        except (OSError, RuntimeError) as error:
            raise ValueError("trusted CLI path could not be resolved safely") from error
        if any(path.name != name for name, path in canonical.items()):
            raise ValueError("trusted CLI executable allowlist name mismatch")
        try:
            metadata = {name: path.stat() for name, path in canonical.items()}
        except FileNotFoundError:
            raise ValueError("trusted CLI path references a missing executable")
        except OSError as error:
            raise ValueError("trusted CLI path could not be inspected safely") from error
        if any(not stat.S_ISREG(item.st_mode) for item in metadata.values()):
            raise ValueError("trusted CLI path must reference a regular executable")
        if any(item.st_mode & 0o111 == 0 for item in metadata.values()) or any(
            not os.access(path, os.X_OK) for path in canonical.values()
        ):
            raise ValueError("trusted CLI path requires executable permission")
        return canonical

    @model_validator(mode="after")
    def reject_root_overlaps(self) -> "ControlPlaneConfig":
        for authority in self.authority_roots:
            for runtime in self.allowed_runtime_roots:
                if authority == runtime or authority in runtime.parents or runtime in authority.parents:
                    raise ValueError("authority and runtime root overlap is forbidden")
            for writable in (self.state_root, self.evidence_root, self.projection_root):
                if (
                    authority == writable
                    or authority in writable.parents
                    or writable in authority.parents
                ):
                    raise ValueError("writable and authority root overlap is forbidden")
        return self

from __future__ import annotations

import stat
from pathlib import Path

import pytest
import yaml

from skillctl.config import ControlPlaneConfig
from skillctl.errors import SafetyViolation
from skillctl.projection import ProjectionBuilder, validate_projection


def _config(tmp_path: Path) -> ControlPlaneConfig:
    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    executables = {}
    for name in ("skillshare", "gh"):
        executable = bin_root / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        executables[name] = executable
    return ControlPlaneConfig(
        registry_root=tmp_path / "registry",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(tmp_path / "authority",),
        allowed_runtime_roots=(tmp_path / "runtime",),
        trusted_cli_paths=executables,
    )


def _source_skill(config: ControlPlaneConfig) -> Path:
    source = config.authority_roots[0] / "canary-skill"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text("# Canary\n", encoding="utf-8")
    return source


def test_projection_builds_plan_bound_project_with_exact_config(tmp_path: Path) -> None:
    config = _config(tmp_path)
    source = _source_skill(config)
    targets = (tmp_path / "runtime" / "target-a", tmp_path / "runtime" / "target-b")

    descriptor = ProjectionBuilder(config).build("plan-1", source, targets)

    root = Path(descriptor.root)
    expected_targets = tuple(str(path.resolve()) for path in targets)
    assert root.parent == config.projection_root
    assert (root / ".skillshare/skills/canary-skill/SKILL.md").read_text() == "# Canary\n"
    assert yaml.safe_load((root / "skillshare.config.yaml").read_text()) == {
        "sources": {"skills": str(root / ".skillshare/skills")},
        "mode": "copy",
        "targets": {
            "target-a": {"skills": {"path": expected_targets[0], "mode": "copy"}},
            "target-b": {"skills": {"path": expected_targets[1], "mode": "copy"}},
        },
        "ignore": ["**/.git/**"],
    }
    assert yaml.safe_load((root / ".skillshare/config.yaml").read_text()) == {
        "sources": {"skills": str(root / ".skillshare/skills")},
        "mode": "copy",
        "targets": [
            {
                "name": "target-a",
                "skills": {"path": expected_targets[0], "mode": "copy"},
            },
            {
                "name": "target-b",
                "skills": {"path": expected_targets[1], "mode": "copy"},
            },
        ],
        "ignore": ["**/.git/**"],
    }
    assert validate_projection(config, descriptor) == expected_targets


def test_projection_descriptor_binds_content_and_target_set_to_plan(tmp_path: Path) -> None:
    config = _config(tmp_path)
    source = _source_skill(config)
    targets = (tmp_path / "runtime" / "target-a", tmp_path / "runtime" / "target-b")

    first = ProjectionBuilder(config).build("plan-1", source, targets)
    second = ProjectionBuilder(config).build("plan-2", source, targets)

    assert first.plan_id != second.plan_id
    assert first.root != second.root
    assert first.manifest_digest == second.manifest_digest
    assert first.config_digest != second.config_digest
    assert first.runtime_target_paths_digest == second.runtime_target_paths_digest


@pytest.mark.parametrize(
    "targets",
    (
        (Path("authority/target-a"), Path("runtime/target-b")),
        (Path("runtime/target-a"), Path("outside/target-b")),
        (Path("runtime/target-a"), Path(".config/skillshare/skills/target-b")),
    ),
)
def test_projection_rejects_targets_outside_runtime_roots(
    tmp_path: Path, targets: tuple[Path, Path]
) -> None:
    config = _config(tmp_path)
    source = _source_skill(config)
    resolved = tuple(path if path.is_absolute() else tmp_path / path for path in targets)

    with pytest.raises(SafetyViolation, match="runtime"):
        ProjectionBuilder(config).build("plan-1", source, resolved)


def test_projection_rejects_invalid_plan_or_target_cardinality(tmp_path: Path) -> None:
    config = _config(tmp_path)
    source = _source_skill(config)

    with pytest.raises(SafetyViolation, match="plan id"):
        ProjectionBuilder(config).build("../escape", source, ())
    with pytest.raises(SafetyViolation, match="exactly two"):
        ProjectionBuilder(config).build(
            "plan-1", source, (tmp_path / "runtime" / "target-a",)
        )


def test_projection_validation_detects_source_or_config_tampering(tmp_path: Path) -> None:
    config = _config(tmp_path)
    source = _source_skill(config)
    targets = (tmp_path / "runtime" / "target-a", tmp_path / "runtime" / "target-b")
    descriptor = ProjectionBuilder(config).build("plan-1", source, targets)

    copied_source = Path(descriptor.root) / ".skillshare/skills/canary-skill/SKILL.md"
    copied_source.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(SafetyViolation, match="digest"):
        validate_projection(config, descriptor)


def test_projection_validation_detects_runtime_config_tampering(tmp_path: Path) -> None:
    config = _config(tmp_path)
    source = _source_skill(config)
    targets = (tmp_path / "runtime" / "target-a", tmp_path / "runtime" / "target-b")
    descriptor = ProjectionBuilder(config).build("plan-1", source, targets)
    runtime_config = Path(descriptor.root) / ".skillshare/config.yaml"
    runtime_config.write_text(runtime_config.read_text() + "# tampered\n")

    with pytest.raises(SafetyViolation, match="digest"):
        validate_projection(config, descriptor)

    descriptor = ProjectionBuilder(config).build("plan-2", source, targets)
    project_config = Path(descriptor.root) / "skillshare.config.yaml"
    project_config.write_text(project_config.read_text() + "# tampered\n")
    with pytest.raises(SafetyViolation, match="digest"):
        validate_projection(config, descriptor)


@pytest.mark.parametrize("link_kind", ("file", "directory"))
@pytest.mark.parametrize("external_kind", ("outside", "runtime", "global-like"))
def test_projection_rejects_nested_source_symlinks_without_copying_external_content(
    tmp_path: Path, link_kind: str, external_kind: str
) -> None:
    config = _config(tmp_path)
    source = _source_skill(config)
    external_roots = {
        "outside": tmp_path / "outside",
        "runtime": config.allowed_runtime_roots[0],
        "global-like": tmp_path / ".config/skillshare/skills",
    }
    external = external_roots[external_kind]
    external.mkdir(parents=True, exist_ok=True)
    secret = external / "must-not-copy.txt"
    secret.write_text("external content\n", encoding="utf-8")
    link = source / "nested-link"
    link.symlink_to(secret if link_kind == "file" else external, target_is_directory=link_kind == "directory")
    targets = (tmp_path / "runtime" / "target-a", tmp_path / "runtime" / "target-b")

    with pytest.raises(SafetyViolation, match="symlink"):
        ProjectionBuilder(config).build("plan-symlink", source, targets)

    projection_root = config.projection_root / "plan-symlink"
    assert not projection_root.exists()
    assert secret.read_text() == "external content\n"

    link.unlink()
    (source / "local.txt").write_text("safe\n", encoding="utf-8")
    descriptor = ProjectionBuilder(config).build("plan-symlink", source, targets)
    copied = Path(descriptor.root) / ".skillshare/skills/canary-skill"
    assert not (copied / "must-not-copy.txt").exists()
    assert (copied / "local.txt").read_text() == "safe\n"

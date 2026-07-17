from __future__ import annotations

import shutil
import stat
import sys
from pathlib import Path

import pytest
from pydantic import JsonValue

from skillctl.errors import AdapterFailure, SafetyViolation
from skillctl.runner import CommandResult
from skillctl.runtime_inventory import discovery as runtime_discovery
from skillctl.runtime_inventory.discovery import (
    LIST,
    STATUS,
    TARGET_LIST,
    VERSION,
    discover_runtime_inventory,
)
from skillctl.runtime_inventory.models import ScanLimits


class FakeRunner:
    def __init__(self, payloads: dict[tuple[str, ...], JsonValue]) -> None:
        self._payloads = payloads
        self.calls: list[tuple[Path, tuple[str, ...], Path]] = []

    def run(self, executable: Path, args: tuple[str, ...], *, cwd: Path) -> CommandResult:
        self.calls.append((executable, args, cwd))
        return CommandResult(payload=self._payloads[args])


def _write_skill(path: Path, *, name: str, description: str, body: str = "body") -> None:
    path.mkdir(parents=True)
    (path / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n",
        encoding="utf-8",
    )


def _runner(
    *,
    shared: Path,
    targets: dict[str, Path],
    listed_skills: list[dict[str, JsonValue]],
    target_rules: dict[str, tuple[list[str], list[str]]] | None = None,
) -> FakeRunner:
    rules = target_rules or {}
    target_payload = [
        {
            "name": name,
            "path": str(path),
            "mode": "symlink" if name == "claude" else "copy",
            "include": rules.get(name, ([], []))[0],
            "exclude": rules.get(name, ([], []))[1],
        }
        for name, path in targets.items()
    ]
    return FakeRunner(
        {
            VERSION: "Skillshare CLI\nRuntime inventory\nv0.19.22\n",
            STATUS: {
                "source": {
                    "path": str(shared),
                    "skillignore": {
                        "active": False,
                        "files": [],
                        "patterns": [],
                        "ignored_count": 0,
                        "ignored_skills": [],
                    },
                },
                "targets": target_payload,
                "version": "0.19.22",
            },
            LIST: listed_skills,
            TARGET_LIST: {"targets": target_payload},
        }
    )


def _write_skillshare_executable(
    tmp_path: Path,
    *,
    shared: Path,
    malformed_command: tuple[str, ...] | None = None,
    required_home: Path | None = None,
) -> Path:
    payloads: dict[tuple[str, ...], JsonValue] = {
        VERSION: "Skillshare CLI\nRuntime inventory\nv0.19.22\n",
        STATUS: {
            "source": {"path": str(shared), "skillignore": str(shared / ".skillignore")},
            "targets": [],
            "version": "0.19.22",
        },
        LIST: [
            {"name": "alpha", "kind": "skill", "relPath": "alpha", "disabled": False}
        ],
        TARGET_LIST: {"targets": []},
    }
    executable = tmp_path / "skillshare"
    executable.write_text(
        f"""#!{sys.executable}
import json
import os
import sys

payloads = {payloads!r}
command = tuple(sys.argv[1:])
required_home = {str(required_home) if required_home is not None else None!r}
home_marker = os.path.join(required_home or "", ".config", "skillshare", "configured")
if required_home is not None and (
    os.environ.get("HOME") != required_home or not os.path.isfile(home_marker)
):
    raise SystemExit(12)
elif command == {malformed_command!r}:
    print("not-json")
elif command not in payloads:
    raise SystemExit(9)
elif command == {VERSION!r}:
    print(payloads[command], end="")
else:
    print(json.dumps(payloads[command]))
""",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def test_production_runner_preserves_trusted_home_for_skillshare_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    trusted_home = tmp_path / "trusted-home"
    marker = trusted_home / ".config" / "skillshare" / "configured"
    marker.parent.mkdir(parents=True)
    marker.write_text("configured\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(trusted_home))
    executable = _write_skillshare_executable(
        tmp_path,
        shared=shared,
        required_home=trusted_home,
    )
    runner_type = runtime_discovery.SkillshareInventoryCommandRunner
    runner = runner_type((executable,))

    result = runner.run(executable, STATUS, cwd=tmp_path)

    assert isinstance(result.payload, dict)
    assert result.payload["source"] == {
        "path": str(shared),
        "skillignore": str(shared / ".skillignore"),
    }


def test_production_runner_accepts_text_version_and_json_inventory(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    _write_skill(shared / "alpha", name="alpha", description="Shared alpha")
    executable = _write_skillshare_executable(tmp_path, shared=shared)

    snapshot = discover_runtime_inventory(
        skillshare_executable=executable,
        cwd=tmp_path,
    )

    assert snapshot.skillshare_version == "v0.19.22"
    assert [asset.name for asset in snapshot.assets] == ["alpha"]


def test_production_runner_requires_json_for_structured_commands(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    executable = _write_skillshare_executable(
        tmp_path,
        shared=shared,
        malformed_command=STATUS,
    )
    runner_type = runtime_discovery.SkillshareInventoryCommandRunner
    runner = runner_type((executable,))

    with pytest.raises(AdapterFailure, match="valid JSON"):
        runner.run(executable, STATUS, cwd=tmp_path)


def test_production_runner_rejects_non_inventory_argv(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    executable = _write_skillshare_executable(tmp_path, shared=shared)
    runner_type = runtime_discovery.SkillshareInventoryCommandRunner
    runner = runner_type((executable,))

    with pytest.raises(SafetyViolation, match="not allowed"):
        runner.run(executable, ("sync", "--json"), cwd=tmp_path)


def test_discovers_unique_assets_and_preserves_diverged_status(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    alpha = shared / "alpha"
    _write_skill(alpha, name="alpha", description="Shared alpha")

    codex = tmp_path / "codex"
    shutil.copytree(alpha, codex / "alpha-copy")
    _write_skill(codex / "local-dir", name="local-only", description="Local skill")

    claude = tmp_path / "claude"
    claude.mkdir()
    (claude / "alpha-link").symlink_to(alpha, target_is_directory=True)

    qoder = tmp_path / "qoder"
    _write_skill(qoder / "alpha-diverged", name="alpha", description="Shared alpha", body="changed")

    runner = _runner(
        shared=shared,
        targets={"qoder": qoder, "claude": claude, "codex": codex},
        listed_skills=[
            {"name": "alpha", "kind": "skill", "relPath": "alpha", "disabled": False}
        ],
    )

    snapshot = discover_runtime_inventory(
        runner,
        skillshare_executable=tmp_path / "bin" / "skillshare",
        cwd=tmp_path,
        limits=ScanLimits(),
    )

    assert [asset.name for asset in snapshot.assets] == ["alpha", "local-only"]
    assert snapshot.skillshare_version == "v0.19.22"
    assert snapshot.asset("alpha").description == "Shared alpha"
    assert snapshot.asset("alpha").status == "diverged"
    assert snapshot.asset("alpha").target("claude").is_symlink is True
    assert snapshot.asset("local-only").status == "local_only"
    assert [args for _, args, _ in runner.calls] == [VERSION, STATUS, LIST, TARGET_LIST]


def test_directory_digest_ignores_runtime_noise(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    stable = shared / "stable"
    _write_skill(stable, name="stable", description="Stable")
    (stable / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    codex = tmp_path / "codex"
    shutil.copytree(stable, codex / "stable")
    (stable / ".DS_Store").write_bytes(b"source noise")
    (codex / "stable" / ".DS_Store").write_bytes(b"target noise")
    (stable / "__pycache__").mkdir()
    (stable / "__pycache__" / "module.pyc").write_bytes(b"source bytecode")
    (codex / "stable" / "module.pyc").write_bytes(b"target bytecode")

    runner = _runner(
        shared=shared,
        targets={"codex": codex},
        listed_skills=[
            {"name": "stable", "kind": "skill", "relPath": "stable", "disabled": False}
        ],
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    assert snapshot.asset("stable").status == "consistent"
    assert (
        snapshot.asset("stable").source_instance.digest
        == snapshot.asset("stable").target("codex").digest
    )


def test_scan_limit_marks_asset_warning_without_reading_unbounded_files(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    limited = shared / "limited"
    _write_skill(limited, name="limited", description="Limited")
    (limited / "extra.txt").write_text("extra", encoding="utf-8")

    runner = _runner(
        shared=shared,
        targets={},
        listed_skills=[
            {"name": "limited", "kind": "skill", "relPath": "limited", "disabled": False}
        ],
    )

    snapshot = discover_runtime_inventory(
        runner,
        cwd=tmp_path,
        limits=ScanLimits(max_files=1, max_file_bytes=1024, max_total_bytes=1024),
    )

    assert snapshot.asset("limited").status == "scan_warning"
    assert any("file limit" in warning for warning in snapshot.warnings)


def test_archives_structured_ignored_skills_without_scanning_their_content(
    tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    _write_skill(shared / "enabled", name="enabled", description="Enabled")
    _write_skill(
        shared / "ignored-by-rule",
        name="ignored-by-rule",
        description="DO_NOT_STORE_RULE_CONTENT",
    )
    _write_skill(
        shared / "disabled-in-list",
        name="disabled-in-list",
        description="DO_NOT_STORE_DISABLED_CONTENT",
    )
    codex = tmp_path / "codex"
    _write_skill(codex / "ignored-copy", name="string-only", description="Ignored copy")
    runner = _runner(
        shared=shared,
        targets={"codex": codex},
        listed_skills=[
            {"name": "enabled", "kind": "skill", "relPath": "enabled", "disabled": False},
            {
                "name": "disabled-in-list",
                "kind": "skill",
                "relPath": "disabled-in-list",
                "disabled": True,
            },
            {
                "name": "disabled-alias",
                "kind": "skill",
                "relPath": "nested/string-only",
                "disabled": True,
            },
        ],
    )
    status = runner._payloads[STATUS]
    assert isinstance(status, dict)
    source = status["source"]
    assert isinstance(source, dict)
    skillignore = source["skillignore"]
    assert isinstance(skillignore, dict)
    skillignore.update(
        {
            "active": True,
            "patterns": ["ignored-*"],
            "ignored_count": 1,
            "ignored_skills": [
                "nested/string-only",
                {
                    "name": "ignored-by-rule",
                    "relPath": "ignored-by-rule",
                    "reason": "ignored-*",
                }
            ],
        }
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    assert [asset.name for asset in snapshot.assets] == ["enabled"]
    assert [(item.name, item.reason) for item in snapshot.ignored] == [
        ("disabled-in-list", "disabled"),
        ("ignored-by-rule", "ignored-*"),
        ("string-only", "skillignore"),
    ]
    assert snapshot.ignored[2].path == str(shared / "nested" / "string-only")
    serialized = snapshot.model_dump_json()
    assert "DO_NOT_STORE_RULE_CONTENT" not in serialized
    assert "DO_NOT_STORE_DISABLED_CONTENT" not in serialized


def test_target_patterns_determine_missing_targets_and_status_priority(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    _write_skill(shared / "alpha", name="alpha", description="Alpha")
    _write_skill(shared / "beta", name="beta", description="Beta")
    _write_skill(shared / "gamma", name="gamma", description="Gamma")

    codex = tmp_path / "codex"
    _write_skill(codex / "alpha", name="alpha", description="Alpha", body="diverged")
    qoder = tmp_path / "qoder"
    qoder.mkdir()
    claude = tmp_path / "claude"
    claude.mkdir()
    runner = _runner(
        shared=shared,
        targets={"codex": codex, "qoder": qoder, "claude": claude},
        target_rules={
            "codex": (["a*", "beta"], ["beta"]),
            "qoder": ([], ["beta", "gamma"]),
            "claude": (["beta"], []),
        },
        listed_skills=[
            {"name": name, "kind": "skill", "relPath": name, "disabled": False}
            for name in ("alpha", "beta", "gamma")
        ],
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    assert snapshot.asset("alpha").missing_targets == ("qoder",)
    assert snapshot.asset("alpha").status == "diverged"
    assert snapshot.asset("beta").missing_targets == ("claude",)
    assert snapshot.asset("beta").status == "missing"
    assert snapshot.asset("gamma").missing_targets == ()
    assert snapshot.asset("gamma").status == "consistent"


def test_unavailable_target_is_local_warning_and_preserves_other_results(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    alpha = shared / "alpha"
    _write_skill(alpha, name="alpha", description="Alpha")
    codex = tmp_path / "codex"
    shutil.copytree(alpha, codex / "alpha")
    unavailable = tmp_path / "unavailable"
    runner = _runner(
        shared=shared,
        targets={"codex": codex, "unavailable": unavailable},
        listed_skills=[
            {"name": "alpha", "kind": "skill", "relPath": "alpha", "disabled": False}
        ],
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    assert snapshot.asset("alpha").target("codex").readable is True
    assert snapshot.asset("alpha").missing_targets == ("unavailable",)
    assert snapshot.asset("alpha").status == "missing"
    assert {target.name: target.readable for target in snapshot.targets} == {
        "codex": True,
        "unavailable": False,
    }
    assert any("target directory is unavailable" in warning for warning in snapshot.warnings)


def test_internal_skill_file_symlink_is_not_followed_or_serialized(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    linked = shared / "linked-doc"
    linked.mkdir(parents=True)
    outside = tmp_path / "outside-skill.md"
    outside.write_text(
        "---\nname: linked-doc\ndescription: DO_NOT_READ_SYMLINK_MARKER\n---\n",
        encoding="utf-8",
    )
    (linked / "SKILL.md").symlink_to(outside)
    runner = _runner(
        shared=shared,
        targets={},
        listed_skills=[
            {
                "name": "linked-doc",
                "kind": "skill",
                "relPath": "linked-doc",
                "disabled": False,
            }
        ],
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    asset = snapshot.asset("linked-doc")
    assert asset.description is None
    assert asset.status == "scan_warning"
    assert asset.source_instance is not None
    assert asset.source_instance.readable is False
    assert any("internal symlink" in warning for warning in asset.source_instance.scan_warnings)
    assert "DO_NOT_READ_SYMLINK_MARKER" not in snapshot.model_dump_json()


def test_file_replacement_with_symlink_during_scan_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = tmp_path / "shared"
    frontmatter_skill = shared / "frontmatter-race"
    _write_skill(
        frontmatter_skill,
        name="frontmatter-race",
        description="Original frontmatter",
    )
    digest_skill = shared / "digest-race"
    _write_skill(digest_skill, name="digest-race", description="Digest race")
    digest_file = digest_skill / "payload.txt"
    digest_file.write_bytes(b"original digest content")

    outside_frontmatter = tmp_path / "outside-skill.md"
    outside_frontmatter.write_text(
        "---\nname: frontmatter-race\ndescription: DO_NOT_READ_RACED_FRONTMATTER\n---\n",
        encoding="utf-8",
    )
    outside_digest = tmp_path / "outside-payload.txt"
    outside_digest.write_bytes(b"DO_NOT_READ_RACED_DIGEST")

    replacements = {
        frontmatter_skill / "SKILL.md": outside_frontmatter,
        digest_file: outside_digest,
    }
    replaced: set[Path] = set()
    original_is_symlink = Path.is_symlink

    def replace_after_symlink_check(path: Path) -> bool:
        result = original_is_symlink(path)
        replacement = replacements.get(path)
        if replacement is not None and path not in replaced:
            path.unlink()
            path.symlink_to(replacement)
            replaced.add(path)
        return result

    monkeypatch.setattr(Path, "is_symlink", replace_after_symlink_check)
    runner = _runner(
        shared=shared,
        targets={},
        listed_skills=[
            {
                "name": "frontmatter-race",
                "kind": "skill",
                "relPath": "frontmatter-race",
                "disabled": False,
            },
            {
                "name": "digest-race",
                "kind": "skill",
                "relPath": "digest-race",
                "disabled": False,
            },
        ],
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    assert "DO_NOT_READ_RACED_FRONTMATTER" not in snapshot.model_dump_json()
    digest_instance = snapshot.asset("digest-race").source_instance
    assert digest_instance is not None
    assert digest_instance.readable is False
    assert digest_instance.scan_warnings


def test_shared_path_rejects_intermediate_symlink_but_allows_skill_root_symlink(
    tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    (shared / "nested").mkdir(parents=True)
    outside = tmp_path / "outside"
    _write_skill(
        outside / "skill",
        name="escaped",
        description="DO_NOT_READ_INTERMEDIATE_SYMLINK_MARKER",
    )
    (shared / "nested" / "link").symlink_to(outside, target_is_directory=True)

    allowed = tmp_path / "allowed-root"
    _write_skill(allowed, name="allowed-root", description="Allowed root link")
    (shared / "root-link").symlink_to(allowed, target_is_directory=True)
    runner = _runner(
        shared=shared,
        targets={},
        listed_skills=[
            {
                "name": "escaped",
                "kind": "skill",
                "relPath": "nested/link/skill",
                "disabled": False,
            },
            {
                "name": "allowed-root",
                "kind": "skill",
                "relPath": "root-link",
                "disabled": False,
            },
        ],
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    assert [asset.name for asset in snapshot.assets] == ["allowed-root"]
    source_instance = snapshot.asset("allowed-root").source_instance
    assert source_instance is not None
    assert source_instance.is_symlink is True
    assert any("intermediate symlink" in warning for warning in snapshot.warnings)
    assert "DO_NOT_READ_INTERMEDIATE_SYMLINK_MARKER" not in snapshot.model_dump_json()


def test_target_scan_skips_non_skill_subdirectories(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    codex = tmp_path / "codex"
    _write_skill(codex / "valid", name="valid", description="Valid")
    (codex / ".system").mkdir()
    (codex / ".system" / "cache.json").write_text("{}", encoding="utf-8")
    (codex / "ordinary-cache").mkdir()
    (codex / "ordinary-cache" / "entry.txt").write_text("cache", encoding="utf-8")
    runner = _runner(shared=shared, targets={"codex": codex}, listed_skills=[])

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path)

    assert [asset.name for asset in snapshot.assets] == ["valid"]
    assert snapshot.asset("valid").status == "local_only"


@pytest.mark.parametrize(
    ("limits", "expected_warning"),
    [
        (
            ScanLimits(max_files=10, max_file_bytes=128, max_total_bytes=1024),
            "file size limit",
        ),
        (
            ScanLimits(max_files=10, max_file_bytes=1024, max_total_bytes=64),
            "total byte limit",
        ),
    ],
)
def test_incomplete_quota_digest_cannot_be_consistent(
    tmp_path: Path,
    limits: ScanLimits,
    expected_warning: str,
) -> None:
    shared = tmp_path / "shared"
    bounded = shared / "bounded"
    _write_skill(bounded, name="bounded", description="Bounded")
    (bounded / "payload.txt").write_bytes(b"x" * 256)
    codex = tmp_path / "codex"
    shutil.copytree(bounded, codex / "bounded")
    runner = _runner(
        shared=shared,
        targets={"codex": codex},
        listed_skills=[
            {"name": "bounded", "kind": "skill", "relPath": "bounded", "disabled": False}
        ],
    )

    snapshot = discover_runtime_inventory(runner, cwd=tmp_path, limits=limits)

    asset = snapshot.asset("bounded")
    assert asset.status == "scan_warning"
    assert asset.source_instance is not None
    assert asset.source_instance.readable is False
    assert asset.target("codex").readable is False
    assert any(expected_warning in warning for warning in snapshot.warnings)


@pytest.mark.parametrize("rel_path", ["/tmp/outside", ".", "nested/../outside"])
def test_rejects_list_paths_outside_the_shared_root(tmp_path: Path, rel_path: str) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    runner = _runner(
        shared=shared,
        targets={},
        listed_skills=[
            {"name": "unsafe", "kind": "skill", "relPath": rel_path, "disabled": False}
        ],
    )

    with pytest.raises(AdapterFailure, match="safe relative path"):
        discover_runtime_inventory(runner, cwd=tmp_path)

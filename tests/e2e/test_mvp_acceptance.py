from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from skillctl.bootstrap import build_runtime
from skillctl.cli import app
from skillctl.config import ControlPlaneConfig


RUNNER = CliRunner()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in directories + files:
            path = current_path / name
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            if path.is_symlink():
                digest.update(os.readlink(path).encode("utf-8"))
            elif path.is_file():
                digest.update(path.read_bytes())
    return digest.hexdigest()


def _write_skillshare_contract(executable: Path) -> None:
    interpreter = Path(sys.executable)
    executable.write_text(
        f"""#!{interpreter}
import filecmp
import json
import shutil
import sys
from pathlib import Path

import yaml


def same_tree(source: Path, target: Path) -> bool:
    if not source.is_dir() or not target.is_dir():
        return False
    comparison = filecmp.dircmp(source, target)
    if comparison.left_only or comparison.right_only or comparison.funny_files:
        return False
    if any(not filecmp.cmp(source / name, target / name, shallow=False)
           for name in comparison.common_files):
        return False
    return all(same_tree(source / name, target / name)
               for name in comparison.common_dirs)


config = yaml.safe_load(Path("skillshare.config.yaml").read_text(encoding="utf-8"))
source = Path(config["sources"]["skills"])
targets = {{name: Path(item["skills"]["path"])
           for name, item in config["targets"].items()}}
command = sys.argv[1]
if command == "sync" and "--dry-run" not in sys.argv:
    for target in targets.values():
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)
    payload = {{"result": "synced"}}
elif command == "diff":
    payload = {{"targets": [
        {{"name": name, "synced": same_tree(source, target), "items": []}}
        for name, target in sorted(targets.items())
    ]}}
else:
    payload = {{"result": "ok"}}
print(json.dumps(payload, separators=(",", ":")))
""",
        encoding="utf-8",
    )
    executable.chmod(0o700)


@pytest.fixture
def mvp_workspace(mvp_root: Path, tmp_path: Path) -> tuple[Path, Path, Path]:
    governance = mvp_root / "governance"
    runtime_root = tmp_path / "runtime"
    assets_path = governance / "assets.yaml"
    assets = yaml.safe_load(assets_path.read_text(encoding="utf-8"))
    assets["items"][0]["source_path"] = "canary-skill"
    assets_path.write_text(
        yaml.safe_dump(assets, sort_keys=False), encoding="utf-8"
    )
    targets_path = governance / "targets.yaml"
    targets = yaml.safe_load(targets_path.read_text(encoding="utf-8"))
    for item in targets["items"]:
        item["config"]["root"] = str((runtime_root / item["id"]).resolve())
    targets_path.write_text(
        yaml.safe_dump(targets, sort_keys=False), encoding="utf-8"
    )

    bin_root = tmp_path / "bin"
    bin_root.mkdir()
    skillshare = bin_root / "skillshare"
    _write_skillshare_contract(skillshare)
    gh = bin_root / "gh"
    gh.write_text("#!/bin/sh\nprintf '{}\\n'\n", encoding="utf-8")
    gh.chmod(0o700)

    config = ControlPlaneConfig(
        registry_root=governance,
        state_root=governance,
        evidence_root=tmp_path / "evidence",
        projection_root=tmp_path / "projections",
        authority_roots=(mvp_root / "authority",),
        allowed_runtime_roots=(runtime_root,),
        trusted_cli_paths={"skillshare": skillshare, "gh": gh},
    )
    config_path = tmp_path / "control-plane.yaml"
    config_path.write_text(
        yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    return config_path, mvp_root / "authority", runtime_root


def _invoke(arguments: list[str], *, expected_exit: int = 0) -> dict[str, Any]:
    result = RUNNER.invoke(app, arguments)
    assert result.exit_code == expected_exit, (
        f"exit={result.exit_code}, stdout={result.stdout!r}, "
        f"stderr={result.stderr!r}, exception={result.exception!r}"
    )
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def test_mvp_canary_end_to_end(
    mvp_workspace: tuple[Path, Path, Path],
) -> None:
    config_path, authority, _ = mvp_workspace
    target_id = "target-local-b"
    base = ["--config", str(config_path)]
    authority_before = _tree_digest(authority)
    try:
        snapshot = build_runtime(config_path).read.snapshot()
        assert [asset.name for asset in snapshot.assets] == ["canary-skill"]

        plan = _invoke(["plan", *base, target_id])
        plan_id = str(plan["id"])
        _invoke(
            [
                "approve",
                *base,
                plan_id,
                "--approver",
                "mvp-reviewer",
                "--decision",
                "approved",
                "--reason",
                "canary reviewed",
            ]
        )
        deployment = _invoke(["apply", *base, plan_id])
        deployment_id = str(deployment["deployment_id"])

        healthy = _invoke(["status", *base, "--target", target_id])
        assert healthy["drift_count"] == 0
        assert all(
            (Path(path) / "canary-skill" / "SKILL.md").is_file()
            for path in plan["runtime_target_paths"]
        )

        managed_skill = Path(str(plan["runtime_target_paths"][0])) / "canary-skill"
        shutil.rmtree(managed_skill)
        drift = _invoke(
            ["drift", *base, "--target", target_id], expected_exit=4
        )
        assert drift["has_drift"] is True

        runtime = build_runtime(config_path)
        rollback_plan = runtime.deployment.create_rollback_plan(
            deployment_id, now=datetime.now(timezone.utc)
        )
        _invoke(
            [
                "approve",
                *base,
                rollback_plan.id,
                "--approver",
                "mvp-reviewer",
                "--decision",
                "approved",
                "--reason",
                "restore canary",
            ]
        )
        _invoke(["rollback", *base, deployment_id, rollback_plan.id])

        restored = _invoke(["status", *base, "--target", target_id])
        assert restored["drift_count"] == 0
        ledger = build_runtime(config_path).read.deployments()
        assert [entry.result for entry in ledger] == ["succeeded", "rolled_back"]
    finally:
        assert _tree_digest(authority) == authority_before

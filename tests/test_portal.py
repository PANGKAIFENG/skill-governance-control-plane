from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

import skillctl.portal as portal_module
from skillctl.bootstrap import build_runtime
from skillctl.errors import GovernanceValidationError
from skillctl.portal import build_local_portal_app, prepare_local_portal, run_local_portal


def _fake_executable(root: Path, name: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_prepare_local_portal_creates_portable_state_without_overwriting(
    tmp_path: Path,
) -> None:
    binaries = tmp_path / "bin"
    skillshare = _fake_executable(binaries, "skillshare")
    gh = _fake_executable(binaries, "gh")
    state_dir = tmp_path / "portal-state"

    config_path = prepare_local_portal(
        state_dir,
        skillshare_executable=skillshare,
        gh_executable=gh,
    )

    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert payload["trusted_cli_paths"] == {
        "skillshare": str(skillshare),
        "gh": str(gh),
    }
    assert Path(payload["state_root"]).is_relative_to(state_dir)
    assert Path(payload["registry_root"]).is_relative_to(state_dir)
    runtime = build_runtime(config_path)
    assert runtime.repository.load_snapshot().assets == ()

    assets_path = runtime.config.registry_root / "assets.yaml"
    assets_path.write_text(
        'schema_version: "1.0"\nitems: []\n# keep-me\n',
        encoding="utf-8",
    )
    prepare_local_portal(
        state_dir,
        skillshare_executable=skillshare,
        gh_executable=gh,
    )

    assert "# keep-me" in assets_path.read_text(encoding="utf-8")


def test_build_local_portal_app_serves_inventory_fallback(tmp_path: Path) -> None:
    skillshare = _fake_executable(tmp_path / "bin", "skillshare")
    gh = _fake_executable(tmp_path / "bin", "gh")
    config_path = prepare_local_portal(
        tmp_path / "portal-state",
        skillshare_executable=skillshare,
        gh_executable=gh,
    )

    app = build_local_portal_app(
        config_path,
        origin="http://127.0.0.1:8123",
    )

    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "Skill 资产" in response.text


def test_run_local_portal_rejects_non_loopback_host(tmp_path: Path) -> None:
    with pytest.raises(GovernanceValidationError, match="loopback"):
        run_local_portal(host="0.0.0.0", port=8000, state_dir=tmp_path)


def test_run_local_portal_starts_uvicorn_with_generated_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binaries = tmp_path / "bin"
    executables = {
        "skillshare": _fake_executable(binaries, "skillshare"),
        "gh": _fake_executable(binaries, "gh"),
    }
    calls: list[tuple[Any, str, int]] = []
    monkeypatch.setattr(
        portal_module.shutil,
        "which",
        lambda name: str(executables[name]),
    )
    monkeypatch.setattr(
        portal_module.uvicorn,
        "run",
        lambda app, *, host, port: calls.append((app, host, port)),
    )

    run_local_portal(
        host="127.0.0.1",
        port=8123,
        state_dir=tmp_path / "portal-state",
    )

    assert len(calls) == 1
    assert calls[0][1:] == ("127.0.0.1", 8123)

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
import yaml  # type: ignore[import-untyped]
from fastapi import FastAPI

from skillctl.bootstrap import build_runtime
from skillctl.errors import GovernanceValidationError
from skillctl.runtime_inventory import (
    RuntimeInventoryService,
    RuntimeInventoryStore,
    SkillshareInventoryDiscovery,
)
from skillctl.web import DecisionTokenStore, create_app
from skillctl.web.app import PortalReadProviders
from skillctl.web.readiness import EvidenceReadinessProvider
from skillctl.web.security import InventoryRefreshTokenStore


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})
_EMPTY_DOCUMENTS = (
    ("registry", "assets.yaml"),
    ("registry", "targets.yaml"),
    ("registry", "profiles.yaml"),
    ("registry", "profile-memberships.yaml"),
    ("registry", "consumer-bindings.yaml"),
    ("state", "observed-states.yaml"),
)


def _write_empty_document(path: Path) -> None:
    if path.exists():
        return
    path.write_text(
        yaml.safe_dump(
            {"schema_version": "1.0", "items": []},
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def prepare_local_portal(
    state_dir: Path,
    *,
    skillshare_executable: Path,
    gh_executable: Path,
) -> Path:
    root = state_dir.expanduser().resolve(strict=False)
    directories = {
        "registry": root / "registry",
        "state": root / "state",
        "evidence": root / "evidence",
        "projection": root / "projections",
        "runtime": root / "runtime",
    }
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in directories.values():
            directory.mkdir(mode=0o700, exist_ok=True)
        for directory_name, filename in _EMPTY_DOCUMENTS:
            _write_empty_document(directories[directory_name] / filename)
    except OSError:
        raise GovernanceValidationError("portal state could not be prepared") from None

    config_path = root / "control-plane.yaml"
    config = {
        "registry_root": str(directories["registry"]),
        "state_root": str(directories["state"]),
        "evidence_root": str(directories["evidence"]),
        "projection_root": str(directories["projection"]),
        "authority_roots": [],
        "allowed_runtime_roots": [str(directories["runtime"])],
        "trusted_cli_paths": {
            "skillshare": str(skillshare_executable),
            "gh": str(gh_executable),
        },
    }
    try:
        config_path.write_text(
            yaml.safe_dump(config, sort_keys=False),
            encoding="utf-8",
        )
    except OSError:
        raise GovernanceValidationError("portal configuration could not be written") from None
    return config_path


def build_local_portal_app(config_path: Path, *, origin: str) -> FastAPI:
    runtime = build_runtime(config_path)

    def now() -> datetime:
        return datetime.now(timezone.utc)

    inventory = RuntimeInventoryService(
        SkillshareInventoryDiscovery(
            skillshare_executable=runtime.config.trusted_cli_paths["skillshare"],
            cwd=Path.cwd(),
        ),
        RuntimeInventoryStore(runtime.config.state_root),
    )
    inventory.refresh()
    providers = PortalReadProviders(
        readiness=EvidenceReadinessProvider(runtime.config.evidence_root),
        runtime_inventory=inventory,
        runtime_inventory_refresher=inventory,
        inventory_refresh_tokens=InventoryRefreshTokenStore(
            now=now,
            allowed_origins=(origin,),
        ),
    )
    return create_app(
        runtime.read,
        runtime.approvals,
        DecisionTokenStore(
            now=now,
            allowed_origins=(origin,),
            approver="portal-reviewer",
        ),
        providers,
    )


def run_local_portal(*, host: str, port: int, state_dir: Path) -> None:
    if host not in _LOOPBACK_HOSTS:
        raise GovernanceValidationError("portal host must be loopback-only")
    executables: dict[str, Path] = {}
    for name in ("skillshare", "gh"):
        discovered = shutil.which(name)
        if discovered is None:
            raise GovernanceValidationError(f"portal requires the {name} executable")
        executables[name] = Path(discovered)
    config_path = prepare_local_portal(
        state_dir,
        skillshare_executable=executables["skillshare"],
        gh_executable=executables["gh"],
    )
    origin = f"http://{host}:{port}"
    app = build_local_portal_app(config_path, origin=origin)
    uvicorn.run(app, host=host, port=port)

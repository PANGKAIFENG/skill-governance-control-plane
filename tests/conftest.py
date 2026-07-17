"""Shared test fixtures."""

from pathlib import Path
from shutil import copytree

import pytest


@pytest.fixture
def mvp_root(tmp_path: Path) -> Path:
    source = Path("tests/fixtures/mvp")
    destination = tmp_path / "mvp"
    copytree(source, destination)
    return destination

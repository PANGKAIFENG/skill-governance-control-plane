import hashlib
import json
from pathlib import Path

import pytest

from skillctl.inventory import discover_inventory


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_discovers_mvp_inventory_without_mutating_fixture(mvp_root: Path) -> None:
    expected = json.loads(
        (mvp_root / "expected" / "inventory.json").read_text(encoding="utf-8")
    )
    before = _tree_digest(mvp_root)

    report = discover_inventory({"private": mvp_root / "authority"})

    after = _tree_digest(mvp_root)
    actual = report.model_dump(mode="json")
    for item in actual["items"]:
        item["source_path"] = Path(item["source_path"]).relative_to(mvp_root).as_posix()
    assert actual == expected
    assert after == before


def test_skips_symlinks_unreadable_directories_and_nested_git(
    mvp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority_root = mvp_root / "authority"
    (authority_root / "plain-directory").mkdir()
    nested_skill = authority_root / ".git" / "nested-skill"
    nested_skill.mkdir(parents=True)
    (nested_skill / "SKILL.md").write_text("ignored", encoding="utf-8")
    (authority_root / "canary-alias").symlink_to(
        authority_root / "canary-skill", target_is_directory=True
    )
    unreadable = authority_root / "unreadable-skill"
    unreadable.mkdir()
    unreadable_skill_md = unreadable / "SKILL.md"
    unreadable_skill_md.write_text("unreadable", encoding="utf-8")
    before = _tree_digest(mvp_root)
    original_is_file = Path.is_file

    def controlled_is_file(path: Path) -> bool:
        if path == unreadable_skill_md:
            raise PermissionError("controlled unreadable directory")
        return original_is_file(path)

    with monkeypatch.context() as context:
        context.setattr(Path, "is_file", controlled_is_file)
        report = discover_inventory({"private": authority_root})

    after = _tree_digest(mvp_root)
    assert tuple(item.name for item in report.items) == ("canary-skill",)
    assert after == before


def test_skips_skill_md_symlink(mvp_root: Path) -> None:
    authority_root = mvp_root / "authority"
    leaf_symlink_skill = authority_root / "leaf-symlink-skill"
    leaf_symlink_skill.mkdir()
    (leaf_symlink_skill / "SKILL.md").symlink_to(
        authority_root / "canary-skill" / "SKILL.md"
    )
    before = _tree_digest(mvp_root)

    report = discover_inventory({"private": authority_root})

    after = _tree_digest(mvp_root)
    assert tuple(item.name for item in report.items) == ("canary-skill",)
    assert after == before


def test_reports_public_private_canonical_path_conflicts(mvp_root: Path) -> None:
    authority_root = mvp_root / "authority"
    before = _tree_digest(mvp_root)

    report = discover_inventory(
        {"public": authority_root, "private": authority_root}
    )

    after = _tree_digest(mvp_root)
    canonical_path = str((authority_root / "canary-skill").resolve())
    assert tuple(item.authority_class for item in report.items) == (
        "private",
        "public",
    )
    assert report.conflicts == (canonical_path,)
    assert after == before

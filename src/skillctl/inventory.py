from pathlib import Path

from skillctl.models import StrictModel


class InventoryItem(StrictModel):
    name: str
    source_path: str
    has_skill_md: bool
    authority_class: str


class InventoryReport(StrictModel):
    items: tuple[InventoryItem, ...]
    conflicts: tuple[str, ...]


def discover_inventory(authority_roots: dict[str, Path]) -> InventoryReport:
    """Read only the first directory level of each authority root."""
    items: list[InventoryItem] = []
    classes_by_path: dict[str, set[str]] = {}
    for authority_class, root in sorted(authority_roots.items()):
        for candidate in sorted(root.iterdir(), key=lambda path: path.name):
            try:
                skill_md = candidate / "SKILL.md"
                has_skill_md = (
                    not candidate.is_symlink()
                    and candidate.is_dir()
                    and not skill_md.is_symlink()
                    and skill_md.is_file()
                )
            except PermissionError:
                continue
            if not has_skill_md:
                continue
            source_path = str(candidate.resolve())
            classes_by_path.setdefault(source_path, set()).add(authority_class)
            items.append(
                InventoryItem(
                    name=candidate.name,
                    source_path=source_path,
                    has_skill_md=True,
                    authority_class=authority_class,
                )
            )
    return InventoryReport(
        items=tuple(
            sorted(
                items,
                key=lambda item: (
                    item.source_path,
                    item.authority_class,
                    item.name,
                ),
            )
        ),
        conflicts=tuple(
            sorted(
                path
                for path, authority_classes in classes_by_path.items()
                if {"public", "private"} <= authority_classes
            )
        ),
    )

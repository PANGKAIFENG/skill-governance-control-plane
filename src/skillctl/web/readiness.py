from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol


ReadinessStatus = Literal[
    "VERIFIED",
    "COMPLETED_WITH_CONCERNS",
    "COMPLETED",
    "PASS",
    "UNKNOWN",
    "FAIL",
]


@dataclass(frozen=True)
class GateReadiness:
    gate: str
    title: str
    status: ReadinessStatus
    detail: str


@dataclass(frozen=True)
class ReadinessPresentation:
    rows: tuple[GateReadiness, ...]
    evidence_closed: bool
    overall_label: str


class ReadinessProvider(Protocol):
    def readiness(self) -> tuple[GateReadiness, ...]: ...


def build_readiness_presentation(
    rows: tuple[GateReadiness, ...],
) -> ReadinessPresentation:
    evidence_closed = tuple((row.gate, row.status) for row in rows) == (
        ("Gate 1", "VERIFIED"),
        ("Gate 2", "COMPLETED_WITH_CONCERNS"),
        ("Gate 3", "COMPLETED"),
        ("Gate 4", "PASS"),
    )
    return ReadinessPresentation(
        rows=rows,
        evidence_closed=evidence_closed,
        overall_label="Gate 1–4 已完成" if evidence_closed else "证据未完整闭合",
    )


_GATE_2_FILE = "gate-2-core-adjudication.md"
_GATE_3_FILE = "gate-3-authority-candidate.md"
_GATE_4_LIFECYCLE_FILE = "skillshare-canary-lifecycle.json"
_GATE_4_COMPATIBILITY_FILE = "skillshare-compatibility-matrix.json"
_FENCE_LINE = re.compile(r"^ {0,3}```(?P<info>[^`]*)\s*$")
_STATUS_DIGEST = re.compile(r"status_digest=[0-9a-f]{64}")
_TREE_DIGEST = re.compile(r"tree_digest=[0-9a-f]{64}")
_GATE_3_PATHS = (
    "SKILL_REGISTRY.md",
    "SKILL_ROUTING.md",
    "docs/governance/single-writer-policy.md",
    "docs/local-distribution.md",
    "prd-architect/SKILL.md",
    "prd-architect/evals/evals.json",
    "prd-architect/evals/fixtures/legacy-five-tab-dashboard.html",
    "prd-architect/references/mockup-handoff.md",
    "prd-architect/references/prd-shape-gates.md",
    "prd-architect/scripts/check_prd_shape.py",
    "prd-architect/tests/test_check_prd_shape.py",
    "scripts/audit_skills.py",
    "tests/test_audit_skills.py",
)
_MAX_EVIDENCE_BYTES = 2_000_000


class _EvidenceUnavailable(Exception):
    pass


class _EvidenceMalformed(Exception):
    pass


@dataclass(frozen=True)
class _FenceBlock:
    opening_line: int
    closing_line: int
    info: str
    content: tuple[str, ...]


@dataclass(frozen=True)
class _MarkdownDocument:
    lines: tuple[str, ...]
    outside_text: str
    blocks: tuple[_FenceBlock, ...]


def _parse_markdown(text: str) -> _MarkdownDocument | None:
    lines = tuple(text.splitlines())
    outside_lines = [""] * len(lines)
    blocks: list[_FenceBlock] = []
    opening_line: int | None = None
    info = ""
    content: list[str] = []

    for line_number, line in enumerate(lines):
        fence = _FENCE_LINE.fullmatch(line)
        if opening_line is None:
            if fence is None:
                outside_lines[line_number] = line
                continue
            opening_line = line_number
            info = fence.group("info").strip()
            content = []
            continue
        if fence is None:
            content.append(line)
            continue
        if fence.group("info").strip():
            return None
        blocks.append(
            _FenceBlock(
                opening_line=opening_line,
                closing_line=line_number,
                info=info,
                content=tuple(content),
            )
        )
        opening_line = None
        info = ""
        content = []

    if opening_line is not None:
        return None
    return _MarkdownDocument(
        lines=lines,
        outside_text="\n".join(outside_lines),
        blocks=tuple(blocks),
    )


def _text_block_after_marker(
    document: _MarkdownDocument, marker: str
) -> tuple[str, ...] | None:
    if document.outside_text.count(marker) != 1:
        return None
    marker_lines = tuple(
        index for index, line in enumerate(document.lines) if marker in line
    )
    if len(marker_lines) != 1:
        return None
    next_line = marker_lines[0] + 1
    while next_line < len(document.lines) and not document.lines[next_line].strip():
        next_line += 1
    blocks_by_opening = {block.opening_line: block for block in document.blocks}
    block = blocks_by_opening.get(next_line)
    if block is None or block.info != "text":
        return None

    following_line = block.closing_line + 1
    while (
        following_line < len(document.lines)
        and not document.lines[following_line].strip()
    ):
        following_line += 1
    if following_line in blocks_by_opening:
        return None
    return block.content


class EvidenceReadinessProvider:
    def __init__(self, evidence_root: Path) -> None:
        self._evidence_root = evidence_root

    def readiness(self) -> tuple[GateReadiness, ...]:
        gate_2_document: _MarkdownDocument | None = None
        gate_2_unavailable = False
        try:
            gate_2_document = _parse_markdown(self._read_text(_GATE_2_FILE))
        except _EvidenceUnavailable:
            gate_2_unavailable = True

        gate_1 = self._gate_1(gate_2_document, gate_2_unavailable)
        gate_2 = self._gate_2(gate_2_document, gate_2_unavailable)
        gate_3 = self._gate_3()
        gate_4 = self._gate_4()
        return (gate_1, gate_2, gate_3, gate_4)

    def _gate_1(
        self, document: _MarkdownDocument | None, unavailable: bool
    ) -> GateReadiness:
        if unavailable:
            return GateReadiness("Gate 1", "运行源基线", "UNKNOWN", "复核证据不可用")
        if document is None:
            return GateReadiness("Gate 1", "运行源基线", "FAIL", "复核证据格式无效")
        if not self._single_gate_2_conclusion(document):
            return GateReadiness("Gate 1", "运行源基线", "FAIL", "复核证据存在冲突")
        digest_lines = _text_block_after_marker(
            document, "结果与 Gate 1 不可变基线完全一致"
        )
        if (
            digest_lines is not None
            and len(digest_lines) == 2
            and _STATUS_DIGEST.fullmatch(digest_lines[0]) is not None
            and _TREE_DIGEST.fullmatch(digest_lines[1]) is not None
        ):
            return GateReadiness(
                "Gate 1",
                "运行源基线",
                "VERIFIED",
                "由 Gate 2 复核证据证明",
            )
        return GateReadiness("Gate 1", "运行源基线", "FAIL", "基线复核证据不完整")

    def _gate_2(
        self, document: _MarkdownDocument | None, unavailable: bool
    ) -> GateReadiness:
        if unavailable:
            return GateReadiness("Gate 2", "核心资产裁决", "UNKNOWN", "裁决证据不可用")
        if document is None:
            return GateReadiness("Gate 2", "核心资产裁决", "FAIL", "裁决证据格式无效")
        if self._single_gate_2_conclusion(document):
            return GateReadiness(
                "Gate 2",
                "核心资产裁决",
                "COMPLETED_WITH_CONCERNS",
                "裁决完成，保留已记录关注项",
            )
        return GateReadiness("Gate 2", "核心资产裁决", "FAIL", "裁决结论缺失或冲突")

    def _gate_3(self) -> GateReadiness:
        try:
            text = self._read_text(_GATE_3_FILE)
        except _EvidenceUnavailable:
            return GateReadiness("Gate 3", "Authority 候选", "UNKNOWN", "候选证据不可用")
        document = _parse_markdown(text)
        if document is None:
            return GateReadiness("Gate 3", "Authority 候选", "FAIL", "候选证据格式无效")
        conclusions = re.findall(r"(?m)^结论：`([^`]+)`。", document.outside_text)
        paths = _text_block_after_marker(document, "精确为 13 个路径")
        if conclusions == ["DONE"] and paths == _GATE_3_PATHS:
            return GateReadiness(
                "Gate 3", "Authority 候选", "COMPLETED", "13 个批准路径已完成"
            )
        return GateReadiness("Gate 3", "Authority 候选", "FAIL", "候选结论或路径清单不匹配")

    def _gate_4(self) -> GateReadiness:
        try:
            lifecycle = self._read_json(_GATE_4_LIFECYCLE_FILE)
            compatibility = self._read_json(_GATE_4_COMPATIBILITY_FILE)
        except (_EvidenceUnavailable, _EvidenceMalformed):
            return GateReadiness("Gate 4", "Adapter 兼容性", "UNKNOWN", "兼容性证据不可用")

        lifecycle_safety = lifecycle.get("safety_after")
        compatibility_safety = compatibility.get("safety_verification")
        if not isinstance(lifecycle_safety, dict) or not isinstance(
            compatibility_safety, dict
        ):
            return GateReadiness("Gate 4", "Adapter 兼容性", "FAIL", "安全证据不完整")
        global_cli = compatibility_safety.get("global_cli")
        global_tree = compatibility_safety.get("global_skills_tree")
        safety_checks = (
            lifecycle.get("result") == "PASS",
            compatibility.get("result") == "compatible",
            lifecycle_safety.get("global_cli_unchanged") is True,
            lifecycle_safety.get("global_skills_tree_unchanged") is True,
            compatibility_safety.get("all_sync_commands_were_dry_run") is True,
            compatibility_safety.get("runtime_target_entries_after") == [],
            compatibility_safety.get("apply_commands_run") == [],
            isinstance(global_cli, dict),
            isinstance(global_tree, dict),
            isinstance(global_cli, dict)
            and global_cli.get("version_matches_baseline") is True,
            isinstance(global_cli, dict)
            and global_cli.get("sha256_matches_baseline") is True,
            isinstance(global_tree, dict)
            and global_tree.get("sha256_matches_baseline") is True,
        )
        if all(safety_checks):
            return GateReadiness(
                "Gate 4", "Adapter 兼容性", "PASS", "隔离兼容性与安全校验通过"
            )
        return GateReadiness("Gate 4", "Adapter 兼容性", "FAIL", "兼容性或安全校验未通过")

    def _read_text(self, filename: str) -> str:
        path = self._evidence_root / filename
        try:
            if not path.is_file() or path.stat().st_size > _MAX_EVIDENCE_BYTES:
                raise _EvidenceUnavailable
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise _EvidenceUnavailable from None

    def _read_json(self, filename: str) -> dict[str, Any]:
        text = self._read_text(filename)
        try:
            value = json.loads(text, object_pairs_hook=self._unique_object)
        except (json.JSONDecodeError, _EvidenceMalformed):
            raise _EvidenceMalformed from None
        if not isinstance(value, dict):
            raise _EvidenceMalformed
        return value

    @staticmethod
    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise _EvidenceMalformed
            value[key] = child
        return value

    @staticmethod
    def _single_gate_2_conclusion(document: _MarkdownDocument) -> bool:
        return re.findall(r"(?m)^结论：`([^`]+)`。", document.outside_text) == [
            "DONE_WITH_CONCERNS"
        ]

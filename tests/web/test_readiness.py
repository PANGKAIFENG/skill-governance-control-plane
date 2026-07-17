from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillctl.web.readiness import (
    EvidenceReadinessProvider,
    build_readiness_presentation,
)


GATE_3_PATHS = (
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


def _write_valid_evidence(root: Path) -> None:
    (root / "gate-2-core-adjudication.md").write_text(
        "\n".join(
            (
                "结论：`DONE_WITH_CONCERNS`。",
                "结果与 Gate 1 不可变基线完全一致：",
                "```text",
                "status_digest=" + "a" * 64,
                "tree_digest=" + "b" * 64,
                "```",
            )
        ),
        encoding="utf-8",
    )
    (root / "gate-3-authority-candidate.md").write_text(
        "\n".join(
            (
                "结论：`DONE`。",
                "最终 authority diff pathspec",
                "精确为 13 个路径：",
                "```text",
                *GATE_3_PATHS,
                "```",
            )
        ),
        encoding="utf-8",
    )
    (root / "skillshare-canary-lifecycle.json").write_text(
        json.dumps(
            {
                "result": "PASS",
                "safety_after": {
                    "global_cli_unchanged": True,
                    "global_skills_tree_unchanged": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (root / "skillshare-compatibility-matrix.json").write_text(
        json.dumps(
            {
                "result": "compatible",
                "safety_verification": {
                    "apply_commands_run": [],
                    "all_sync_commands_were_dry_run": True,
                    "runtime_target_entries_after": [],
                    "global_cli": {
                        "version_matches_baseline": True,
                        "sha256_matches_baseline": True,
                    },
                    "global_skills_tree": {"sha256_matches_baseline": True},
                },
            }
        ),
        encoding="utf-8",
    )


def test_reads_only_whitelisted_evidence_into_exact_gate_states(tmp_path: Path) -> None:
    _write_valid_evidence(tmp_path)
    (tmp_path / "gate-2-core-adjudication-copy.md").write_text(
        "结论：`FAIL`。", encoding="utf-8"
    )

    rows = EvidenceReadinessProvider(tmp_path).readiness()

    assert tuple(row.gate for row in rows) == ("Gate 1", "Gate 2", "Gate 3", "Gate 4")
    assert tuple(row.status for row in rows) == (
        "VERIFIED",
        "COMPLETED_WITH_CONCERNS",
        "COMPLETED",
        "PASS",
    )
    assert rows[0].detail == "由 Gate 2 复核证据证明"
    assert all("生产已就绪" not in row.detail for row in rows)


def test_ignores_gate_conclusions_and_baseline_claims_inside_fenced_code(
    tmp_path: Path,
) -> None:
    _write_valid_evidence(tmp_path)
    (tmp_path / "gate-2-core-adjudication.md").write_text(
        "\n".join(
            (
                "正文没有裁决结论。",
                "```text",
                "结论：`DONE_WITH_CONCERNS`。",
                "结果与 Gate 1 不可变基线完全一致：",
                "status_digest=" + "a" * 64,
                "tree_digest=" + "b" * 64,
                "```",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "gate-3-authority-candidate.md").write_text(
        "\n".join(
            (
                "正文没有候选结论。",
                "```text",
                "结论：`DONE`。",
                "```",
                "精确为 13 个路径：",
                "```text",
                *GATE_3_PATHS,
                "```",
            )
        ),
        encoding="utf-8",
    )

    rows = EvidenceReadinessProvider(tmp_path).readiness()

    assert tuple(row.status for row in rows[:3]) == ("FAIL", "FAIL", "FAIL")
    assert build_readiness_presentation(rows).evidence_closed is False


@pytest.mark.parametrize("fence_tail", ((), ("```json", "```", "```")))
def test_rejects_unclosed_or_nested_baseline_digest_fences(
    tmp_path: Path, fence_tail: tuple[str, ...]
) -> None:
    _write_valid_evidence(tmp_path)
    (tmp_path / "gate-2-core-adjudication.md").write_text(
        "\n".join(
            (
                "结论：`DONE_WITH_CONCERNS`。",
                "结果与 Gate 1 不可变基线完全一致：",
                "```text",
                "status_digest=" + "a" * 64,
                "tree_digest=" + "b" * 64,
                *fence_tail,
            )
        ),
        encoding="utf-8",
    )

    rows = EvidenceReadinessProvider(tmp_path).readiness()

    assert tuple(row.status for row in rows[:2]) == ("FAIL", "FAIL")


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("missing-gate-2", ("UNKNOWN", "UNKNOWN", "COMPLETED", "PASS")),
        ("bad-lifecycle-json", ("VERIFIED", "COMPLETED_WITH_CONCERNS", "COMPLETED", "UNKNOWN")),
        ("conflicting-gate-2", ("FAIL", "FAIL", "COMPLETED", "PASS")),
        ("extra-gate-3-path", ("VERIFIED", "COMPLETED_WITH_CONCERNS", "FAIL", "PASS")),
        ("unsafe-gate-4", ("VERIFIED", "COMPLETED_WITH_CONCERNS", "COMPLETED", "FAIL")),
    ),
)
def test_fails_closed_for_missing_malformed_conflicting_or_unsafe_evidence(
    tmp_path: Path, mutation: str, expected: tuple[str, ...]
) -> None:
    _write_valid_evidence(tmp_path)
    if mutation == "missing-gate-2":
        (tmp_path / "gate-2-core-adjudication.md").unlink()
    elif mutation == "bad-lifecycle-json":
        (tmp_path / "skillshare-canary-lifecycle.json").write_text(
            "{not-json", encoding="utf-8"
        )
    elif mutation == "conflicting-gate-2":
        path = tmp_path / "gate-2-core-adjudication.md"
        path.write_text(path.read_text(encoding="utf-8") + "\n结论：`DONE`。")
    elif mutation == "extra-gate-3-path":
        path = tmp_path / "gate-3-authority-candidate.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "tests/test_audit_skills.py\n```",
                "tests/test_audit_skills.py\nREADME.md\n```",
            ),
            encoding="utf-8",
        )
    elif mutation == "unsafe-gate-4":
        path = tmp_path / "skillshare-compatibility-matrix.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["safety_verification"]["all_sync_commands_were_dry_run"] = False
        path.write_text(json.dumps(payload), encoding="utf-8")

    rows = EvidenceReadinessProvider(tmp_path).readiness()

    assert tuple(row.status for row in rows) == expected

"""Wiring of the reusable source-scan workflow."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security-source.yml"


def _wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_notify_input_is_kept_as_a_no_op():
    """Callers still pass it; removing a passed input breaks the caller."""
    inp = _wf()[True]["workflow_call"]["inputs"]["notify-on-schedule-failure"]
    assert inp["default"] is False
    assert "Deprecated" in inp["description"]
    assert list(_wf()["jobs"]) == ["scan"]
    assert "gh issue" not in WORKFLOW.read_text()


# ── Semgrep (v11) ────────────────────────────────────────────────────────


def _scan_steps() -> list[dict]:
    return _wf()["jobs"]["scan"]["steps"]


def _semgrep() -> dict:
    (step,) = [s for s in _scan_steps() if s.get("id") == "semgrep"]
    return step


def test_semgrep_is_off_by_default():
    # Existing callers pass no semgrep-configs and must see no new scanner.
    inputs = _wf()[True]["workflow_call"]["inputs"]
    assert inputs["semgrep-configs"]["default"] == ""
    assert inputs["semgrep-paths"]["default"] == "."
    assert _semgrep()["if"] == "inputs.semgrep-configs != ''"
    assert _semgrep()["continue-on-error"] is True


def test_semgrep_is_pinned():
    step = _semgrep()
    assert step["env"]["SEMGREP_VERSION"] == "1.181.0"
    assert '"semgrep==${SEMGREP_VERSION}"' in step["run"]


def test_semgrep_inputs_reach_the_shell_through_env_only():
    run = _semgrep()["run"]
    assert "${{" not in run
    assert _semgrep()["env"]["SEMGREP_CONFIGS"] == "${{ inputs.semgrep-configs }}"
    assert _semgrep()["env"]["SEMGREP_PATHS"] == "${{ inputs.semgrep-paths }}"
    assert "set -f" in run


def test_semgrep_flags():
    run = _semgrep()["run"]
    for flag in (
        "--severity WARNING --severity ERROR",
        "--error",
        "--metrics=off",
        # No inline or ignore-file waivers: only the exception file waives.
        "--disable-nosem",
        "--x-ignore-semgrepignore-files",
        '--json-output "$SEMGREP_JSON"',
    ):
        assert flag in run, flag
    assert "--severity INFO" not in run


def test_semgrep_excludes_the_same_noise_dirs_as_bandit():
    (bandit,) = [s for s in _scan_steps() if s.get("id") == "bandit"]
    run = _semgrep()["run"]
    # .security-tooling: the security-ci checkout itself, not the caller's code.
    for d in ("node_modules", ".venv", "dist", ".worktrees", ".wt-*", "tests", ".security-tooling"):
        assert d in bandit["run"], d
        assert f"--exclude {d}" in run or f"--exclude '{d}'" in run, d


def test_semgrep_waivers_come_from_the_exception_file():
    run = _semgrep()["run"]
    assert "--emit-semgrep-args" in run
    assert "$EXCLUDE_RULES" in run
    assert '--semgrep-json "$SEMGREP_JSON"' in run


def test_semgrep_fails_closed_on_any_exit_but_clean_or_findings():
    run = _semgrep()["run"]
    assert "0|1) ;;" in run
    assert '*) echo "::error::semgrep exited $rc' in run


def test_semgrep_is_in_the_verdict():
    (verdict,) = [s for s in _scan_steps() if s.get("id") == "verdict"]
    assert verdict["env"]["SEMGREP"] == "${{ steps.semgrep.outcome }}"
    assert verdict["env"]["SEMGREP_ON"] == "${{ inputs.semgrep-configs != '' }}"
    assert 'report semgrep "$SEMGREP_ON" "$SEMGREP"' in verdict["run"]

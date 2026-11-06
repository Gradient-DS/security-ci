"""Wiring of the reusable image-scan workflow's optional inputs."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security-image.yml"


def _wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _inputs() -> dict:
    # `on` parses as the boolean True under YAML 1.1.
    return _wf()[True]["workflow_call"]["inputs"]


def _build_step() -> dict:
    steps = [s for s in _wf()["jobs"]["scan"]["steps"] if str(s.get("uses", "")).startswith("docker/build-push-action")]
    assert len(steps) == 1
    return steps[0]


def test_no_cache_filters_defaults_off_and_reaches_the_build():
    assert _inputs()["no-cache-filters"]["default"] == ""
    assert _build_step()["with"]["no-cache-filters"] == "${{ inputs.no-cache-filters }}"


def test_notify_input_is_kept_as_a_no_op():
    """Callers still pass it; removing a passed input breaks the caller."""
    assert _inputs()["notify-on-schedule-failure"]["default"] is False
    assert "Deprecated" in _inputs()["notify-on-schedule-failure"]["description"]
    assert list(_wf()["jobs"]) == ["scan"]
    assert "gh issue" not in WORKFLOW.read_text()


def test_verdict_writes_the_digest_and_failures_to_the_summary():
    steps = {s.get("id"): s for s in _wf()["jobs"]["scan"]["steps"]}
    assert '>> "$GITHUB_STEP_SUMMARY"' in steps["verdict"]["run"]


def test_scan_job_names_what_failed_even_when_it_fails():
    steps = {s.get("id"): s for s in _wf()["jobs"]["scan"]["steps"]}
    assert steps["verdict"]["if"] == "always()"
    outputs = _wf()["jobs"]["scan"]["outputs"]
    assert outputs == {"failed": "${{ steps.verdict.outputs.failed }}", "image": "${{ steps.verdict.outputs.image }}"}
    for sid in ("trivyignore", "build", "trivy"):
        assert sid in steps

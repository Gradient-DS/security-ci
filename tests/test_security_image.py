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
    steps = [s for s in _wf()["jobs"]["scan"]["steps"]
             if str(s.get("uses", "")).startswith("docker/build-push-action")]
    assert len(steps) == 1
    return steps[0]


def test_no_cache_filters_defaults_off_and_reaches_the_build():
    assert _inputs()["no-cache-filters"]["default"] == ""
    assert _build_step()["with"]["no-cache-filters"] == "${{ inputs.no-cache-filters }}"


def test_notifier_is_opt_in_and_schedule_only():
    assert _inputs()["notify-on-schedule-failure"]["default"] is False
    cond = _wf()["jobs"]["notify-scheduled-failure"]["if"]
    for part in ("always()", "inputs.notify-on-schedule-failure", "github.event_name == 'schedule'",
                 "needs.scan.result == 'failure'"):
        assert part in cond


def test_notifier_requests_no_permissions_of_its_own():
    """A reusable job asking for `issues: write` fails every caller that does
    not grant it at startup, whatever its `if` says: v6 callers grant only
    contents/packages read."""
    assert "permissions" not in _wf()["jobs"]["notify-scheduled-failure"]


def test_scan_job_names_what_failed_even_when_it_fails():
    steps = {s.get("id"): s for s in _wf()["jobs"]["scan"]["steps"]}
    assert steps["verdict"]["if"] == "always()"
    outputs = _wf()["jobs"]["scan"]["outputs"]
    assert outputs == {"failed": "${{ steps.verdict.outputs.failed }}",
                       "image": "${{ steps.verdict.outputs.image }}"}
    for sid in ("trivyignore", "build", "trivy"):
        assert sid in steps

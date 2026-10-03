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

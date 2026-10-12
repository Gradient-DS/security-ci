"""Wiring of the reusable source-scan workflow's scheduled-failure notifier."""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security-source.yml"


def _wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_notifier_is_opt_in_and_scheduled_only():
    # `on` parses as the boolean True under YAML 1.1.
    assert _wf()[True]["workflow_call"]["inputs"]["notify-on-schedule-failure"]["default"] is False
    cond = _wf()["jobs"]["notify-scheduled-failure"]["if"]
    for part in ("always()", "inputs.notify-on-schedule-failure", "github.event_name == 'schedule'"):
        assert part in cond


def test_notifier_inherits_the_callers_permissions():
    # A grant requested here fails every caller that does not give it.
    assert "permissions" not in _wf()["jobs"]["notify-scheduled-failure"]

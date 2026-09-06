"""Every combination of the gate's inputs, because a gate is worth what its
worst case is worth. The dangerous direction is a false pass: a gate that
reports green when it did not actually run blocks nothing while looking like it
blocks everything.
"""

import itertools

import pytest

from scripts.runtime_gate import RESULTS, decide, main

EVENTS = ("pull_request", "schedule")


def test_every_combination_is_decided():
    """No input combination may fall through undecided."""
    for relevant, event, result in itertools.product((True, False), EVENTS, RESULTS):
        passed, reason = decide(relevant=relevant, event=event, audit_result=result)
        assert isinstance(passed, bool)
        assert reason.strip(), (relevant, event, result)


@pytest.mark.parametrize("event", EVENTS)
def test_success_passes_whenever_the_audit_ran(event):
    assert decide(relevant=True, event=event, audit_result="success")[0] is True


@pytest.mark.parametrize("result", ("failure", "cancelled"))
@pytest.mark.parametrize("event", EVENTS)
def test_a_failed_audit_fails_the_gate(event, result):
    assert decide(relevant=True, event=event, audit_result=result)[0] is False


def test_skipped_passes_only_when_the_paths_were_irrelevant():
    assert decide(relevant=False, event="pull_request", audit_result="skipped")[0] is True


def test_skipped_on_a_relevant_change_fails():
    """The case that makes this a script instead of a one-line shell test.

    A cancelled dependency or a reusable workflow that failed to load both
    surface as `skipped`, and both mean the gate did not run.
    """
    passed, reason = decide(relevant=True, event="pull_request", audit_result="skipped")

    assert passed is False
    assert "did not run" in reason


def test_the_nightly_run_is_never_path_filtered():
    """soev-solutions' Helm charts live in another repo, so its PR filter cannot
    see a chart change. The schedule is what covers that, which only holds if
    `schedule` ignores relevance."""
    passed, _ = decide(relevant=False, event="schedule", audit_result="skipped")

    assert passed is False


@pytest.mark.parametrize("result", ("failure", "cancelled"))
def test_a_failure_outside_the_filter_still_fails(result):
    assert decide(relevant=False, event="pull_request", audit_result=result)[0] is False


def test_cli_exit_codes():
    assert main(["--relevant", "true", "--event", "pull_request",
                 "--audit-result", "success"]) == 0
    assert main(["--relevant", "true", "--event", "pull_request",
                 "--audit-result", "failure"]) == 1
    assert main(["--relevant", "false", "--event", "pull_request",
                 "--audit-result", "skipped"]) == 0

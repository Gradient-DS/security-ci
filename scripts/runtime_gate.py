"""Decide whether the runtime-security gate passes.

`gate` is a required status check on every consuming repo's ruleset, and a job
skipped by a workflow-level `on: paths:` filter reports no status at all -- a
path-filtered required check leaves every pull request waiting forever for a
check that will never arrive. So the workflow always runs, the expensive job is
filtered *inside* it, and this decides the outcome.

The subtlety worth testing: `skipped` means pass only when the paths were
irrelevant. A run skipped for any other reason -- a cancelled dependency, a
syntax error in the reusable workflow, a failed `changes` job -- is a gate that
did not run, which must never be reported as a gate that passed.
"""

from __future__ import annotations

import argparse
import sys

#: Outcomes GitHub reports for a `needs.<job>.result`.
RESULTS = ("success", "failure", "cancelled", "skipped")


def decide(*, relevant: bool, event: str, audit_result: str) -> tuple[bool, str]:
    """Return (passed, reason)."""
    expected_to_run = relevant or event == "schedule"

    if not expected_to_run:
        if audit_result in ("skipped", ""):
            return True, "No runtime-relevant paths changed -- nothing to test."
        if audit_result == "success":
            return True, "Runtime security passed (ran despite irrelevant paths)."
        return False, (
            f"The runtime audit ran on an irrelevant change and reported "
            f"'{audit_result}'. Something drove it outside the filter; treat it "
            f"as a real failure rather than assuming the filter was wrong."
        )

    if audit_result == "success":
        return True, "Runtime security passed."
    if audit_result == "skipped":
        return False, (
            "The runtime audit was skipped even though the change touches "
            "runtime-relevant paths. A gate that did not run is not a gate that "
            "passed -- check whether a dependency was cancelled or the reusable "
            "workflow failed to load."
        )
    return False, f"Runtime security failed: {audit_result}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relevant", required=True, choices=("true", "false"))
    parser.add_argument("--event", required=True)
    parser.add_argument("--audit-result", required=True, default="")
    args = parser.parse_args(argv)

    passed, reason = decide(
        relevant=args.relevant == "true",
        event=args.event,
        audit_result=args.audit_result,
    )
    print(reason)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

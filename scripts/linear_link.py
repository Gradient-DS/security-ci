"""Fail a pull request whose description does not link a Linear ticket.

Reads the `pull_request` event from GITHUB_EVENT_PATH. A link is a magic word
followed by a GRA ticket id, e.g. `Fixes GRA-123` or `Part of GRA-123`.
"""
from __future__ import annotations

import json
import os
import re
import sys

LINK = re.compile(
    r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|completes?|part\s+of|refs?|related\s+to)\s*:?\s+GRA-\d+\b",
    re.IGNORECASE,
)
# Template examples sit in HTML comments; they must not count as a link.
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
PROMOTIONS = {("dev", "test"), ("test", "main")}
ESCAPE_LABEL = "no-ticket"


def verdict(pr: dict) -> tuple[bool, str]:
    """Return (passes, reason) for one pull_request payload."""
    user = pr.get("user") or {}
    if user.get("type") == "Bot" or str(user.get("login", "")).endswith("[bot]"):
        return True, f"bot pull request ({user.get('login')}): no ticket needed"
    if (pr["head"]["ref"], pr["base"]["ref"]) in PROMOTIONS:
        return True, f"promotion {pr['head']['ref']} -> {pr['base']['ref']}: no ticket needed"
    if any(label.get("name") == ESCAPE_LABEL for label in pr.get("labels") or []):
        return True, f"labelled {ESCAPE_LABEL}"
    match = LINK.search(COMMENT.sub("", pr.get("body") or ""))
    if match:
        return True, f"linked: {match.group(0)}"
    return False, (
        "No Linear ticket in the PR description. Add `Fixes GRA-123` (this PR completes it) "
        f"or `Part of GRA-123` (more PRs follow) under ## Linear, or label the PR {ESCAPE_LABEL}."
    )


def main() -> int:
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        event = json.load(fh)
    passes, reason = verdict(event["pull_request"])
    print(reason if passes else f"::error title=Linear link missing::{reason}")
    return 0 if passes else 1


if __name__ == "__main__":
    sys.exit(main())

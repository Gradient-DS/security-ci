"""linear-link passes a PR only with a magic-word GRA link, or as a listed exemption."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import linear_link as ll

ROOT = Path(__file__).resolve().parents[1]


def _pr(body: str | None = "", *, head: str = "fix/thing", base: str = "dev",
        login: str = "octo", user_type: str = "User", labels: tuple[str, ...] = ()) -> dict:
    return {
        "body": body,
        "head": {"ref": head},
        "base": {"ref": base},
        "user": {"login": login, "type": user_type},
        "labels": [{"name": name} for name in labels],
    }


@pytest.mark.parametrize("body", [
    "## Linear\n\nFixes GRA-123",
    "fixes GRA-1",
    "Closes GRA-9, GRA-10",
    "Resolved: GRA-42",
    "Part of GRA-491",
    "part  of GRA-491 and Fixes GRA-474",
    "Refs GRA-7",
    "Related to GRA-7",
])
def test_magic_word_link_passes(body: str) -> None:
    assert ll.verdict(_pr(body))[0]


@pytest.mark.parametrize("body", [
    None,
    "",
    "GRA-123",
    "Fixes #12",
    "Fixes GRA-",
    "Fixes ABC-123",
    "prefixes GRA-123",
    "## Linear\n\nFixes GRA-",
    "## Linear\n\n<!-- Fixes GRA-123 when this PR completes the ticket -->",
])
def test_missing_link_fails(body: str | None) -> None:
    passes, reason = ll.verdict(_pr(body))
    assert not passes
    assert "no-ticket" in reason


@pytest.mark.parametrize("pr", [
    _pr(login="dependabot[bot]", user_type="Bot"),
    _pr(login="renovate[bot]"),
    _pr(head="dev", base="test"),
    _pr(head="test", base="main"),
    _pr(labels=("no-ticket",)),
])
def test_exemptions_pass(pr: dict) -> None:
    assert ll.verdict(pr)[0]


def test_github_flow_pr_into_main_needs_a_link() -> None:
    assert not ll.verdict(_pr(head="feat/x", base="main"))[0]


def test_main_reads_the_event_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                   capsys: pytest.CaptureFixture[str]) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": _pr("no link")}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert ll.main() == 1
    assert "::error" in capsys.readouterr().out


def test_action_runs_the_script_from_its_own_checkout() -> None:
    action = yaml.safe_load((ROOT / "actions/linear-link/action.yml").read_text())
    runs = [step["run"] for step in action["runs"]["steps"]]
    assert runs == ['python3 "$GITHUB_ACTION_PATH/../../scripts/linear_link.py"']
    assert (ROOT / "actions/linear-link/../../scripts/linear_link.py").resolve().is_file()

"""tested-tree trusts only records from same-repository pull_request runs.

On a public repository a fork PR runs its own copy of the workflow in the base
repository's context, so it can upload a `tested-tree-*` artifact for any tree.
`check` must reject such a record (and any record not made by a pull_request
run of the same workflow file), and `record` must not upload one.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from scripts import tested_tree as tt

REPO = "Gradient-DS/open-webui"
FORK = "mallory/open-webui"
WF = ".github/workflows/security.yml"
WF_REF = f"{REPO}/{WF}@refs/heads/dev"
SHA = "a" * 40
TREE = "b" * 40
NAME = f"tested-tree-security-{TREE}"
ROOT = Path(__file__).resolve().parents[1]


def _artifact(run_id: int = 1, *, name: str = NAME, expired: bool = False,
              repository_id: int | None = 10, head_repository_id: int | None = 10) -> dict:
    return {
        "name": name,
        "expired": expired,
        "workflow_run": {"id": run_id, "repository_id": repository_id,
                         "head_repository_id": head_repository_id},
    }


def _run(*, event: str = "pull_request", base: str = REPO, head: str | None = REPO,
         path: str = WF) -> dict:
    return {
        "event": event,
        "path": path,
        "repository": {"full_name": base},
        "head_repository": None if head is None else {"full_name": head},
    }


class FakeApi:
    def __init__(self, artifacts: list[dict], runs: dict[int, dict]):
        self.artifacts = artifacts
        self.runs = runs
        self.calls: list[str] = []

    def __call__(self, path: str):
        self.calls.append(path)
        if path == f"repos/{REPO}/git/commits/{SHA}":
            return {"tree": {"sha": TREE}}
        if path.startswith(f"repos/{REPO}/actions/artifacts?name={NAME}&"):
            return {"artifacts": self.artifacts}
        prefix = f"repos/{REPO}/actions/runs/"
        if path.startswith(prefix):
            run_id = int(path[len(prefix):])
            if run_id not in self.runs:
                raise tt.TestedTreeError(f"gh api {path} failed: HTTP 404")
            return self.runs[run_id]
        raise AssertionError(f"unexpected API call {path}")


def _check(api: FakeApi) -> dict[str, str]:
    return tt.check(api, repo=REPO, key="security", sha=SHA, workflow_ref=WF_REF,
                    server_url="https://github.com")


def test_same_repo_pull_request_record_is_a_hit():
    out = _check(FakeApi([_artifact(7)], {7: _run()}))
    assert out == {"hit": "true", "tree": TREE,
                   "run-url": f"https://github.com/{REPO}/actions/runs/7"}


@pytest.mark.parametrize("run", [
    _run(head=FORK),
    _run(head=None),
    _run(base=FORK, head=FORK),
    _run(event="push"),
    _run(event="pull_request_target"),
    _run(event="workflow_dispatch"),
    _run(event="schedule"),
    _run(path=".github/workflows/other.yml"),
    {},
], ids=["fork-head", "deleted-fork", "foreign-base", "push", "pull_request_target",
        "dispatch", "schedule", "other-workflow", "empty-run"])
def test_untrusted_run_is_a_miss(run):
    assert _check(FakeApi([_artifact(7)], {7: run}))["hit"] == "false"


@pytest.mark.parametrize("artifact", [
    _artifact(7, expired=True),
    _artifact(7, head_repository_id=99),
    _artifact(7, head_repository_id=None),
    _artifact(7, repository_id=None, head_repository_id=None),
    _artifact(7, name=NAME + "x"),
    {"name": NAME, "expired": False, "workflow_run": {}},
    {"name": NAME, "expired": False, "workflow_run": {"id": "7"}},
    {"name": NAME, "workflow_run": {"id": 7, "repository_id": 10, "head_repository_id": 10}},
], ids=["expired", "fork-head-id", "no-head-id", "no-ids", "other-name", "no-run",
        "string-run-id", "no-expired-flag"])
def test_untrusted_artifact_is_a_miss(artifact):
    assert _check(FakeApi([artifact], {7: _run()}))["hit"] == "false"


def test_forged_fork_record_does_not_hide_a_genuine_one():
    """A fork's record listed first must be skipped, not end the search."""
    api = FakeApi([_artifact(1), _artifact(2)], {1: _run(head=FORK), 2: _run()})
    out = _check(api)
    assert out["hit"] == "true" and out["run-url"].endswith("/runs/2")


def test_fork_head_id_mismatch_needs_no_run_lookup():
    api = FakeApi([_artifact(7, head_repository_id=99)], {7: _run()})
    assert _check(api)["hit"] == "false"
    assert not any("/actions/runs/" in c for c in api.calls)


def test_no_record_is_a_miss():
    assert _check(FakeApi([], {})) == {"hit": "false", "tree": TREE, "run-url": ""}


def test_run_lookup_error_fails_the_step():
    with pytest.raises(tt.TestedTreeError):
        _check(FakeApi([_artifact(7)], {}))


def test_malformed_listing_fails_the_step():
    api = FakeApi([], {})
    api.artifacts = None  # type: ignore[assignment]
    with pytest.raises(tt.TestedTreeError):
        _check(api)


def test_listing_is_paginated():
    pages = {1: [_artifact(1, expired=True)] * tt.PAGE_SIZE, 2: [_artifact(2)]}

    def api(path: str):
        if path.endswith(f"/git/commits/{SHA}"):
            return {"tree": {"sha": TREE}}
        if "/actions/artifacts?" in path:
            return {"artifacts": pages[int(path.rsplit("page=", 1)[1])]}
        return _run()

    assert _check(api)["run-url"].endswith("/runs/2")  # type: ignore[arg-type]


@pytest.mark.parametrize("key", ["", "a b", "x/y", "$(id)"])
def test_bad_key_fails(key):
    with pytest.raises(tt.TestedTreeError):
        tt.check(FakeApi([], {}), repo=REPO, key=key, sha=SHA, workflow_ref=WF_REF,
                 server_url="https://github.com")


def test_bad_tree_fails():
    with pytest.raises(tt.TestedTreeError):
        tt.check(lambda _p: {"tree": {"sha": "nope"}}, repo=REPO, key="k", sha=SHA,
                 workflow_ref=WF_REF, server_url="https://github.com")


def test_workflow_path():
    assert tt.workflow_path(WF_REF, REPO) == WF
    with pytest.raises(tt.TestedTreeError):
        tt.workflow_path(f"{FORK}/{WF}@refs/heads/dev", REPO)


PR_EVENT = {"pull_request": {"head": {"repo": {"full_name": REPO}},
                             "base": {"repo": {"full_name": REPO}}}}


def _record(tmp_path: Path, event_name: str, event: dict) -> dict[str, str]:
    return tt.record(FakeApi([], {}), repo=REPO, key="security", sha=SHA,
                     event_name=event_name, event=event,
                     record_file=tmp_path / "rec" / "tested-tree.txt", run_url="u")


def test_record_on_same_repo_pull_request(tmp_path):
    out = _record(tmp_path, "pull_request", PR_EVENT)
    assert out == {"recorded": "true", "tree": TREE, "name": NAME}
    assert f"tree={TREE}\n" in (tmp_path / "rec" / "tested-tree.txt").read_text()


def _fork_event() -> dict:
    event = copy.deepcopy(PR_EVENT)
    event["pull_request"]["head"]["repo"]["full_name"] = FORK
    return event


@pytest.mark.parametrize("event_name,event", [
    ("pull_request", _fork_event()),
    ("pull_request", {"pull_request": {"head": {"repo": None}, "base": {"repo": {"full_name": REPO}}}}),
    ("pull_request", {}),
    ("pull_request_target", PR_EVENT),
    ("push", {}),
], ids=["fork", "deleted-fork", "no-payload", "pull_request_target", "push"])
def test_record_refuses_anything_else(tmp_path, event_name, event):
    out = _record(tmp_path, event_name, event)
    assert out["recorded"] == "false"
    assert not (tmp_path / "rec").exists()


def _action(name: str) -> dict:
    return yaml.safe_load((ROOT / f"actions/tested-tree/{name}/action.yml").read_text())


@pytest.mark.parametrize("name", ["record", "check"])
def test_action_runs_this_script(name):
    steps = _action(name)["runs"]["steps"]
    runs = [s["run"] for s in steps if "run" in s]
    assert runs == [f'python3 "$GITHUB_ACTION_PATH/../../../scripts/tested_tree.py" {name}']
    assert (ROOT / "actions/tested-tree" / name / "../../../scripts/tested_tree.py").resolve().is_file()


def test_record_uploads_only_when_recorded():
    uploads = [s for s in _action("record")["runs"]["steps"]
               if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    assert len(uploads) == 1
    assert uploads[0].get("if") == "steps.tree.outputs.recorded == 'true'"


def _env(monkeypatch, tmp_path: Path, event_name: str, event: dict) -> Path:
    import json
    out = tmp_path / "out"
    out.write_text("")
    (tmp_path / "event.json").write_text(json.dumps(event))
    for k, v in {"GITHUB_REPOSITORY": REPO, "GITHUB_OUTPUT": str(out),
                 "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
                 "GITHUB_EVENT_PATH": str(tmp_path / "event.json"),
                 "GITHUB_EVENT_NAME": event_name, "GITHUB_SERVER_URL": "https://github.com",
                 "GITHUB_RUN_ID": "5", "GITHUB_RUN_ATTEMPT": "1", "KEY": "security", "SHA": SHA,
                 "WORKFLOW_REF": WF_REF, "RECORD_DIR": str(tmp_path / "rec")}.items():
        monkeypatch.setenv(k, v)
    return out


def test_main_check_writes_outputs(monkeypatch, tmp_path):
    out = _env(monkeypatch, tmp_path, "push", {})
    monkeypatch.setattr(tt, "gh_api", FakeApi([_artifact(7)], {7: _run(head=FORK)}))
    assert tt.main(["check"]) == 0
    assert "hit=false\n" in out.read_text()


def test_main_check_api_error_is_red(monkeypatch, tmp_path):
    out = _env(monkeypatch, tmp_path, "push", {})
    monkeypatch.setattr(tt, "gh_api", FakeApi([_artifact(7)], {}))
    assert tt.main(["check"]) == 1
    assert out.read_text() == ""


def test_main_record_fork_writes_recorded_false(monkeypatch, tmp_path):
    out = _env(monkeypatch, tmp_path, "pull_request", _fork_event())
    monkeypatch.setattr(tt, "gh_api", FakeApi([], {}))
    assert tt.main(["record"]) == 0
    assert "recorded=false\n" in out.read_text()

"""Record and check tested-tree artifacts for actions/tested-tree.

`record` uploads a marker only from a same-repository pull_request run; `check`
trusts a marker only if the run that uploaded it was such a run, of the same
workflow file. Anything unexpected in a record is a miss; an API error is a
failure, never a silent miss.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

Api = Callable[[str], Any]

KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")
TREE_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
PAGE_SIZE = 100


class TestedTreeError(Exception):
    """A failure the step must report red, not answer as a miss."""


def gh_api(path: str) -> Any:
    proc = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if proc.returncode != 0:
        raise TestedTreeError(f"gh api {path} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def check_key(key: str) -> None:
    if not KEY_RE.match(key):
        raise TestedTreeError(f"workflow-key must match [A-Za-z0-9._-]+, got '{key}'")


def resolve_tree(api: Api, repo: str, sha: str) -> str:
    tree = (api(f"repos/{repo}/git/commits/{sha}").get("tree") or {}).get("sha")
    if not isinstance(tree, str) or not TREE_RE.match(tree):
        raise TestedTreeError(f"no tree for commit {sha}")
    return tree


def workflow_path(workflow_ref: str, repo: str) -> str:
    """`owner/repo/.github/workflows/x.yml@ref` -> `.github/workflows/x.yml`."""
    prefix = f"{repo}/"
    if not workflow_ref.startswith(prefix) or "@" not in workflow_ref:
        raise TestedTreeError(f"unexpected github.workflow_ref '{workflow_ref}'")
    return workflow_ref[len(prefix):].rsplit("@", 1)[0]


def same_repo_pull_request(event_name: str, event: dict, repo: str) -> tuple[bool, str]:
    """Whether this run is a pull_request from a branch of `repo` itself."""
    if event_name != "pull_request":
        return False, f"event is {event_name}, not pull_request"
    pr = event.get("pull_request") or {}
    head = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
    base = ((pr.get("base") or {}).get("repo") or {}).get("full_name")
    if head != repo or base != repo:
        return False, f"pull request from {head} into {base}, not a branch of {repo}"
    return True, "same-repository pull request"


def record(api: Api, *, repo: str, key: str, sha: str, event_name: str, event: dict,
           record_file: Path, run_url: str) -> dict[str, str]:
    check_key(key)
    ok, why = same_repo_pull_request(event_name, event, repo)
    if not ok:
        # `check` would never trust it, and on a public repository a fork
        # run's record is exactly what must not exist.
        print(f"::notice::Not recording a tested tree: {why}")
        return {"recorded": "false", "tree": "", "name": ""}
    tree = resolve_tree(api, repo, sha)
    record_file.parent.mkdir(parents=True, exist_ok=True)
    record_file.write_text(f"tree={tree}\nsha={sha}\nevent={event_name}\nrun={run_url}\n")
    name = f"tested-tree-{key}-{tree}"
    print(f"Recording tree {tree} of {sha} as tested for '{key}'")
    return {"recorded": "true", "tree": tree, "name": name}


def list_artifacts(api: Api, repo: str, name: str) -> list[dict]:
    artifacts: list[dict] = []
    page = 1
    while True:
        body = api(f"repos/{repo}/actions/artifacts?name={name}&per_page={PAGE_SIZE}&page={page}")
        batch = body.get("artifacts")
        if not isinstance(batch, list):
            raise TestedTreeError(f"malformed artifact listing for {name}")
        artifacts.extend(batch)
        if len(batch) < PAGE_SIZE:
            return artifacts
        page += 1


def trust(api: Api, repo: str, artifact: dict, wf_path: str) -> tuple[bool, str]:
    """Whether `artifact` was uploaded by a same-repository pull_request run of `wf_path`."""
    if artifact.get("expired") is not False:
        return False, "expired"
    wr = artifact.get("workflow_run") or {}
    run_id = wr.get("id")
    if not isinstance(run_id, int) or isinstance(run_id, bool):
        return False, "no workflow_run id"
    if wr.get("repository_id") is None or wr.get("head_repository_id") != wr.get("repository_id"):
        return False, f"run {run_id}: head repository is not this repository"
    run = api(f"repos/{repo}/actions/runs/{run_id}")
    event = run.get("event")
    if event != "pull_request":
        return False, f"run {run_id}: event {event}, not pull_request"
    base = (run.get("repository") or {}).get("full_name")
    head = (run.get("head_repository") or {}).get("full_name")
    if base != repo or head != repo:
        return False, f"run {run_id}: from {head} into {base}, not a branch of {repo}"
    if run.get("path") != wf_path:
        return False, f"run {run_id}: recorded by {run.get('path')}, not {wf_path}"
    return True, f"run {run_id}"


def check(api: Api, *, repo: str, key: str, sha: str, workflow_ref: str,
          server_url: str) -> dict[str, str]:
    check_key(key)
    wf_path = workflow_path(workflow_ref, repo)
    tree = resolve_tree(api, repo, sha)
    name = f"tested-tree-{key}-{tree}"
    for artifact in list_artifacts(api, repo, name):
        if artifact.get("name") != name:
            print(f"Ignoring artifact {artifact.get('name')!r}: not {name}")
            continue
        ok, why = trust(api, repo, artifact, wf_path)
        if ok:
            run_url = f"{server_url}/{repo}/actions/runs/{artifact['workflow_run']['id']}"
            return {"hit": "true", "tree": tree, "run-url": run_url}
        print(f"Ignoring {name}: {why}")
    return {"hit": "false", "tree": tree, "run-url": ""}


def _write_outputs(outputs: dict[str, str]) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
        for k, v in outputs.items():
            fh.write(f"{k}={v}\n")


def main(argv: list[str]) -> int:
    env = os.environ
    repo = env["GITHUB_REPOSITORY"]
    try:
        if argv == ["record"]:
            event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
            run_url = (f"{env['GITHUB_SERVER_URL']}/{repo}/actions/runs/"
                       f"{env['GITHUB_RUN_ID']}/attempts/{env['GITHUB_RUN_ATTEMPT']}")
            out = record(gh_api, repo=repo, key=env["KEY"], sha=env["SHA"],
                         event_name=env["GITHUB_EVENT_NAME"], event=event,
                         record_file=Path(env["RECORD_DIR"]) / "tested-tree.txt", run_url=run_url)
        elif argv == ["check"]:
            out = check(gh_api, repo=repo, key=env["KEY"], sha=env["SHA"],
                        workflow_ref=env["WORKFLOW_REF"], server_url=env["GITHUB_SERVER_URL"])
            if out["hit"] == "true":
                print(f"Tree {out['tree']} was tested for '{env['KEY']}' by {out['run-url']}")
                with open(env["GITHUB_STEP_SUMMARY"], "a") as fh:
                    fh.write(f"Tree `{out['tree']}` was already tested for `{env['KEY']}` by {out['run-url']}\n")
            else:
                print(f"No trusted record of tree {out['tree']} for '{env['KEY']}'; running everything")
        else:
            print("usage: tested_tree.py record|check", file=sys.stderr)
            return 2
    except TestedTreeError as exc:
        print(f"::error::{exc}")
        return 1
    _write_outputs(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

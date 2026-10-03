"""runtime-security's optional cached build: off by default, exact when on."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/runtime-security.yml"


def _wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> list[dict]:
    return _wf()["jobs"]["runtime-audit"]["steps"]


def _by_name(prefix: str) -> list[dict]:
    return [s for s in _steps() if str(s.get("name", "")).startswith(prefix)]


def test_cache_is_off_by_default():
    inputs = _wf()[True]["workflow_call"]["inputs"]
    assert inputs["cache-scope"]["default"] == ""
    assert inputs["cache-from"]["default"] == ""
    plan = [s for s in _steps() if s.get("id") == "bake"][0]
    assert plan["if"] == "inputs.cache-scope != '' || inputs.cache-from != ''"


def test_default_path_is_the_v6_bring_up():
    plain, prebuilt = _by_name("Bring up the egress-denied stack")
    assert plain["if"] == "steps.bake.outputs.targets == ''"
    assert plain["run"] == 'docker compose -f "$COMPOSE_FILE_PATH" up -d --build'
    assert plain["env"]["GH_TOKEN"] == "${{ steps.tooling-token.outputs.token }}"
    assert prebuilt["if"] == "steps.bake.outputs.targets != ''"
    assert prebuilt["run"] == 'docker compose -f "$COMPOSE_FILE_PATH" up -d --no-build'


def test_every_cached_build_step_is_gated():
    for step in _steps():
        uses = str(step.get("uses", ""))
        if uses.startswith(("docker/setup-buildx-action", "docker/bake-action", "docker/login-action")):
            assert "steps.bake.outputs.targets != ''" in step["if"], uses


def test_bake_loads_into_docker_from_the_workspace():
    bake = [s for s in _steps() if str(s.get("uses", "")).startswith("docker/bake-action")][0]
    assert bake["with"]["load"] is True
    assert bake["with"]["source"] == "."
    assert bake["env"]["GH_TOKEN"] == "${{ steps.tooling-token.outputs.token }}"


COMPOSE_CONFIG = {
    "name": "proj",
    "services": {
        "app": {"build": {"context": "."}},
        "named": {"build": {"context": "x"}, "image": "ghcr.io/o/named:ci"},
        "db": {"image": "postgres:15-alpine"},
    },
}


def _plan(tmp_path: Path, scope: str, write: str, cache_from: str, config: dict) -> tuple[int, dict, str]:
    script = [s for s in _steps() if s.get("id") == "bake"][0]["run"]
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (tmp_path / "cfg.json").write_text(json.dumps(config))
    fake = bindir / "docker"
    fake.write_text(f"#!/bin/sh\ncat '{tmp_path / 'cfg.json'}'\n")
    fake.chmod(0o755)
    out = tmp_path / "out"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "RUNNER_TEMP": str(tmp_path),
           "GITHUB_OUTPUT": str(out), "COMPOSE_FILE_PATH": "c.yml", "CACHE_SCOPE": scope,
           "CACHE_WRITE": write, "CACHE_FROM": cache_from, "OVERRIDE": str(tmp_path / "o.json")}
    proc = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    override = json.loads((tmp_path / "o.json").read_text()) if proc.returncode == 0 else {}
    return proc.returncode, override, out.read_text() if out.exists() else ""


def test_plan_scopes_cache_per_service_and_tags_what_compose_expects(tmp_path):
    rc, override, out = _plan(tmp_path, "rt", "true", "type=registry,ref=r:c\n", COMPOSE_CONFIG)
    assert rc == 0
    assert out == "targets=app,named\n"
    assert override == {"target": {
        "app": {"tags": ["proj-app"],
                "cache-from": ["type=gha,scope=rt-app", "type=registry,ref=r:c"],
                "cache-to": ["type=gha,scope=rt-app,mode=max"]},
        "named": {"tags": ["ghcr.io/o/named:ci"],
                  "cache-from": ["type=gha,scope=rt-named", "type=registry,ref=r:c"],
                  "cache-to": ["type=gha,scope=rt-named,mode=max"]},
    }}


@pytest.mark.parametrize("scope,write", [("rt", "false"), ("", "true")])
def test_plan_without_write_or_scope_writes_nothing(tmp_path, scope, write):
    rc, override, _ = _plan(tmp_path, scope, write, "type=registry,ref=r:c", COMPOSE_CONFIG)
    assert rc == 0
    assert all(t["cache-to"] == [] for t in override["target"].values())


def test_plan_fails_when_nothing_is_built(tmp_path):
    rc, _, out = _plan(tmp_path, "rt", "true", "", {"name": "p", "services": {"db": {"image": "x"}}})
    assert rc != 0 and out == ""


def test_no_checkout_leaves_a_token_in_the_build_context():
    checkouts = [s for s in _steps() if str(s.get("uses", "")).startswith("actions/checkout")]
    assert len(checkouts) == 2
    assert all(s["with"]["persist-credentials"] is False for s in checkouts)

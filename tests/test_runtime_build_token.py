"""runtime-security's BUILD_TOKEN: optional, and only ever seen by the image build."""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/runtime-security.yml"
REF = "${{ secrets.BUILD_TOKEN }}"


def _wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> list[dict]:
    return _wf()["jobs"]["runtime-audit"]["steps"]


def _build_steps(steps: list[dict] | None = None) -> list[dict]:
    steps = _steps() if steps is None else steps
    bake = [s for s in steps if str(s.get("uses", "")).startswith("docker/bake-action")]
    plain = [s for s in steps if s.get("run") == 'docker compose -f "$COMPOSE_FILE_PATH" up -d --build']
    assert len(bake) == 1 and len(plain) == 1
    return bake + plain


def test_build_token_is_an_optional_secret():
    # Optional, so every existing caller keeps working without passing it.
    secret = _wf()[True]["workflow_call"]["secrets"]["BUILD_TOKEN"]
    assert secret["required"] is False


def test_both_build_paths_get_the_build_token():
    for step in _build_steps():
        assert step["env"]["BUILD_TOKEN"] == REF, step.get("name")


def test_build_token_reaches_no_other_step():
    # The traffic driver runs caller-controlled commands next to the guarded
    # containers, and Falco is a privileged container: neither may see it.
    steps = _steps()
    build = [id(s) for s in _build_steps(steps)]
    for step in steps:
        if id(step) in build:
            continue
        assert "BUILD_TOKEN" not in yaml.safe_dump(step), step.get("name") or step.get("uses")


def test_build_token_is_not_exported_job_or_workflow_wide():
    wf = _wf()
    assert "BUILD_TOKEN" not in (wf.get("env") or {})
    assert "BUILD_TOKEN" not in (wf["jobs"]["runtime-audit"].get("env") or {})


def test_build_token_is_never_passed_as_a_build_arg():
    # A build arg is recorded in the image history; a BuildKit secret is not.
    for step in _build_steps():
        assert "BUILD_TOKEN" not in yaml.safe_dump(step.get("with") or {})
        assert "--build-arg" not in str(step.get("run", ""))

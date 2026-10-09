from itertools import product
import re

import pytest

from tests.test_runtime_build_cache import _wf


def _condition(expression, *, ghcr_login, targets="", cache_from=""):
    expression = expression.strip().removeprefix("${{").removesuffix("}}")
    for context, value in {
        "inputs.ghcr-login": ghcr_login,
        "inputs.cache-from": cache_from,
        "steps.bake.outputs.targets": targets,
    }.items():
        expression = expression.replace(context, repr(value))
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", "not ", expression)
    return eval(expression.strip(), {"__builtins__": {}},
                {"contains": lambda source, part: part.lower() in source.lower()})


def test_ghcr_is_opt_in_and_does_not_raise_callers_permission_floor():
    workflow = _wf()
    setting = workflow[True]["workflow_call"]["inputs"]["ghcr-login"]
    assert setting["type"] == "boolean"
    assert setting["default"] is False
    assert setting["required"] is False
    assert "permissions" not in workflow
    jobs = workflow["jobs"]
    assert set(jobs) == {"runtime-audit", "runtime-audit-ghcr"}
    assert jobs["runtime-audit"]["permissions"] == {"contents": "read"}
    # Even a skipped job's explicit packages request can reject legacy callers.
    assert "permissions" not in jobs["runtime-audit-ghcr"]


@pytest.mark.parametrize("enabled", [False, True])
def test_exactly_one_audit_runs_with_the_requested_permission_policy(enabled):
    jobs = _wf()["jobs"]
    selected = [name for name, job in jobs.items()
                if _condition(job["if"], ghcr_login=enabled)]
    assert selected == ["runtime-audit-ghcr" if enabled else "runtime-audit"]


def test_audit_variants_share_all_steps_and_execution_settings():
    jobs = _wf()["jobs"]
    plain, ghcr = jobs["runtime-audit"], jobs["runtime-audit-ghcr"]
    # Identity checks require YAML aliases, preventing copy-paste drift.
    assert plain["steps"] is ghcr["steps"]
    assert plain["env"] is ghcr["env"]
    for key in ("runs-on", "timeout-minutes"):
        assert plain[key] == ghcr[key]


@pytest.mark.parametrize("enabled,targets,cache_from", list(product(
    [False, True], ["", "app"],
    ["", "type=registry,ref=ghcr.io/org/cache:dev", "type=registry,ref=registry.example/cache:dev"],
)))
def test_login_covers_uncached_and_cached_stacks_and_preserves_legacy_trigger(enabled, targets, cache_from):
    steps = _wf()["jobs"]["runtime-audit"]["steps"]
    login, = [step for step in steps if step.get("uses", "").startswith("docker/login-action@")]
    assert _condition(login["if"], ghcr_login=enabled, targets=targets, cache_from=cache_from) == (
        enabled or (bool(targets) and "ghcr.io" in cache_from)
    )
    assert login["with"] == {
        "registry": "ghcr.io",
        "username": "${{ github.actor }}",
        "password": "${{ github.token }}",
    }


def test_login_precedes_every_build_or_pull_path():
    steps = _wf()["jobs"]["runtime-audit"]["steps"]
    login_index, = [i for i, step in enumerate(steps)
                   if step.get("uses", "").startswith("docker/login-action@")]
    pullers = [i for i, step in enumerate(steps)
               if step.get("uses", "").startswith(("docker/setup-buildx-action@", "docker/bake-action@"))
               or any(command in step.get("run", "") for command in (
                   " up -d --build", " up -d --no-build", "docker run ", "docker pull ",
               ))]
    assert len(pullers) == 6
    assert all(login_index < i for i in pullers)

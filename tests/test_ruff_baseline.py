"""The ruff baseline check: what passes, what fails, and which configs it finds."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import ruff_baseline as rb

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "pre-commit/ruff-baseline.toml"
WORKFLOW = ROOT / ".github/workflows/pre-commit.yml"

GOOD = """
line-length = 120

[lint]
select = ["E", "F", "W", "I", "UP", "B", "SIM", "D"]

[lint.pydocstyle]
convention = "google"
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _problems(path: Path) -> list[str]:
    return rb.check(path).problems


def test_template_meets_its_own_baseline():
    assert _problems(TEMPLATE) == []


def test_this_repo_meets_the_baseline():
    assert rb.main([str(ROOT)]) == 0


def test_minimal_good_config_passes(tmp_path):
    assert _problems(_write(tmp_path / "ruff.toml", GOOD)) == []


def test_pyproject_table_is_read(tmp_path):
    text = GOOD.replace("[lint", "[tool.ruff.lint").replace("line-length", "[tool.ruff]\nline-length")
    assert _problems(_write(tmp_path / "pyproject.toml", text)) == []


def test_default_line_length_fails(tmp_path):
    (problem,) = _problems(_write(tmp_path / "ruff.toml", GOOD.replace("line-length = 120", "")))
    assert "line-length is 88" in problem


def test_missing_family_fails(tmp_path):
    cfg = _write(tmp_path / "ruff.toml", GOOD.replace('"SIM", "D"', '"D"'))
    assert _problems(cfg) == ["lint.select is missing baseline rule families: SIM"]


def test_partial_family_does_not_count(tmp_path):
    cfg = _write(tmp_path / "ruff.toml", GOOD.replace('"E",', '"E4", "E7",'))
    assert _problems(cfg) == ["lint.select is missing baseline rule families: E"]


def test_extra_rules_and_single_rule_ignores_pass(tmp_path):
    text = GOOD.replace("select = [", 'ignore = ["E501", "D417"]\nextend-select = ["S", "RUF"]\nselect = [')
    assert _problems(_write(tmp_path / "ruff.toml", text)) == []


def test_ignoring_a_whole_family_fails(tmp_path):
    cfg = _write(tmp_path / "ruff.toml", GOOD.replace("select = [", 'ignore = ["D"]\nselect = ['))
    assert _problems(cfg) == ["lint.select is missing baseline rule families: D"]


def test_select_all_passes(tmp_path):
    cfg = _write(tmp_path / "ruff.toml", GOOD.replace('"E", "F", "W", "I", "UP", "B", "SIM", "D"', '"ALL"'))
    assert _problems(cfg) == []


def test_legacy_top_level_select_is_read(tmp_path):
    text = GOOD.replace("[lint]\n", "")
    assert _problems(_write(tmp_path / "ruff.toml", text)) == []


def test_wrong_convention_fails(tmp_path):
    (problem,) = _problems(_write(tmp_path / "ruff.toml", GOOD.replace("google", "numpy")))
    assert "convention is 'numpy'" in problem


def test_missing_convention_fails(tmp_path):
    (problem,) = _problems(_write(tmp_path / "ruff.toml", GOOD.split("[lint.pydocstyle]")[0]))
    assert "convention is None" in problem


def test_single_quotes_fail(tmp_path):
    (problem,) = _problems(_write(tmp_path / "ruff.toml", GOOD + '\n[format]\nquote-style = "single"\n'))
    assert "quote-style is 'single'" in problem


def test_extend_inherits_and_overrides(tmp_path):
    _write(tmp_path / "base.toml", GOOD)
    child = _write(tmp_path / "pkg/ruff.toml", 'extend = "../base.toml"\n[lint]\nextend-select = ["S"]\n')
    assert _problems(child) == []
    child.write_text('extend = "../base.toml"\nline-length = 100\n')
    assert _problems(child) == ["line-length is 100, the baseline is 120"]


def test_child_select_replaces_the_parents(tmp_path):
    _write(tmp_path / "base.toml", GOOD)
    child = _write(tmp_path / "ruff.toml", 'extend = "base.toml"\n[lint]\nselect = ["E", "F"]\n')
    assert _problems(child) == ["lint.select is missing baseline rule families: W, I, UP, B, SIM, D"]


def test_child_select_drops_the_parents_ignores(tmp_path):
    _write(tmp_path / "base.toml", GOOD.replace("select = [", 'ignore = ["D"]\nselect = ['))
    child = _write(tmp_path / "ruff.toml", 'extend = "base.toml"\n[lint]\nselect = ' + GOOD.split("select = ")[1])
    assert _problems(child) == []


def test_broken_extend_is_reported(tmp_path):
    (problem,) = _problems(_write(tmp_path / "ruff.toml", 'extend = "missing.toml"\n'))
    assert "does not exist" in problem


def test_extend_cycle_is_reported(tmp_path):
    _write(tmp_path / "a.toml", 'extend = "b.toml"\n')
    _write(tmp_path / "b.toml", 'extend = "a.toml"\n')
    (problem,) = _problems(tmp_path / "a.toml")
    assert "cycle" in problem


def test_discover_prefers_ruff_toml_and_skips_pyproject_without_ruff(tmp_path):
    files = [
        _write(tmp_path / "pyproject.toml", "[tool.ruff]\nline-length = 120\n"),
        _write(tmp_path / "ruff.toml", GOOD),
        _write(tmp_path / "lib/pyproject.toml", "[project]\nname = 'x'\n"),
        _write(tmp_path / "svc/.ruff.toml", GOOD),
        _write(tmp_path / "svc/pyproject.toml", "[tool.ruff]\n"),
    ]
    assert rb.discover(files) == [tmp_path / "ruff.toml", tmp_path / "svc/.ruff.toml"]


def _git_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name, text in files.items():
        _write(tmp_path / name, text)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    return tmp_path


def test_main_ignores_untracked_configs(tmp_path):
    repo = _git_repo(tmp_path, {"ruff.toml": GOOD, "a.py": "x = 1\n"})
    _write(repo / ".security-tooling/ruff.toml", "line-length = 80\n")
    assert rb.main([str(repo)]) == 0


def test_main_fails_on_a_bad_config(tmp_path, capsys):
    repo = _git_repo(tmp_path, {"ruff.toml": GOOD, "sub/ruff.toml": "line-length = 80\n"})
    assert rb.main([str(repo)]) == 1
    assert "sub/ruff.toml: line-length is 80" in capsys.readouterr().out


def test_main_fails_on_python_without_config(tmp_path):
    assert rb.main([str(_git_repo(tmp_path, {"a.py": "x = 1\n"}))]) == 1


def test_main_passes_a_repo_without_python(tmp_path):
    assert rb.main([str(_git_repo(tmp_path, {"index.js": "1;\n"}))]) == 0


# ── The workflow ─────────────────────────────────────────────────────────


def _wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> list[dict]:
    return _wf()["jobs"]["pre-commit"]["steps"]


def _step(step_id: str) -> dict:
    (step,) = [s for s in _steps() if s.get("id") == step_id]
    return step


def test_job_name_gives_the_documented_check_name():
    # Callers name their job `pre-commit`, so the check is `pre-commit / pre-commit`.
    assert _wf()["jobs"]["pre-commit"]["name"] == "pre-commit"


def test_baseline_opt_outs():
    inputs = _wf()[True]["workflow_call"]["inputs"]
    assert inputs["skip-baseline"]["default"] is False
    flag = _wf()["jobs"]["pre-commit"]["env"]["BASELINE"]
    assert "!inputs.skip-baseline" in flag
    assert "github.event.repository.custom_properties.source != 'upstream-mirror'" in flag
    for step in [_step("baseline"), _step("tooling-ref"), _step("tooling-token")]:
        assert "env.BASELINE == 'true'" in step["if"]


@pytest.mark.parametrize("step_id", ["node", "baseline"])
def test_inputs_reach_the_shell_through_env_only(step_id):
    assert "${{" not in _step(step_id)["run"]


def test_templates_pin_the_same_versions():
    revs: dict[str, set[str]] = {}
    for template in sorted((ROOT / "pre-commit").glob("*.yaml")):
        for repo in yaml.safe_load(template.read_text())["repos"]:
            revs.setdefault(repo["repo"], set()).add(repo["rev"])
    assert {repo: rev for repo, rev in revs.items() if len(rev) > 1} == {}
    own = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())["repos"]
    for repo in own:
        if repo["repo"] in revs:
            assert {repo["rev"]} == revs[repo["repo"]], repo["repo"]

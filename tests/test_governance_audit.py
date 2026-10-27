import copy
import datetime as dt
import json

import pytest
import yaml

from scripts.governance import ROOT, checks_ruleset
from scripts.governance_audit import (
    MAX_PIN_AGE_DAYS, Repo, audit_repo, check_branch_model, check_drafts, check_exceptions, check_gate,
    check_org_rulesets, check_production_rules, check_properties, check_security_ci, issue_title,
    needs_draft_check, never_on_pr, skips_drafts, summary,
)

TODAY = dt.date(2026, 10, 27)
PIN = "a" * 40
GOOD_WF = f"""
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
jobs:
  security:
    if: github.event.pull_request.draft != true
    uses: Gradient-DS/security-ci/.github/workflows/security-source.yml@{PIN} # v10
"""


def wf(text):
    return yaml.safe_load(text)


def job(text):
    return yaml.safe_load(text)


# --- draft classification ---

def test_root_job_needs_the_draft_check():
    assert needs_draft_check({"runs-on": "x"})
    assert not skips_drafts({"runs-on": "x"})


def test_needs_only_job_inherits_the_skip():
    assert not needs_draft_check({"needs": "build"})
    assert not needs_draft_check({"needs": ["a"], "if": "needs.a.result == 'success'"})


def test_status_function_gate_runs_after_skipped_needs():
    assert needs_draft_check({"needs": ["a", "b"], "if": "${{ always() }}"})
    assert needs_draft_check({"needs": "a", "if": "failure() && github.ref == 'refs/heads/main'"})


def test_non_pr_only_if_is_exempt():
    assert never_on_pr("github.event_name == 'push'")
    assert never_on_pr("(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && always()")
    assert not never_on_pr("github.event_name == 'push' || github.event_name == 'pull_request'")
    assert not needs_draft_check({"if": "github.event_name == 'schedule'"})
    assert needs_draft_check({"if": "github.event_name != 'schedule'"})


def test_folded_multiline_if():
    j = job("""
needs: [a]
if: >-
  ${{ always() &&
      (needs.a.result == 'success' || needs.a.result == 'skipped') &&
      github.event.pull_request.draft != true }}
""")
    assert needs_draft_check(j)
    assert skips_drafts(j)


def test_draft_guard_must_be_a_top_level_conjunct():
    assert skips_drafts({"if": "${{ (github.event_name == 'push' || x) && github.event.pull_request.draft != true }}"})
    assert skips_drafts({"if": "!github.event.pull_request.draft"})
    assert not skips_drafts({"if": "github.event.pull_request.draft != true || always()"})


def test_check_drafts_passes_a_compliant_workflow():
    assert check_drafts("ci.yml", wf(GOOD_WF)) == []


def test_check_drafts_flags_missing_ready_for_review_and_unguarded_job():
    findings = check_drafts("ci.yml", wf("on: [push, pull_request]\njobs:\n  test:\n    runs-on: x\n"))
    assert len(findings) == 2
    assert "ready_for_review" in findings[0] and "`test`" in findings[1]


def test_check_drafts_skips_closed_only_and_non_pr_workflows():
    assert check_drafts("c.yml", wf("on:\n  pull_request:\n    types: [closed]\njobs:\n  a:\n    runs-on: x\n")) == []
    assert check_drafts("p.yml", wf("on: push\njobs:\n  a:\n    runs-on: x\n")) == []


# --- per-repo checks ---

def test_properties():
    assert check_properties(Repo("r", "development", "gitflow")) == []
    assert len(check_properties(Repo("r", None, "trunk"))) == 2


@pytest.mark.parametrize("repo, n", [
    (Repo("r", branch_model="gitflow", default_branch="dev", branches={"test": True, "main": True}), 0),
    (Repo("r", branch_model="gitflow", default_branch="main", branches={"main": True}), 2),
    (Repo("r", branch_model="github-flow", default_branch="main", branches={"main": True}), 0),
    (Repo("r", branch_model="github-flow", default_branch="dev", branches={"test": True}), 2),
])
def test_branch_model(repo, n):
    assert len(check_branch_model(repo)) == n


def test_security_ci_pinned_and_fresh():
    workflows = {"s.yml": wf(GOOD_WF)}
    assert check_security_ci(workflows, {PIN: TODAY - dt.timedelta(days=MAX_PIN_AGE_DAYS)}, TODAY) == []
    stale = check_security_ci(workflows, {PIN: TODAY - dt.timedelta(days=MAX_PIN_AGE_DAYS + 1)}, TODAY)
    assert "older than" in stale[0]
    assert "not a commit" in check_security_ci(workflows, {PIN: None}, TODAY)[0]


def test_security_ci_missing_or_unpinned():
    assert "no workflow" in check_security_ci({}, {}, TODAY)[0]
    unpinned = {"s.yml": wf(GOOD_WF.replace(PIN, "main"))}
    assert "pin it" in check_security_ci(unpinned, {}, TODAY)[0]


def test_gate():
    ok = {"status": "completed", "conclusion": "success", "completed_at": "2026-10-27T02:00:00Z"}
    bad = {"status": "completed", "conclusion": "failure", "completed_at": "2026-10-27T03:00:00Z"}
    assert check_gate(Repo("r", gate=[ok])) == []
    assert check_gate(Repo("r", gate=[{"status": "in_progress"}])) == []
    assert "`failure`" in check_gate(Repo("r", gate=[ok, bad]))[0]
    assert "no `gate`" in check_gate(Repo("r", gate=[]))[0]


EXC = """exceptions:
  - id: CVE-2026-0001
    package: foo
    scanner: trivy
    reason: no fix
    replacement_considered: none
    usage_analysis: unreachable
    approved_by: someone
    recheck: {date}
"""


def test_exceptions():
    assert check_exceptions(None, TODAY) == []
    assert check_exceptions(EXC.format(date="2026-10-27"), TODAY) == []
    assert "expired on 2026-10-26" in check_exceptions(EXC.format(date="2026-10-26"), TODAY)[0]
    assert "invalid" in check_exceptions(EXC.format(date="soon"), TODAY)[0]


def rule_checks(*contexts):
    return [{"type": "required_status_checks",
             "parameters": {"required_status_checks": [{"context": c} for c in contexts]}}]


def prod_repo(**kw):
    base = dict(tier="production", branch_model="github-flow", default_branch="main",
                rules={"main": rule_checks("gate", "test")}, rulesets=[checks_ruleset(["test"])])
    return Repo("warren", **{**base, **kw})


def test_production_rules_clean():
    assert check_production_rules(prod_repo(), {"warren": ["test"]}) == []


def test_production_rules_drift():
    extra = copy.deepcopy(checks_ruleset(["test"]))
    extra["rules"].append({"type": "deletion"})
    findings = check_production_rules(
        prod_repo(rules={"main": rule_checks("test")}, rulesets=[extra, {"name": "legacy"}],
                  classic_protection=True),
        {"warren": ["test", "lint"]})
    text = "\n".join(findings)
    for needle in ("require check `gate`", "`legacy` is not allowed", "only required_status_checks",
                   "repo-checks.json lists", "classic branch protection"):
        assert needle in text


def test_production_rules_gitflow_and_unlisted():
    repo = prod_repo(branch_model="gitflow", default_branch="dev",
                     rules={"dev": rule_checks("gate"), "main": rule_checks("gate")})
    findings = check_production_rules(repo, {})
    assert any("promotion-guard" in f for f in findings)
    assert any("does not list this repo" in f for f in findings)
    assert "is missing" in check_production_rules(prod_repo(rulesets=[]), {"warren": ["test"]})[0]


def test_audit_repo_by_tier():
    assert audit_repo(Repo("x", "experiment", "github-flow", branches={"test": True}), {}, {}, TODAY) == []
    dev = Repo("x", "development", "github-flow", workflows={"s.yml": GOOD_WF},
               gate=[{"status": "completed", "conclusion": "success"}])
    assert audit_repo(dev, {PIN: TODAY}, {}, TODAY) == []
    dev.errors.append("audit could not read branches (HTTP 403)")
    assert audit_repo(dev, {PIN: TODAY}, {}, TODAY) == dev.errors


def test_security_ci_need_not_call_itself():
    gate = [{"status": "completed", "conclusion": "success"}]
    assert audit_repo(Repo("security-ci", "development", "github-flow", gate=gate), {}, {}, TODAY) == []
    assert "no workflow" in audit_repo(Repo("x", "development", "github-flow", gate=gate), {}, {}, TODAY)[0]


# --- org rulesets ---

def expected_rulesets():
    return {p.stem: json.loads(p.read_text()) for p in (ROOT / "rulesets").glob("*.json")}


def as_live(rs):
    live = copy.deepcopy(rs)
    live.update(id=1, source_type="Organization", node_id="x", _links={})
    live["bypass_actors"] = [{**a, "actor_id": 1} for a in live["bypass_actors"]]
    live["rules"] = list(reversed(live["rules"]))
    return live


def test_org_rulesets_match_ignoring_server_fields():
    expected = expected_rulesets()
    assert check_org_rulesets(expected, [as_live(r) for r in expected.values()]) == []


def test_org_rulesets_drift_missing_and_unannounced():
    expected = expected_rulesets()
    drifted = as_live(expected["production"])
    drifted["enforcement"] = "evaluate"
    findings = check_org_rulesets(expected, [drifted, {"name": "rogue"}])
    assert any("`production` differs" in f and "enforcement" in f for f in findings)
    assert "org ruleset `gitflow-promotion` is missing" in findings
    assert "org ruleset `rogue` is not in governance/rulesets" in findings


# --- reporting ---

def test_issue_title_is_stable():
    assert issue_title("AIRE") == "Governance audit: AIRE"


def test_summary_lists_clean_development_repos_as_ready():
    results = {"a": (Repo("a", "development"), []), "b": (Repo("b", "development"), ["x"]),
               "c": (Repo("c", "production"), [])}
    text = summary(results, [])
    ready = text.split("## Ready for production")[1].split("##")[0]
    assert "- a" in ready and "- b" not in ready and "- c" not in ready


def test_org_rulesets_read_through_a_repo_are_compared_on_the_rest():
    expected = {p.stem: json.loads(p.read_text()) for p in (ROOT / "rulesets").glob("*.json")}
    live = [{k: v for k, v in as_live(r).items() if k != "bypass_actors"} for r in expected.values()]
    for rs in live:
        rs["conditions"] = {"ref_name": rs["conditions"]["ref_name"]}
    assert check_org_rulesets(expected, live) == []
    live[0]["enforcement"] = "disabled"
    assert any("enforcement" in f for f in check_org_rulesets(expected, live))

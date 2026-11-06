import json
from pathlib import Path

from scripts.governance import (
    BATCH,
    GITHUB_ACTIONS,
    RANK,
    Change,
    OrgState,
    checks_ruleset,
    label_batches,
    permission,
    plan_direct,
    plan_teams,
)

ROOT = Path(__file__).resolve().parent.parent / "governance"


def rulesets():
    return {p.stem: json.loads(p.read_text()) for p in (ROOT / "rulesets").glob("*.json")}


def required_checks(ruleset):
    rule = next(r for r in ruleset["rules"] if r["type"] == "required_status_checks")
    return rule["parameters"]["required_status_checks"]


def test_production_requires_gate_and_linear_link_from_github_actions():
    assert required_checks(rulesets()["production"]) == [
        {"context": "gate", "integration_id": GITHUB_ACTIONS},
        {"context": "linear-link", "integration_id": GITHUB_ACTIONS},
    ]


def test_development_is_pr_only_and_requires_linear_link():
    rules = {r["type"]: r for r in rulesets()["development"]["rules"]}
    assert rules["pull_request"]["parameters"]["required_approving_review_count"] == 0
    assert required_checks(rulesets()["development"]) == [{"context": "linear-link", "integration_id": GITHUB_ACTIONS}]


def test_only_org_admins_bypass():
    for ruleset in rulesets().values():
        assert [a["actor_type"] for a in ruleset["bypass_actors"]] == ["OrganizationAdmin"]


def test_rulesets_target_tier_properties():
    props = json.loads((ROOT / "properties.json").read_text())
    for ruleset in rulesets().values():
        for cond in ruleset["conditions"]["repository_property"]["include"]:
            assert set(cond["property_values"]) <= set(props[cond["name"]]["allowed_values"])


def test_gitflow_promotions_are_merge_commits():
    rule = next(r for r in rulesets()["gitflow-promotion"]["rules"] if r["type"] == "pull_request")
    assert rule["parameters"]["allowed_merge_methods"] == ["merge"]


def test_checks_ruleset_holds_only_required_checks():
    ruleset = checks_ruleset(["test"])
    assert [r["type"] for r in ruleset["rules"]] == ["required_status_checks"]
    assert required_checks(ruleset) == [{"context": "test", "integration_id": GITHUB_ACTIONS}]


def test_label_batches_skip_archive_and_respect_the_api_limit():
    labels = {f"r{i:02}": {"tier": "experiment", "branch_model": "github-flow"} for i in range(BATCH + 5)}
    labels["old"] = {"tier": "archive", "branch_model": "github-flow"}
    batches = label_batches(labels)
    assert [len(repos) for _, repos in batches] == [BATCH, 5]
    assert all("old" not in repos for _, repos in batches)


def test_development_blocks_deletion_force_push_and_direct_push():
    assert [r["type"] for r in rulesets()["development"]["rules"]] == [
        "deletion", "non_fast_forward", "pull_request", "required_status_checks"]


def teams_config():
    return {k: v for k, v in json.loads((ROOT / "teams.json").read_text()).items() if not k.startswith("_")}


def org(**kw):
    defaults = {"members": {"ann", "bob", "owner"}, "owners": {"owner"}, "repos": ["app", "web"], "teams": {}}
    return OrgState(**{**defaults, **kw})


DESIRED = {
    "employees": {"description": "", "members": "@org-members", "repos": {"*": "push"}},
    "admins": {"description": "", "members": "@org-owners", "repos": {"*": "admin"}},
    "security": {"description": "", "members": ["ann"], "repos": {"app": "push", "gone": "push"}},
}
IN_STEP = {
    "employees": ({"ann", "bob", "owner"}, {"app": "push", "web": "push"}),
    "admins": ({"owner"}, {"app": "admin", "web": "admin"}),
    "security": ({"ann"}, {"app": "push"}),
}


def test_teams_config_follows_the_decided_model():
    teams = teams_config()
    assert teams["employees"]["members"] == "@org-members" and teams["employees"]["repos"] == {"*": "push"}
    assert teams["admins"]["members"] == "@org-owners" and teams["admins"]["repos"] == {"*": "admin"}
    for spec in teams.values():
        assert set(spec["repos"].values()) <= set(RANK)
        assert isinstance(spec["members"], list) or spec["members"] in ("@org-members", "@org-owners")


def test_plan_creates_missing_teams_and_grants_every_repo():
    changes = plan_teams(DESIRED, org(teams={"security": IN_STEP["security"]}))
    assert Change("create", "employees") in changes and Change("create", "admins") in changes
    assert [c for c in changes if c.team == "employees" and c.kind == "add-member"] == [
        Change("add-member", "employees", m) for m in ("ann", "bob", "owner")]
    assert Change("grant", "admins", "web", "admin") in changes
    assert not [c for c in changes if c.team == "security"]  # "gone" is archived or deleted: skipped


def test_plan_is_empty_when_teams_match():
    assert plan_teams(DESIRED, org(teams=IN_STEP)) == []


def test_plan_corrects_drift_but_leaves_archived_repos_alone():
    teams = {**IN_STEP, "admins": ({"owner", "bob"}, {"app": "push", "web": "admin", "old": "admin"}),
             "security": ({"ann"}, {"app": "push", "web": "push"})}
    assert plan_teams(DESIRED, org(teams=teams)) == [
        Change("remove-member", "admins", "bob"),
        Change("grant", "admins", "app", "admin"),
        Change("revoke", "security", "web"),
    ]


def test_new_repo_gets_both_org_wide_teams():
    changes = plan_teams(DESIRED, org(repos=["app", "new", "web"], teams=IN_STEP))
    assert changes == [Change("grant", "admins", "new", "admin"), Change("grant", "employees", "new", "push")]


def test_direct_grants_prune_only_what_teams_cover():
    direct = {"app": {"ann": "push", "bob": "maintain", "owner": "admin", "guest": "admin"},
              "web": {"bob": "pull"}}
    prune, kept = plan_direct(DESIRED, org(teams=IN_STEP, direct=direct))
    assert prune == [Change("prune-direct", "ann", "app", "push"), Change("prune-direct", "owner", "app", "admin"),
                     Change("prune-direct", "bob", "web", "pull")]
    assert kept == ["keep direct grant of bob (maintain) on app: more than the teams give"]  # guest: outside


def test_unknown_custom_role_is_never_pruned():
    prune, kept = plan_direct(DESIRED, org(teams=IN_STEP, direct={"app": {"ann": "deployer"}}))
    assert prune == [] and len(kept) == 1


def test_role_names_map_to_api_permissions():
    assert [permission(r) for r in ("read", "triage", "write", "maintain", "admin")] == list(RANK)

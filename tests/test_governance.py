import json
from pathlib import Path

from scripts.governance import BATCH, GITHUB_ACTIONS, checks_ruleset, label_batches

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


def test_development_only_blocks_deletion_and_force_push():
    assert [r["type"] for r in rulesets()["development"]["rules"]] == ["deletion", "non_fast_forward"]

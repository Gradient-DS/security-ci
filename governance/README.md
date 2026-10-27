# Governance

Branch protection for every Gradient-DS repository, as code. Two custom
properties decide what applies to a repo:

| Property | Values | Effect |
| --- | --- | --- |
| `tier` | `production` | Org ruleset `production` on the default branch and `main`, `test`, `dev`: no deletion or force-push, a pull request with 1 approval (stale approvals dismissed), required check `gate`. Audited nightly. |
| | `development` | No ruleset; audited nightly. |
| | `experiment` (default) | Nothing. |
| `branch_model` | `github-flow` (default) | `main` only. |
| | `gitflow` | `dev` (default branch) → `test` → `main`. For production repos, org ruleset `gitflow-promotion` lets `test` and `main` take merge commits only and requires `promotion-guard`. |

A production repo may add checks of its own: `repo-checks.json` lists them, and
they live in one repo ruleset named `checks` that holds nothing else. Every check
is pinned to GitHub Actions (integration 15368). Only `OrganizationAdmin` can bypass.

Changing a repo's tier or branch model is an org admin action. Changing the rules
is a pull request here, followed by `scripts/governance.py rulesets --apply`.

## Applying

`scripts/governance.py` prints what it would change; `--apply` changes it. Order
for the first rollout:

1. `properties --labels <labels.json>`: create the properties, label every repo.
2. Merge the pull requests that rename checks to `gate` and `promotion-guard`.
3. `rulesets`: create or update the org rulesets and each repo's `checks`.
4. `cleanup`: delete every other repo ruleset and all classic branch protection.
5. `archive --labels <labels.json>`: archive the repos labelled `archive`.

`labels.json` maps each repo to `{"tier": ..., "branch_model": ...}`; it is only
needed for the first run. Afterwards the properties on GitHub are the record.

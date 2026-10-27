# Governance

Branch protection for every Gradient-DS repository, as code. Two custom
properties decide what applies to a repo:

| Property | Values | Effect |
| --- | --- | --- |
| `tier` | `production` | Org ruleset `production` on the default branch and `main`, `test`, `dev`: no deletion or force-push, a pull request with 1 approval (stale approvals dismissed), required check `gate`. Audited nightly. |
| | `development` | Org ruleset `development` on the same branches: no deletion or force-push. Nothing else blocks a merge; audited nightly. |
| | `experiment` (default) | Nothing. |
| `branch_model` | `github-flow` (default) | `main` only. |
| | `gitflow` | `dev` (default branch) → `test` → `main`. For production repos, org ruleset `gitflow-promotion` lets `test` and `main` take merge commits only and requires `promotion-guard`. |

A third property, `source`, is `own` (default) or `upstream-mirror`: a mirror of
someone else's project, such as the signalen repos. The audit skips the
security-ci, `gate` and draft checks for a mirror, because they would only list
upstream's code; tier rulesets still apply. A fork we develop ourselves, such as
open-webui, stays `own`.

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

## Audit

`.github/workflows/governance-audit.yml` runs `scripts/governance_audit.py` every
night at 03:17 UTC, and on demand (`dry-run` prints the findings and touches no
issue). It checks every non-archived repo:

| Tier | Checked |
| --- | --- |
| all | `tier` and `branch_model` are set. |
| `development`, `production` | The branch model matches the branches (gitflow: default `dev`, `test` and `main` exist; github-flow: no `test`, default not `dev`). A workflow on the default branch calls a `security-ci` reusable workflow pinned to a commit SHA no older than 120 days. The latest `gate` on the default branch HEAD succeeded. Every `pull_request` workflow triggers on `ready_for_review`, and every job that could run on a draft carries `github.event.pull_request.draft != true`. No entry in `.github/security-exceptions.yml` is past its recheck date. |
| `production` | The default branch requires `gate` (gitflow: `main` also requires `promotion-guard`). The only repo ruleset is `checks`, holding exactly the checks in `repo-checks.json`. No classic branch protection. |

The org rulesets on GitHub must match `rulesets/*.json`, and no other org ruleset
may exist. Ruleset bypasses on production repos in the last day are listed in
the run summary for information.

Findings go to one issue per repo, titled `Governance audit: <repo>` and labelled
`governance`: opened or updated while there are findings, closed with a comment
once the repo is clean. Org drift goes to `Governance audit: org` here. The run
summary has a table per repo and a "Ready for production" list: development
repos with no findings.

The audit runs as the GitHub App `gradient-ds-governance-audit`, installed on all
repositories with read access to Administration, Metadata, Contents, Checks and
Actions, org Custom properties and org Administration, and read/write on Issues.
Its id and private key are the secrets `GOVERNANCE_APP_ID` and
`GOVERNANCE_APP_PRIVATE_KEY`.

# linear-link

Every pull request in a Gradient-DS repository links at least one Linear ticket
in its description. This action is the check; the `production` and `development`
org rulesets require it as `linear-link`.

A link is a magic word plus a ticket id, anywhere in the body:

- `Fixes GRA-123` (also `Closes`, `Resolves`, `Completes`): this PR completes the ticket; Linear moves it to Done on merge.
- `Part of GRA-123` (also `Refs`, `Related to`): the ticket needs more PRs; it links without closing.

Passes without a link: bot PRs (dependabot, renovate), promotions (`dev` -> `test`,
`test` -> `main`) and PRs labelled `no-ticket`, which a reviewer sees.

## Caller

Copy as `.github/workflows/linear-link.yml`, pinned to a commit SHA. The job must be
named `linear-link`: that is the status check the rulesets require.

```yaml
name: Linear link

on:
  pull_request:
    types: [opened, edited, reopened, synchronize, ready_for_review, labeled, unlabeled]

permissions: {}

jobs:
  linear-link:
    if: github.event.pull_request.draft != true
    runs-on: ubuntu-latest
    timeout-minutes: 2
    steps:
      - uses: Gradient-DS/security-ci/actions/linear-link@<sha> # vN
```

`edited` reruns it when the description changes, `synchronize` puts it on every new
head commit, and the labels events pick up `no-ticket`. A draft skips the job and
`ready_for_review` runs it.

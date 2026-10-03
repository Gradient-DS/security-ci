# tested-tree: skip a push run whose exact tree already passed

Two composite actions that let a push run reuse a pull request run's result,
**only** when the pushed commit's git tree is byte-for-byte the tree that
run tested.

- `record` — last job of a passing run: uploads a one-file artifact named
  `tested-tree-<workflow-key>-<tree>`.
- `check` — first job of a push run: looks that name up and outputs
  `hit=true|false`.

## Semantics

- **Exact tree match, nothing else.** The key is `git rev-parse <sha>^{tree}`.
  In a `pull_request` run `github.sha` is the `refs/pull/N/merge` commit, so the
  recorded tree is the PR merged into the base *as the base was when the run
  started*. The push after merging hits only if the merge produced that same
  tree — i.e. nothing else landed on the base in between (a strict
  "branch must be up to date" ruleset makes that the norm). Any other change
  to the base, however unrelated, is a miss and everything runs.
- **Same workflow file.** `check` accepts a record only if it was uploaded by
  a run of the workflow file `check` itself runs in. Since that file is part of
  the tree, a hit means the same job definitions ran on the same inputs. Put
  `record` and `check` in the one workflow that handles both `pull_request`
  and `push`; split across two files they never match (safe, but no reuse).
- **What is not reused-proof.** Things outside the tree: secrets, runner
  images, and for scanners the advisory databases. A skipped push-time scan
  reports the advisories as of the PR run. Keep the weekly scheduled scan.
- Records expire after `retention-days` (default 14). An expired record is a
  miss.
- `check` fails (rather than answering `false`) when the API lookup errors.

## Permissions

- `record`: `contents: read` (it reads the commit through the API, so the job
  needs no checkout). Uploading the artifact needs no extra scope.
- `check`: `contents: read`, `actions: read`.

## Caller sketch

```yaml
on:
  pull_request:
  push:
    branches: [dev]

permissions:
  contents: read
  actions: read

jobs:
  reuse:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    outputs:
      hit: ${{ steps.check.outputs.hit }}
    steps:
      - id: check
        uses: Gradient-DS/security-ci/actions/tested-tree/check@<sha> # v6
        with:
          workflow-key: tests

  test:
    needs: reuse
    # Runs on every PR, and on a push unless the exact tree already passed.
    if: ${{ !cancelled() && needs.reuse.result != 'failure' && needs.reuse.outputs.hit != 'true' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo "the real work"

  record:
    needs: [test]
    # !cancelled() is required: without a status function GitHub's implicit
    # success() also sees the skipped `reuse` upstream of `test`, so record
    # would never run on a PR.
    if: ${{ !cancelled() && github.event_name == 'pull_request' && needs.test.result == 'success' }}
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: Gradient-DS/security-ci/actions/tested-tree/record@<sha> # v6
        with:
          workflow-key: tests
```

A `gate` job that is a required check must then accept `test` as `skipped`
**only** when `needs.reuse.outputs.hit == 'true'`, and `success` otherwise.

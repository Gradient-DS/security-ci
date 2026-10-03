# security-ci

Shared security CI for Gradient Data Science: the reusable workflows, the
runtime gate and the Python packages every Gradient-DS repository's security
checks are built on.

Private on purpose. It holds the hostile corpus the attack planes drive and the
Falco rules the runtime gate reads, and neither belongs on a public page.

Until 2026-09-11 this was `Gradient-DS/.github`, the org's public profile
repository. The repository was renamed, so the history, issues and pull request
numbers came with it; `Gradient-DS/.github` is now the org profile and nothing
else.

## What is in here

| Path | What it is |
| --- | --- |
| `.github/workflows/security-source.yml` | Reusable: gitleaks, Bandit, pip-audit, npm audit and trivy config, plus the exception-file gate, as steps of one `Source scans` job |
| `.github/workflows/security-image.yml` | Reusable: Trivy image scan, of an image it builds or of a pushed digest (`image-ref`) |
| `.github/workflows/runtime-security.yml` | Reusable: brings up a caller's stack under Falco, drives its traffic, gates on egress and sensitive reads |
| `.github/workflows/tooling-token-smoke.yml` | Diagnostic: proves the org App can read this repository |
| `actions/tested-tree/{record,check}` | Composite: reuse a passing run's result on a push of the exact same git tree ([README](actions/tested-tree/README.md)) |
| `scripts/runtime_gate.py` | Decides the `runtime-gate` verdict. A skipped audit is never a pass |
| `scripts/security_exceptions.py` | Validates per-repo exception files and their expiry |
| `scripts/notify_scheduled_failure.py` | Issue title and body for a failed scheduled source or image scan |
| `scripts/tested_tree.py` | The logic of the tested-tree actions: who may record, which records count |
| `scripts/requirements_closure.py` | Decides which requirements files pip-audit may audit without resolving |
| `falco/rules/ci-egress.yaml` | Egress and sensitive-read rules, plus the sensor self-test |
| `packages/openapi-surface` | OpenAPI introspection: body skeletons, writable and constrained fields |
| `packages/hostile-corpus` | The hostile payloads and shapes the attack planes drive |
| `packages/pytest-egress-guard` | Pytest plugin that fails any test which reaches the network |

## Consuming it

A caller pins a commit and passes `secrets: inherit`, which hands the workflow
the org App credentials it needs to check this private repository out. The
workflows declare those secrets under the organisation secrets' own names,
because `secrets: inherit` matches by name: an input named anything else stays
empty, the checkout falls back to the caller's own token, and that token cannot
read this repository. A caller that passes secrets explicitly (because it also
passes `git-token` or `build-secrets`) must name them the same way:

```yaml
    secrets:
      SECURITY_CI_APP_ID: ${{ secrets.SECURITY_CI_APP_ID }}
      SECURITY_CI_APP_PRIVATE_KEY: ${{ secrets.SECURITY_CI_APP_PRIVATE_KEY }}
      git-token: ${{ secrets.SOME_READ_TOKEN }}
```


```yaml
  security:
    uses: Gradient-DS/security-ci/.github/workflows/security-source.yml@<sha> # v3
    secrets: inherit
```

Pin a SHA and put the tag in a trailing comment. Never move a tag that a
consumer pins: a moved tag silently changes what every repository runs, which
this org has already been bitten by once.

The Python packages install over git, so they need a credential too — locally
from your own `gh` login, in CI from the App:

```
hostile-corpus @ git+https://github.com/Gradient-DS/security-ci@<sha>#subdirectory=packages/hostile-corpus
```

```bash
gh auth setup-git          # once per workstation
```

```yaml
      - id: tooling-token
        uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0
        with:
          app-id: ${{ secrets.SECURITY_CI_APP_ID }}
          private-key: ${{ secrets.SECURITY_CI_APP_PRIVATE_KEY }}
          owner: Gradient-DS
          repositories: security-ci
      - run: git config --global url."https://x-access-token:${{ steps.tooling-token.outputs.token }}@github.com/".insteadOf "https://github.com/"
```

`runtime-security.yml` also exports that token as `GH_TOKEN` for the caller's
`docker compose up --build` (or, with a build cache, the `docker buildx bake`
that replaces it), so a stack that bakes this tooling into its test
image can install it: the guarded containers have no route off-host, which makes
the image build the last moment a network exists.

The App is `gradient-ds-security-ci-reader`: contents read-only, on this
repository only. Its id and private key are organisation secrets
(`SECURITY_CI_APP_ID`, `SECURITY_CI_APP_PRIVATE_KEY`), readable by every
repository in the org.

If a consumer fails at the tooling checkout with a 404, run the
`Tooling token smoke test` workflow here first: it separates an App problem
from a workflow problem.

## Image scan inputs (v6, v7)

| Input | Default | Use |
| --- | --- | --- |
| `maximize-build-space` | `false` | Frees ~30 GB of runner disk first (~90 s). Only for images that do not fit otherwise. |
| `cache-scope` | `image-name` | GHA cache scope the build reads (then the default scope) and writes. |
| `cache-write` | `true` | Write the build's layers back (`mode=max`). Off for a repo over its GHA cache limit. |
| `cache-from` | `''` | Replaces the gha cache sources, e.g. a `type=registry` ref. ghcr.io is read with `GITHUB_TOKEN`. |
| `image-ref` | `''` | Scan this pushed `name@sha256:...` instead of building. Same Trivy settings and exceptions. |
| `no-cache-filters` | `''` | v7. Stages rebuilt without cache (build-push-action `no-cache-filters`). Name the stage that runs `apt-get upgrade` / `apk upgrade`; replaces the date-valued `*_UPGRADE_EPOCH` build arg. |
| `notify-on-schedule-failure` | `false` | v7. On a failed `schedule` run, open or comment on one `security`-labelled issue per image (`Scheduled image scan failing: <repo> / <image-name>`) naming the digest and failed scanners. Needs `issues: write` on the calling job. |
| `timeout-minutes` | `40` | Job timeout (Trivy alone may take 20). |

The image job asks for `packages: read` (for `image-ref` and a ghcr.io
`cache-from`). It is part of the restricted default token, so a caller only
has to grant it if it narrows the calling job's `permissions:`.

The notifier job requests no permissions of its own and inherits the calling
job's: a reusable job that asks for `issues: write` makes every caller that does
not grant it fail at startup, input or no input. So a caller that turns it on
grants it:

```yaml
  image-published:
    uses: Gradient-DS/security-ci/.github/workflows/security-image.yml@<sha> # v7
    secrets: inherit
    permissions:
      contents: read
      packages: read
      issues: write
    with:
      image-name: app
      image-ref: ${{ needs.resolve.outputs.digest }}
      notify-on-schedule-failure: true
```

Both reusable scan workflows take `timeout-minutes` (source: 20) and a
`tooling-ref` that is empty by default, meaning the commit the reusable
workflow was itself loaded from (`job.workflow_sha`), so the helpers always
match the pinned workflow.

## Runtime security build cache (v7)

`runtime-security.yml` brings the stack up with `docker compose up --build` on
the runner's docker driver, which has no layer cache on a fresh runner. Set
either input below and the compose file's built services are pre-built with
`docker buildx bake` on a docker-container builder, loaded into docker under the
tag compose expects (`image:`, else `<project>-<service>`), and the stack comes
up with `--no-build`. Build args, secrets, targets and contexts still come from
the compose file, so an epoch or upgrade build arg forces exactly what it did.
Both empty (the default) is the v6 job, unchanged.

| Input | Default | Use |
| --- | --- | --- |
| `cache-scope` | `''` | GHA cache, read and written per service under `<cache-scope>-<service>`. |
| `cache-write` | `true` | With `cache-scope`: write the layers back (`mode=max`). |
| `cache-from` | `''` | Extra read-only sources for every built service, e.g. a `type=registry` ref. ghcr.io needs `packages: read`. |

The job checks the caller and this repository out (as `.security-tooling/`)
and writes `.falco/` inside the build context, with `persist-credentials: false`
since v7. A Dockerfile that does `COPY . .` should `.dockerignore` `.git`,
`.security-tooling` and `.falco`: their content differs on every run, so the
layer and everything after it can never be a cache hit.

A pull request run's GHA cache is readable only by runs of that pull request;
the default branch's is readable by every pull request, **fork pull requests on
a public repository included**. Do not write a cache there for a stage that
holds private content (open-webui's `INSTALL_SECURITY_CI_DEPS` layer holds this
repository's packages); use a read-only `cache-from` instead.

## Upgrading from v6

Every v6 input keeps its meaning and default; the new inputs are off by default.

- `tested-tree/check` now trusts a record only if the run that uploaded it was a
  `pull_request` run from a branch of the same repository, of the same workflow
  file (v6 checked the workflow file only). A record from a push, schedule,
  dispatch, `pull_request_target` or fork run is a miss. Callers that record on
  `pull_request`, as the README sketch does, see no difference; a public
  repository's own fork guard after `check` (open-webui's `trust` step) becomes
  redundant.
- `tested-tree/record` uploads nothing outside a same-repository `pull_request`
  run and says so in its new `recorded` output; it does not fail.
- Both tested-tree actions now run `scripts/tested_tree.py` with the runner's
  `python3` (present on GitHub-hosted runners).

## Tests

```bash
uv run pytest
```

Covers the gate decision, the exception-file rules, the gitleaks scan scope,
the scheduled-failure notifiers, tested-tree's trust rules (mocked API), the
runtime build-cache plan and the three packages.

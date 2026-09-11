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
| `.github/workflows/security-source.yml` | Reusable: gitleaks, Bandit, pip-audit, npm audit and trivy config, plus the exception-file gate |
| `.github/workflows/security-image.yml` | Reusable: container build and Trivy image scan |
| `.github/workflows/runtime-security.yml` | Reusable: brings up a caller's stack under Falco, drives its traffic, gates on egress and sensitive reads |
| `.github/workflows/tooling-token-smoke.yml` | Diagnostic: proves the org App can read this repository |
| `scripts/runtime_gate.py` | Decides the `runtime-gate` verdict. A skipped audit is never a pass |
| `scripts/security_exceptions.py` | Validates per-repo exception files and their expiry |
| `scripts/notify_scheduled_failure.py` | Notifies on a failed scheduled run |
| `falco/rules/ci-egress.yaml` | Egress and sensitive-read rules, plus the sensor self-test |
| `packages/openapi-surface` | OpenAPI introspection: body skeletons, writable and constrained fields |
| `packages/hostile-corpus` | The hostile payloads and shapes the attack planes drive |
| `packages/pytest-egress-guard` | Pytest plugin that fails any test which reaches the network |

## Consuming it

A caller pins a commit and passes `secrets: inherit`, which hands the workflow
the org App credentials it needs to check this private repository out:

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

The App is `gradient-ds-security-ci-reader`: contents read-only, on this
repository only. Its id and private key are organisation secrets
(`SECURITY_CI_APP_ID`, `SECURITY_CI_APP_PRIVATE_KEY`), readable by every
repository in the org.

If a consumer fails at the tooling checkout with a 404, run the
`Tooling token smoke test` workflow here first: it separates an App problem
from a workflow problem.

## Tests

```bash
uv run pytest
```

Covers the gate decision, the exception-file rules, the gitleaks scan scope,
the scheduled-failure notifier and the three packages.

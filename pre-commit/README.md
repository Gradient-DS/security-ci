# Org pre-commit baseline

Templates for a repository's `.pre-commit-config.yaml`, the org ruff baseline,
and the CI workflow that runs both.

| File | For |
| --- | --- |
| `python.yaml` | Python repos: hygiene hooks, ruff (lint and format), `uv lock` check, gitleaks, actionlint |
| `node.yaml` | Frontend repos: hygiene, gitleaks, actionlint, and a commented example of local eslint/prettier hooks |
| `minimal.yaml` | Everything else: hygiene, gitleaks, actionlint |
| `ruff-baseline.toml` | The ruff settings every Python repo must contain at least |

Only fast checks belong in pre-commit. Tests and type checks run in CI.

## Adopting it in a repository

1. Copy the matching template to `.pre-commit-config.yaml`. Drop the sections
   that do not apply (no workflows: no actionlint). A repo with Python and a
   frontend takes `python.yaml` plus the local hooks from `node.yaml`.
   Exclude generated and vendored paths with a top-level `exclude:` regex, and
   templated YAML (Helm templates, copier `.jinja`) from `check-yaml`.
2. Python: put `ruff-baseline.toml` into `ruff.toml`, or under `[tool.ruff]` in
   `pyproject.toml`. Add rules if you like; removing a baseline family, or
   changing line length, docstring convention or quote style, fails CI.
3. Run `uvx pre-commit install` once per clone, and
   `uvx pre-commit run --all-files` until it passes.
4. Add the CI backstop to the workflow that runs on `pull_request`, with a job
   named `pre-commit` (the required check is then `pre-commit / pre-commit`):

   ```yaml
     pre-commit:
       if: github.event.pull_request.draft != true
       uses: Gradient-DS/security-ci/.github/workflows/pre-commit.yml@<sha> # v13
       secrets: inherit
       # with:
       #   node-dirs: frontend        # npm ci there first, for local eslint hooks
       #   skip-baseline: true        # follows an upstream's style (open-webui)
   ```

   `secrets: inherit` hands over the org App credentials the workflow needs to
   check out the baseline script from this private repository.

The baseline check (`scripts/ruff_baseline.py`) reads every ruff config git
tracks, following `extend`. It is skipped with `skip-baseline: true`, and for a
repository whose custom property `source` is `upstream-mirror`.

## Bumping a hook version org-wide

1. Change the `rev:` in every template here (a test fails if the templates
   disagree, or if this repo's own `.pre-commit-config.yaml` differs from them),
   merge, and tag a release.
2. In each repository, set the same `rev:` in `.pre-commit-config.yaml` and run
   `uvx pre-commit run --all-files`. Do not use `pre-commit autoupdate`: it
   takes each hook's newest tag, not the org's version.
3. Bumping ruff can bring new rule behaviour or formatting: put a reformat in a
   commit of its own and add its SHA to `.git-blame-ignore-revs`.

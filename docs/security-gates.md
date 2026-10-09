# What the shared security gates assert

The workflows in this repository are consumed by every Gradient-DS
application repo. This document says what a green run of them means, and —
more usefully — what it does not.

A per-repo OWASP coverage matrix belongs in the repo it describes, because
coverage differs: AIRE has an LLM surface and HIPE does not, and a route
coverage gate is only as good as the spec that repo commits. AIRE's is
`security/OWASP-COVERAGE.md`.

## The three layers

| Layer | Where | What it can see |
| --- | --- | --- |
| **1. Egress denial** | `docker-compose.ci.yaml` in the consuming repo | Nothing directly. It removes the route off-host so that an outbound attempt *becomes* observable rather than succeeding quietly. Every legitimate destination is pointed at an in-network stub, so a packet leaving is by definition request data driving a fetching sink. |
| **2. Falco** | `runtime-security.yml` | Unexpected egress and sensitive-file reads from the guarded container, **while traffic is being driven**. It is a sensor, not a scanner: it reports what happened, so it sees exactly as much as the traffic driver provokes. |
| **3. `deny_egress`** | `pytest-egress-guard`, in the consuming repo's tests | The same two classes, inside one test, without a container. Cheaper and narrower. |

The self-test is what makes layer 2 trustworthy. The workflow deliberately
causes one connection and fails the run if the sensor did not report it — so a
clean Falco result means "nothing happened", not "the sensor was not running".
That distinction is the whole value of the layer, and without the self-test
the two are indistinguishable.

## What a green run means

Precisely this: **for the routes some test actually drove**, no unexpected
egress and no sensitive-file read occurred, and the consuming repo's own
assertions passed.

Every clause is load-bearing.

- *For the routes some test drove.* These workflows do not enumerate routes.
  A repo that drives one endpoint gets a green run that covers one endpoint.
  Route coverage is the consuming repo's job — AIRE does it with
  `security/route-coverage.toml` and a gate that fails when a route exists
  that nothing reaches.
- *No unexpected egress.* Not "no SSRF". A sink that is reached but blocked at
  the network still reports as blocked; a sink nothing drove reports as
  nothing.
- *No sensitive-file read.* Of the paths in the rules, from the guarded
  container, during the run.

## What they do not cover

- **Authorization, of any kind.** Nothing here has a second identity. Both
  object-level (API1) and function-level (API5) authorization are the
  consuming repo's to assert.
- **Business logic.** No tool here knows what the application is for.
- **Anything static analysis already owns.** `security-source.yml` runs
  gitleaks, Bandit, pip-audit and npm audit; `security-image.yml` runs Trivy.
  Those are separate, and they are the ones that block by default.
- **The application's own correctness.** These workflows run the consuming
  repo's `test-command` and report its exit status. What that command asserts
  is entirely up to that repo.

## Private GHCR images

`runtime-security.yml` accepts `ghcr-login` (boolean, default `false`) to
authenticate with `github.actor` / `github.token` before cached builds or
plain compose bring-up can pull private images. On the calling job, add:

```yaml
    permissions:
      contents: read
      packages: read
    with:
      ghcr-login: true
```

Keep the caller's other inputs. Each package must grant the caller repository
Read under **Package settings → Manage Actions access** (for OWUI, the repo
is `Gradient-DS/open-webui`). This also applies to private GHCR `cache-from`
sources. The opt-in job inherits the caller's grant; the default job keeps
its existing `contents: read` restriction. The workflow cannot raise the
caller's token permissions. See [registry access and build cache](../README.md#runtime-security-registry-access-and-build-cache)
for the permission design and package setup.

## `enforce`

`runtime-security.yml` takes an `enforce` input, default `false`. With it off
the job **reports success even when the assertions inside it fail** — the
failure appears only in the traffic step's log and a `::warning::` annotation.

That is a deliberate ramp-up, and it has a sharp edge worth stating: a
consuming repo that adds the workflow's check to its branch ruleset while
`enforce` is false has added a check that cannot report red. Making the check
required and flipping `enforce` are two halves of one change, and doing only
the first buys nothing.

Note also that the check names differ on purpose. `security.yml` publishes
`gate`; `runtime-security.yml` publishes `runtime-gate`. A ruleset requiring
`gate` is satisfied by whatever reports under that name, so a runtime workflow
that died at startup would leave the static gate alone to satisfy the rule —
and a dead gate reads exactly like a passing one.

## Proving a gate can fail

A gate that has never failed is indistinguishable from one that cannot, and
this is not a theoretical concern: the AIRE branch that built the attack plane
caught six distinct instances of the gate-that-cannot-fail shape, five of them
late. A `skipif` evaluated at collection time. A CSRF token that invalidated
itself, so 22 routes were recorded as covered while every request 400'd before
reaching a handler. A route that logged the driver out mid-pass.

So each consuming repo should keep a written canary procedure and run it after
material changes to its gate. AIRE's is the appendix of
`docs/superpowers/plans/2026-09-07-aire-attack-plane-handoff.md`; it was run on
2026-09-07, and its second stage turned out to *pass* for a reason worth
knowing — adding a route to the spec makes the driver drive it, so the route is
covered by construction rather than newly uncovered. A canary that cannot fail
is the same problem as a gate that cannot fail, one level up.

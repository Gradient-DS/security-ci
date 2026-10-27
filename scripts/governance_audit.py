"""Nightly governance audit: does every Gradient-DS repo match its tier?

    python -m scripts.governance_audit [--dry-run]

Reads the `tier` and `branch_model` properties, then checks each non-archived
repo against what its tier promises (governance/README.md, "Audit"). Findings go
to one issue per repo, `Governance audit: <repo>`, labelled `governance`: opened
or updated while there are findings, closed once the repo is clean. Org ruleset
drift goes to `Governance audit: org` in security-ci. --dry-run prints the
findings and the summary and touches no issue.

The checks are pure functions over fetched data; `GitHub` is the only part that
talks to the API. Token: GH_TOKEN, else GITHUB_TOKEN, else `gh auth token`.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from scripts import security_exceptions
from scripts.governance import CHECKS_RULESET, ORG, ROOT

SECURITY_CI = "security-ci"
LABEL = "governance"
TITLE_PREFIX = "Governance audit"
MAX_PIN_AGE_DAYS = 120
EXCEPTIONS_FILE = ".github/security-exceptions.yml"
REUSABLE = re.compile(r"^Gradient-DS/security-ci/\.github/workflows/[^@]+\.ya?ml@(.+)$")
# A project generated from soev-project-template calls its project-security.yml,
# which calls security-ci at a pin the template keeps fresh.
TEMPLATE_SECURITY = re.compile(r"^Gradient-DS/soev-project-template/\.github/workflows/project-security\.yml@\S+$")
SHA = re.compile(r"[0-9a-f]{40}")
TIERS = ("production", "development", "experiment")
MODELS = ("github-flow", "gitflow")


def issue_title(repo: str) -> str:
    return f"{TITLE_PREFIX}: {repo}"


# --- Draft pull requests never run CI --------------------------------------

STATUS_FN = re.compile(r"\b(always|cancelled|failure|success)\(\)")
DRAFT_GUARD = re.compile(r"!\s*github\.event\.pull_request\.draft"
                         r"|github\.event\.pull_request\.draft\s*(!=\s*true|==\s*false)")


def conjuncts(expr: str) -> list[str]:
    """Split on top-level `&&` only."""
    parts, depth, cur, i = [], 0, "", 0
    while i < len(expr):
        c = expr[i]
        depth += (c == "(") - (c == ")")
        if depth == 0 and expr.startswith("&&", i):
            parts.append(cur.strip())
            cur, i = "", i + 2
            continue
        cur += c
        i += 1
    parts.append(cur.strip())
    return parts


def _unparen(c: str) -> str:
    c = c.strip()
    while c.startswith("(") and c.endswith(")"):
        c = c[1:-1].strip()
    return c


def never_on_pr(expr: str) -> bool:
    """True when a top-level conjunct only admits named non-PR events."""
    for c in conjuncts(expr):
        terms = [t.strip() for t in _unparen(c).split("||")]
        events = [re.fullmatch(r"github\.event_name\s*==\s*'([a-z_]+)'", t) for t in terms]
        if all(events) and not any(e.group(1).startswith("pull_request") for e in events):
            return True
    return False


def job_if(job: dict) -> str:
    """The job's `if` as one line, without `${{ }}`."""
    expr = str(job.get("if") or "").strip()
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", expr, re.S)
    return " ".join((m.group(1) if m else expr).split())


def needs_draft_check(job: dict) -> bool:
    """Can run on a PR, and no skipped `needs` would skip it on a draft."""
    expr = job_if(job)
    if expr and never_on_pr(expr):
        return False
    return not job.get("needs") or bool(STATUS_FN.search(expr))


def skips_drafts(job: dict) -> bool:
    return any(DRAFT_GUARD.fullmatch(_unparen(c)) for c in conjuncts(job_if(job)))


def pr_trigger(workflow: dict) -> tuple[bool, dict]:
    on = workflow.get(True, workflow.get("on"))  # PyYAML reads `on:` as True
    if isinstance(on, str):
        return on == "pull_request", {}
    if isinstance(on, list):
        return "pull_request" in on, {}
    if isinstance(on, dict) and "pull_request" in on:
        return True, on["pull_request"] or {}
    return False, {}


def check_drafts(path: str, workflow: dict) -> list[str]:
    has_pr, pr = pr_trigger(workflow)
    if not has_pr:
        return []
    types = pr.get("types")
    if isinstance(types, str):
        types = [types]
    if types and "closed" in types and "synchronize" not in types:
        return []
    out = []
    if not types or "ready_for_review" not in types:
        out.append(f"`{path}`: `pull_request` does not trigger on `ready_for_review`")
    for name, job in (workflow.get("jobs") or {}).items():
        job = job or {}
        if needs_draft_check(job) and not skips_drafts(job):
            out.append(f"`{path}` job `{name}` runs on draft PRs: add "
                       "`github.event.pull_request.draft != true` to its `if`")
    return out


# --- Per-repo checks ----------------------------------------------------------

@dataclass
class Repo:
    name: str
    tier: str | None = None
    branch_model: str | None = None
    default_branch: str = "main"
    source: str = "own"                                            # own | upstream-mirror
    branches: dict[str, bool] = field(default_factory=dict)        # dev/test/main -> exists
    workflows: dict[str, str] = field(default_factory=dict)        # path -> text
    gate: list[dict] | None = None                                 # check runs named gate
    exceptions_text: str | None = None
    rules: dict[str, list[dict]] = field(default_factory=dict)     # branch -> effective rules
    rulesets: list[dict] = field(default_factory=list)             # repo rulesets, full
    classic_protection: bool = False
    bypasses: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def check_properties(repo: Repo) -> list[str]:
    out = []
    if repo.tier not in TIERS:
        out.append(f"custom property `tier` is {_shown(repo.tier)}; expected one of {', '.join(TIERS)}")
    if repo.branch_model not in MODELS:
        out.append(f"custom property `branch_model` is {_shown(repo.branch_model)}; "
                   f"expected one of {', '.join(MODELS)}")
    return out


def _shown(value: str | None) -> str:
    return f"`{value}`" if value else "not set"


def check_branch_model(repo: Repo) -> list[str]:
    if repo.branch_model == "gitflow":
        out = [] if repo.default_branch == "dev" else [
            f"gitflow repo has default branch `{repo.default_branch}`, expected `dev`"]
        out += [f"gitflow repo has no `{b}` branch" for b in ("test", "main") if not repo.branches.get(b)]
        return out
    if repo.branch_model == "github-flow":
        out = ["github-flow repo has a `test` branch"] if repo.branches.get("test") else []
        if repo.default_branch == "dev":
            out.append("github-flow repo has default branch `dev`")
        return out
    return []


def parse_workflows(repo: Repo) -> tuple[dict[str, dict], list[str]]:
    parsed, out = {}, []
    for path, text in sorted(repo.workflows.items()):
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            out.append(f"`{path}` does not parse: {str(exc).splitlines()[0]}")
            continue
        if isinstance(doc, dict):
            parsed[path] = doc
    return parsed, out


def security_ci_refs(workflows: dict[str, dict]) -> list[tuple[str, str]]:
    """(path, ref) for every job calling a security-ci reusable workflow."""
    refs = []
    for path, wf in workflows.items():
        for job in (wf.get("jobs") or {}).values():
            m = REUSABLE.match(str((job or {}).get("uses") or ""))
            if m:
                refs.append((path, m.group(1)))
    return refs


def check_security_ci(workflows: dict[str, dict], commit_dates: dict[str, dt.date | None],
                      today: dt.date) -> list[str]:
    refs = security_ci_refs(workflows)
    if not refs:
        if any(TEMPLATE_SECURITY.match(str((job or {}).get("uses") or ""))
               for wf in workflows.values() for job in (wf.get("jobs") or {}).values()):
            return []
        return ["no workflow on the default branch calls a `Gradient-DS/security-ci` reusable workflow"]
    out = []
    for path, ref in sorted(set(refs)):
        if not SHA.fullmatch(ref):
            out.append(f"`{path}` calls security-ci at `{ref}`; pin it to a commit SHA")
            continue
        when = commit_dates.get(ref)
        if when is None:
            out.append(f"`{path}` pins security-ci `{ref[:12]}`, which is not a commit in security-ci")
        elif (today - when).days > MAX_PIN_AGE_DAYS:
            out.append(f"`{path}` pins security-ci `{ref[:12]}` from {when}, "
                       f"older than {MAX_PIN_AGE_DAYS} days")
    return out


def check_gate(repo: Repo) -> list[str]:
    if repo.gate is None:
        return []
    if not repo.gate:
        return [f"no `gate` check run on `{repo.default_branch}` HEAD"]
    done = [r for r in repo.gate if r.get("status") == "completed"]
    if not done:
        return []  # still running; tomorrow's audit sees it
    latest = max(done, key=lambda r: r.get("completed_at") or "")
    if latest.get("conclusion") != "success":
        return [f"latest `gate` on `{repo.default_branch}` HEAD concluded `{latest.get('conclusion')}`"]
    return []


def check_exceptions(text: str | None, today: dt.date) -> list[str]:
    if text is None:
        return []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "security-exceptions.yml"
        path.write_text(text)
        try:
            excs = security_exceptions.load(path)
        except (security_exceptions.ExceptionFileError, yaml.YAMLError) as exc:
            return [f"`{EXCEPTIONS_FILE}` is invalid: {str(exc).replace(str(path), EXCEPTIONS_FILE)}"]
    return [f"security exception `{e.id}` ({e.package}) expired on {e.recheck}"
            for e in security_exceptions.expired(excs, today)]


def required_contexts(rules: list[dict]) -> set[str]:
    return {c["context"] for r in rules if r.get("type") == "required_status_checks"
            for c in (r.get("parameters") or {}).get("required_status_checks", [])}


def check_production_rules(repo: Repo, repo_checks: dict[str, list[str]]) -> list[str]:
    out = []
    branch = repo.default_branch
    if "gate" not in required_contexts(repo.rules.get(branch, [])):
        out.append(f"`{branch}` does not require check `gate`")
    if repo.branch_model == "gitflow" and "promotion-guard" not in required_contexts(repo.rules.get("main", [])):
        out.append("`main` does not require check `promotion-guard`")
    expected = repo_checks.get(repo.name)
    names = [rs.get("name") for rs in repo.rulesets]
    out += [f"repo ruleset `{n}` is not allowed; only `{CHECKS_RULESET}`" for n in names if n != CHECKS_RULESET]
    checks = next((rs for rs in repo.rulesets if rs.get("name") == CHECKS_RULESET), None)
    if checks and expected is None:
        out.append(f"repo ruleset `{CHECKS_RULESET}` exists but repo-checks.json does not list this repo")
    elif expected is not None and not checks:
        out.append(f"repo ruleset `{CHECKS_RULESET}` is missing")
    elif checks:
        types = [r.get("type") for r in checks.get("rules", [])]
        if types != ["required_status_checks"]:
            out.append(f"repo ruleset `{CHECKS_RULESET}` holds {types}; only required_status_checks")
        live = required_contexts(checks.get("rules", []))
        if live != set(expected):
            out.append(f"repo ruleset `{CHECKS_RULESET}` requires {sorted(live)}; "
                       f"repo-checks.json lists {sorted(expected)}")
    if repo.classic_protection:
        out.append(f"classic branch protection on `{branch}`; rulesets only")
    return out


def audit_repo(repo: Repo, commit_dates: dict[str, dt.date | None], repo_checks: dict[str, list[str]],
               today: dt.date) -> list[str]:
    out = check_properties(repo) + list(repo.errors)
    if repo.tier not in ("development", "production"):
        return out
    workflows, out_parse = parse_workflows(repo)
    out += check_branch_model(repo) + out_parse
    if repo.source == "upstream-mirror":
        # Someone else's code and CI: scanning it would only list upstream's
        # findings. The branch model and rulesets still apply.
        return out + (check_production_rules(repo, repo_checks) if repo.tier == "production" else [])
    if repo.name != SECURITY_CI:  # the scans live here; its own CI tests them in place
        out += check_security_ci(workflows, commit_dates, today)
    out += check_gate(repo)
    for path, wf in workflows.items():
        out += check_drafts(path, wf)
    out += check_exceptions(repo.exceptions_text, today)
    if repo.tier == "production":
        out += check_production_rules(repo, repo_checks)
    return out


# --- Org rulesets -------------------------------------------------------------

def _diff(expected: object, live: object, where: str) -> list[str]:
    """Paths where `live` differs from `expected`; keys only `live` has are ignored."""
    if isinstance(expected, dict):
        if not isinstance(live, dict):
            return [where]
        return [d for k, v in expected.items() for d in _diff(v, live.get(k), f"{where}.{k}")]
    if isinstance(expected, list):
        if not isinstance(live, list) or len(live) != len(expected):
            return [where]
        return [d for i, (e, l) in enumerate(zip(expected, live)) for d in _diff(e, l, f"{where}[{i}]")]
    return [] if expected == live else [where]


def _comparable(rs: dict) -> dict:
    return {
        "name": rs.get("name"), "target": rs.get("target"), "enforcement": rs.get("enforcement"),
        "conditions": rs.get("conditions"),
        "bypass_actors": sorted((a.get("actor_type"), a.get("bypass_mode")) for a in rs.get("bypass_actors") or []),
        "rules": sorted(rs.get("rules") or [], key=lambda r: r.get("type", "")),
    }


def check_org_rulesets(expected: dict[str, dict], live: list[dict]) -> list[str]:
    by_name = {rs.get("name"): rs for rs in live}
    out = []
    for name, want in sorted(expected.items()):
        have = by_name.get(name)
        if have is None:
            out.append(f"org ruleset `{name}` is missing")
            continue
        exp, got = _comparable(want), _comparable(have)
        exp["bypass_actors"] = [list(a) for a in exp["bypass_actors"]]
        got["bypass_actors"] = [list(a) for a in got["bypass_actors"]]
        if "bypass_actors" not in have:
            # GitHub returns bypass actors only to a token that may edit the
            # ruleset; the audit App only reads, so it cannot compare them.
            exp.pop("bypass_actors"), got.pop("bypass_actors")
        if "repository_property" not in (have.get("conditions") or {}):
            # Read through a repo, an org ruleset omits its repository
            # condition; the per-repo rule checks cover which repos it hits.
            exp["conditions"] = {k: v for k, v in (exp["conditions"] or {}).items() if k != "repository_property"}
        diffs = _diff(exp, got, name)
        if diffs:
            out.append(f"org ruleset `{name}` differs from governance/rulesets at {', '.join(diffs)}")
    out += [f"org ruleset `{n}` is not in governance/rulesets" for n in sorted(set(by_name) - set(expected))]
    return out


# --- Reporting ----------------------------------------------------------------

def issue_body(repo: str, findings: list[str], bypasses: list[dict], run_url: str) -> str:
    lines = [f"The nightly governance audit found {len(findings)} problem(s) in **{repo}**.", ""]
    lines += [f"- [ ] {f}" for f in findings]
    if bypasses:
        lines += ["", "Ruleset bypasses in the last day (informational):", ""]
        lines += [f"- {b.get('actor_name')} pushed `{b.get('ref')}` at {b.get('pushed_at')}" for b in bypasses]
    lines += ["", f"Run: {run_url}" if run_url else "",
              "This issue is updated every night and closed when the audit comes back clean. "
              "What each check means: Gradient-DS/security-ci, governance/README.md."]
    return "\n".join(lines).rstrip() + "\n"


def summary(results: dict[str, tuple[Repo, list[str]]], org_findings: list[str]) -> str:
    lines = ["# Governance audit", "", "| Repo | Tier | Branch model | Findings |", "| --- | --- | --- | --- |"]
    for name, (repo, findings) in sorted(results.items(), key=lambda kv: kv[0].lower()):
        lines.append(f"| {name} | {repo.tier or '-'} | {repo.branch_model or '-'} | {len(findings) or ''} |")
    ready = sorted(n for n, (r, f) in results.items() if r.tier == "development" and not f)
    lines += ["", "## Ready for production", ""] + ([f"- {n}" for n in ready] or ["None."])
    lines += ["", "## Org", ""] + ([f"- {f}" for f in org_findings] or ["No ruleset drift."])
    bypassed = [(n, b) for n, (r, _) in sorted(results.items()) for b in r.bypasses]
    if bypassed:
        lines += ["", "## Ruleset bypasses, last day", ""]
        lines += [f"- {n}: {b.get('actor_name')} pushed `{b.get('ref')}` at {b.get('pushed_at')}" for n, b in bypassed]
    return "\n".join(lines) + "\n"


# --- GitHub -------------------------------------------------------------------

class ApiError(RuntimeError):
    def __init__(self, status: int, path: str):
        super().__init__(f"HTTP {status} on {path}")
        self.status = status


class GitHub:
    def __init__(self, token: str, api: str = "https://api.github.com"):
        self.token, self.api = token, api

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[object, str]:
        url = path if path.startswith("http") else f"{self.api}/{path}"
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return (json.loads(raw) if raw else None), resp.headers.get("Link") or ""
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, path) from None

    def get(self, path: str, missing_ok: bool = False) -> object:
        try:
            return self.request("GET", path)[0]
        except ApiError as exc:
            if missing_ok and exc.status == 404:
                return None
            raise

    def paginate(self, path: str) -> list:
        out, url = [], path + ("&" if "?" in path else "?") + "per_page=100"
        while url:
            data, link = self.request("GET", url)
            out += data if isinstance(data, list) else next(v for v in data.values() if isinstance(v, list))
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = m.group(1) if m else ""
        return out

    def file(self, repo: str, path: str, ref: str) -> str | None:
        data = self.get(f"repos/{ORG}/{repo}/contents/{path}?ref={ref}", missing_ok=True)
        if not isinstance(data, dict) or not data.get("content"):
            return None
        return base64.b64decode(data["content"]).decode()


def collect(gh: GitHub, meta: dict, props: dict[str, str]) -> Repo:
    name = meta["name"]
    repo = Repo(name, props.get("tier"), props.get("branch_model"), meta["default_branch"],
                source=props.get("source") or "own")
    if repo.tier not in ("development", "production"):
        return repo
    base, branch = f"repos/{ORG}/{name}", repo.default_branch

    def attempt(what: str, fn):
        try:
            fn()
        except ApiError as exc:
            repo.errors.append(f"audit could not read {what} ({exc})")

    def branches():
        for b in ("dev", "test", "main"):
            repo.branches[b] = gh.get(f"{base}/branches/{b}", missing_ok=True) is not None

    def workflows():
        listing = gh.get(f"{base}/contents/.github/workflows?ref={branch}", missing_ok=True) or []
        for entry in listing:
            if entry.get("type") == "file" and entry["name"].endswith((".yml", ".yaml")):
                text = gh.file(name, entry["path"], branch)
                if text is not None:
                    repo.workflows[entry["path"]] = text

    def gate():
        repo.gate = gh.get(f"{base}/commits/{branch}/check-runs?check_name=gate&filter=latest")["check_runs"]

    def exceptions():
        repo.exceptions_text = gh.file(name, EXCEPTIONS_FILE, branch)

    attempt("branches", branches)
    attempt("workflows", workflows)
    attempt("the gate check run", gate)
    attempt(EXCEPTIONS_FILE, exceptions)
    if repo.tier == "production":
        def rules():
            for b in {branch, "main"} if repo.branch_model == "gitflow" else {branch}:
                repo.rules[b] = gh.paginate(f"{base}/rules/branches/{b}")

        def rulesets():
            for rs in gh.paginate(f"{base}/rulesets?includes_parents=false"):
                repo.rulesets.append(gh.get(f"{base}/rulesets/{rs['id']}"))

        def protection():
            repo.classic_protection = gh.get(f"{base}/branches/{branch}/protection", missing_ok=True) is not None

        def bypasses():
            repo.bypasses = gh.get(f"{base}/rulesets/rule-suites?rule_suite_result=bypass&time_period=day") or []

        attempt("effective branch rules", rules)
        attempt("repo rulesets", rulesets)
        attempt("classic branch protection", protection)
        attempt("rule suites", bypasses)
    return repo


def commit_dates(gh: GitHub, repos: list[Repo]) -> dict[str, dt.date | None]:
    shas = {ref for r in repos for _, ref in security_ci_refs(parse_workflows(r)[0]) if SHA.fullmatch(ref)}
    out: dict[str, dt.date | None] = {}
    for sha in sorted(shas):
        try:
            c = gh.get(f"repos/{ORG}/{SECURITY_CI}/commits/{sha}")
            out[sha] = dt.date.fromisoformat(c["commit"]["committer"]["date"][:10])
        except ApiError as exc:
            if exc.status not in (404, 422):
                raise
            out[sha] = None
    return out


def sync_issue(gh: GitHub, repo: str, title: str, body: str | None) -> None:
    """Open or update the issue when there is a body, close it when there is none."""
    try:
        open_ = [i for i in gh.paginate(f"repos/{ORG}/{repo}/issues?state=open&labels={LABEL}")
                 if i["title"] == title and "pull_request" not in i]
        if body is not None and open_:
            gh.request("PATCH", f"repos/{ORG}/{repo}/issues/{open_[0]['number']}", {"body": body})
        elif body is not None:
            gh.request("POST", f"repos/{ORG}/{repo}/issues", {"title": title, "body": body, "labels": [LABEL]})
        for issue in open_ if body is None else []:
            gh.request("POST", f"repos/{ORG}/{repo}/issues/{issue['number']}/comments",
                       {"body": "The governance audit is clean for this repo. Closing."})
            gh.request("PATCH", f"repos/{ORG}/{repo}/issues/{issue['number']}",
                       {"state": "closed", "state_reason": "completed"})
    except ApiError as exc:  # e.g. 410: issues disabled
        print(f"::warning::could not sync issue in {repo}: {exc}")


def token() -> str:
    for var in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()


def org_rulesets(gh: GitHub, metas: list[dict]) -> list[dict]:
    """Every org ruleset that applies to some repo, read through that repo.

    `orgs/{org}/rulesets` needs organization administration write; a repo's own
    listing with `includes_parents=true` shows the org rulesets that target it
    with read access only. That view omits bypass actors and the repository
    condition, and an org ruleset that targets no repo is not seen.
    """
    seen: dict[int, dict] = {}
    for m in metas:
        base = f"repos/{ORG}/{m['name']}/rulesets"
        for rs in gh.paginate(f"{base}?includes_parents=true"):
            if rs.get("source_type") == "Organization" and rs["id"] not in seen:
                seen[rs["id"]] = gh.get(f"{base}/{rs['id']}?includes_parents=true")
    return list(seen.values())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="print findings; touch no issue")
    args = ap.parse_args(argv)
    gh, today = GitHub(token()), dt.date.today()
    run_url = (f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
               f"{os.environ['GITHUB_RUN_ID']}" if os.environ.get("GITHUB_RUN_ID") else "")

    props = {p["repository_name"]: {v["property_name"]: v["value"] for v in p["properties"]}
             for p in gh.paginate(f"orgs/{ORG}/properties/values")}
    metas = [m for m in gh.paginate(f"orgs/{ORG}/repos?type=all") if not m["archived"]]
    repos = [collect(gh, m, props.get(m["name"], {})) for m in metas]
    dates = commit_dates(gh, repos)
    repo_checks = {k: v for k, v in json.loads((ROOT / "repo-checks.json").read_text()).items()
                   if not k.startswith("_")}
    results = {r.name: (r, audit_repo(r, dates, repo_checks, today)) for r in repos}

    expected = {json.loads(p.read_text())["name"]: json.loads(p.read_text())
                for p in sorted((ROOT / "rulesets").glob("*.json"))}
    org_findings = check_org_rulesets(expected, org_rulesets(gh, metas))

    text = summary(results, org_findings)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(text)
    if args.dry_run:
        for name, (repo, findings) in sorted(results.items(), key=lambda kv: kv[0].lower()):
            for f in findings:
                print(f"{name}: {f}")
        print(text)
        return 0

    for name, (repo, findings) in results.items():
        body = issue_body(name, findings, repo.bypasses, run_url) if findings else None
        sync_issue(gh, name, issue_title(name), body)
    sync_issue(gh, SECURITY_CI, issue_title("org"),
               issue_body("the org rulesets", org_findings, [], run_url) if org_findings else None)
    return 0


if __name__ == "__main__":
    sys.exit(main())

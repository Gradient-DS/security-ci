"""Apply the org's governance/: properties, org rulesets, repo checks, teams.

Run by an org admin with `gh` logged in. Every step prints what it would do and
changes nothing without --apply:

    python scripts/governance.py properties --labels labels.json [--apply]
    python scripts/governance.py rulesets [--apply]
    python scripts/governance.py cleanup [--apply]
    python scripts/governance.py archive --labels labels.json [--apply]
    python scripts/governance.py teams [--prune-direct] [--grants-only] [--apply]

`labels.json` maps repo -> {"tier": ..., "branch_model": ...}; tier "archive"
archives the repo instead of labelling it. After the first run the properties on
GitHub are the record; the nightly audit reads them there.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ORG = "Gradient-DS"
ROOT = Path(__file__).resolve().parent.parent / "governance"
CHECKS_RULESET = "checks"
GITHUB_ACTIONS = 15368
BATCH = 30  # PATCH /orgs/{org}/properties/values takes at most 30 repos


def gh(*args: str, body: dict | None = None, apply: bool = True) -> object:
    cmd = ["gh", "api", *args]
    if body is not None:
        cmd += ["--input", "-"]
    if not apply:
        print("  would run:", " ".join(cmd), json.dumps(body) if body is not None else "")
        return None
    out = subprocess.run(cmd, input=json.dumps(body) if body is not None else None,
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"gh {' '.join(args)} failed: {out.stderr.strip() or out.stdout.strip()}")
    return json.loads(out.stdout) if out.stdout.strip() else None


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


def label_batches(labels: dict[str, dict]) -> list[tuple[dict[str, str], list[str]]]:
    """Group repos by identical property values, in batches the API accepts."""
    groups: dict[tuple[tuple[str, str], ...], list[str]] = {}
    for repo, props in sorted(labels.items()):
        if props["tier"] == "archive":
            continue
        key = tuple(sorted(props.items()))
        groups.setdefault(key, []).append(repo)
    return [
        (dict(key), repos[i:i + BATCH])
        for key, repos in sorted(groups.items())
        for i in range(0, len(repos), BATCH)
    ]


def checks_ruleset(contexts: list[str]) -> dict:
    return {
        "name": CHECKS_RULESET,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [{"actor_id": None, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
        "rules": [{
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": False,
                "do_not_enforce_on_create": True,
                "required_status_checks": [{"context": c, "integration_id": GITHUB_ACTIONS} for c in contexts],
            },
        }],
    }


def upsert(path: str, existing: list[dict], ruleset: dict, apply: bool) -> None:
    match = next((r for r in existing if r["name"] == ruleset["name"]), None)
    if match:
        print(f"update {path} ruleset {ruleset['name']} ({match['id']})")
        gh("-X", "PUT", f"{path}/{match['id']}", body=ruleset, apply=apply)
    else:
        print(f"create {path} ruleset {ruleset['name']}")
        gh("-X", "POST", path, body=ruleset, apply=apply)


def cmd_properties(args: argparse.Namespace) -> None:
    for name, schema in load("properties.json").items():
        print(f"property {name}")
        gh("-X", "PUT", f"orgs/{ORG}/properties/schema/{name}", body=schema, apply=args.apply)
    for props, repos in label_batches(json.loads(Path(args.labels).read_text())):
        print(f"set {props} on {', '.join(repos)}")
        body = {"repository_names": repos,
                "properties": [{"property_name": k, "value": v} for k, v in props.items()]}
        gh("-X", "PATCH", f"orgs/{ORG}/properties/values", body=body, apply=args.apply)


def cmd_rulesets(args: argparse.Namespace) -> None:
    org_existing = gh(f"orgs/{ORG}/rulesets") or []
    for path in sorted((ROOT / "rulesets").glob("*.json")):
        upsert(f"orgs/{ORG}/rulesets", org_existing, json.loads(path.read_text()), args.apply)
    for repo, contexts in load("repo-checks.json").items():
        if repo.startswith("_"):
            continue
        existing = gh(f"repos/{ORG}/{repo}/rulesets") or []
        upsert(f"repos/{ORG}/{repo}/rulesets", existing, checks_ruleset(contexts), args.apply)


def cmd_cleanup(args: argparse.Namespace) -> None:
    """Remove every repo ruleset except `checks`, and classic branch protection."""
    listing = subprocess.run(
        ["gh", "api", "--paginate", f"orgs/{ORG}/repos", "--jq", ".[] | select(.archived | not) | .name"],
        capture_output=True, text=True, check=True)
    for repo in listing.stdout.split():
        for rs in gh(f"repos/{ORG}/{repo}/rulesets") or []:
            if rs.get("source_type") == "Repository" and rs["name"] != CHECKS_RULESET:
                print(f"delete {repo} ruleset {rs['name']} ({rs['id']})")
                gh("-X", "DELETE", f"repos/{ORG}/{repo}/rulesets/{rs['id']}", apply=args.apply)
        default = gh(f"repos/{ORG}/{repo}")["default_branch"]
        probe = subprocess.run(["gh", "api", f"repos/{ORG}/{repo}/branches/{default}/protection"],
                               capture_output=True, text=True)
        if probe.returncode == 0:
            print(f"delete {repo} classic protection on {default}")
            gh("-X", "DELETE", f"repos/{ORG}/{repo}/branches/{default}/protection", apply=args.apply)


def cmd_archive(args: argparse.Namespace) -> None:
    for repo, props in sorted(json.loads(Path(args.labels).read_text()).items()):
        if props["tier"] == "archive":
            print(f"archive {repo}")
            gh("-X", "PATCH", f"repos/{ORG}/{repo}", body={"archived": True}, apply=args.apply)


# --- Teams ---------------------------------------------------------------------

ALL_REPOS = "*"
RANK = {"pull": 1, "triage": 2, "push": 3, "maintain": 4, "admin": 5}
ROLE_TO_PERMISSION = {"read": "pull", "write": "push"}  # role_name -> API permission name


def permission(role_name: str) -> str:
    return ROLE_TO_PERMISSION.get(role_name, role_name)


@dataclass
class OrgState:
    members: set[str]
    owners: set[str]
    repos: list[str]                                              # non-archived
    teams: dict[str, tuple[set[str], dict[str, str]]]             # slug -> (members, repo -> permission)
    direct: dict[str, dict[str, str]] = field(default_factory=dict)  # repo -> member login -> permission


@dataclass(frozen=True)
class Change:
    kind: str     # create | add-member | remove-member | grant | revoke | prune-direct
    team: str     # team slug; the user's login for prune-direct
    target: str = ""
    value: str = ""

    def __str__(self) -> str:
        return {
            "create": f"create team {self.team}",
            "add-member": f"add {self.target} to team {self.team}",
            "remove-member": f"remove {self.target} from team {self.team}",
            "grant": f"grant team {self.team} {self.value} on {self.target}",
            "revoke": f"revoke team {self.team} from {self.target}",
            "prune-direct": f"remove direct grant of {self.team} ({self.value}) on {self.target}",
        }[self.kind]


def wanted_members(spec: dict, state: OrgState) -> set[str]:
    members = spec["members"]
    if members == "@org-members":
        return set(state.members)
    if members == "@org-owners":
        return set(state.owners)
    return set(members)


def wanted_repos(spec: dict, state: OrgState) -> dict[str, str]:
    if ALL_REPOS in spec["repos"]:
        return dict.fromkeys(state.repos, spec["repos"][ALL_REPOS])
    return {r: p for r, p in spec["repos"].items() if r in state.repos}


def coverage(desired: dict[str, dict], state: OrgState, login: str, repo: str) -> int:
    """The highest permission `login` gets on `repo` from ownership or the desired teams."""
    best = RANK["admin"] if login in state.owners else 0
    for spec in desired.values():
        if login in wanted_members(spec, state):
            best = max(best, RANK.get(wanted_repos(spec, state).get(repo, ""), 0))
    return best


def plan_teams(desired: dict[str, dict], state: OrgState) -> list[Change]:
    """Changes that make the teams match `desired`; grants on archived repos are left alone."""
    out: list[Change] = []
    for slug, spec in sorted(desired.items()):
        members, repos = state.teams.get(slug, (set(), {}))
        if slug not in state.teams:
            out.append(Change("create", slug))
        want = wanted_members(spec, state)
        out += [Change("add-member", slug, m) for m in sorted(want - members, key=str.lower)]
        out += [Change("remove-member", slug, m) for m in sorted(members - want, key=str.lower)]
        want_repos = wanted_repos(spec, state)
        out += [Change("grant", slug, r, p) for r, p in sorted(want_repos.items(), key=lambda kv: kv[0].lower())
                if repos.get(r) != p]
        out += [Change("revoke", slug, r) for r in sorted(repos, key=str.lower)
                if r in state.repos and r not in want_repos]
    return out


def plan_direct(desired: dict[str, dict], state: OrgState) -> tuple[list[Change], list[str]]:
    """Direct grants of org members the teams cover (prunable), and those they do not (kept)."""
    prune, kept = [], []
    for repo in sorted(state.direct, key=str.lower):
        for login, perm in sorted(state.direct[repo].items(), key=lambda kv: kv[0].lower()):
            if login not in state.members:
                continue  # outside collaborators stay per repo
            if RANK.get(perm, RANK["admin"] + 1) <= coverage(desired, state, login, repo):
                prune.append(Change("prune-direct", login, repo, perm))
            else:
                kept.append(f"keep direct grant of {login} ({perm}) on {repo}: more than the teams give")
    return prune, kept


def gh_items(path: str) -> list[dict]:
    """Every item of a paginated list endpoint."""
    out = subprocess.run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        sys.exit(f"gh {path} failed: {out.stderr.strip() or out.stdout.strip()}")
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def fetch_state(desired: dict[str, dict], with_direct: bool) -> OrgState:
    existing = {t["slug"] for t in gh_items(f"orgs/{ORG}/teams")}
    teams = {
        slug: ({u["login"] for u in gh_items(f"orgs/{ORG}/teams/{slug}/members")},
               {r["name"]: permission(r["role_name"]) for r in gh_items(f"orgs/{ORG}/teams/{slug}/repos")})
        for slug in sorted(existing & set(desired))
    }
    repos = sorted((r["name"] for r in gh_items(f"orgs/{ORG}/repos?type=all") if not r["archived"]), key=str.lower)
    state = OrgState(members={u["login"] for u in gh_items(f"orgs/{ORG}/members")},
                     owners={u["login"] for u in gh_items(f"orgs/{ORG}/members?role=admin")},
                     repos=repos, teams=teams)
    if with_direct:
        state.direct = {r: {c["login"]: permission(c["role_name"])
                            for c in gh_items(f"repos/{ORG}/{r}/collaborators?affiliation=direct")}
                        for r in repos}
    return state


def apply_change(change: Change, desired: dict[str, dict]) -> None:
    team = f"orgs/{ORG}/teams/{change.team}"
    if change.kind == "create":
        gh("-X", "POST", f"orgs/{ORG}/teams", body={
            "name": change.team, "description": desired[change.team]["description"], "privacy": "closed"})
    elif change.kind == "add-member":
        gh("-X", "PUT", f"{team}/memberships/{change.target}", body={"role": "member"})
    elif change.kind == "remove-member":
        gh("-X", "DELETE", f"{team}/memberships/{change.target}")
    elif change.kind == "grant":
        gh("-X", "PUT", f"{team}/repos/{ORG}/{change.target}", body={"permission": change.value})
    elif change.kind == "revoke":
        gh("-X", "DELETE", f"{team}/repos/{ORG}/{change.target}")
    elif change.kind == "prune-direct":
        gh("-X", "DELETE", f"repos/{ORG}/{change.target}/collaborators/{change.team}")


def cmd_teams(args: argparse.Namespace) -> None:
    """Teams, members and repo grants from teams.json; direct member grants are reported, pruned on request.

    --grants-only (the nightly sync) adds and corrects repo grants of teams that
    exist and leaves everything else to an org admin.
    """
    desired = {k: v for k, v in load("teams.json").items() if not k.startswith("_")}
    state = fetch_state(desired, with_direct=not args.grants_only)
    changes = plan_teams(desired, state)
    if args.prune_direct and args.apply and changes:
        sys.exit("teams are not in their desired state yet: run `teams --apply` first, then --prune-direct")
    if args.apply and not args.grants_only and any(c.kind == "create" for c in changes):
        for c in changes:
            if c.kind == "create":
                print(c)
                apply_change(c, desired)
        state = fetch_state(desired, with_direct=True)  # the creator joins a new team as maintainer
        changes = plan_teams(desired, state)
    todo = [c for c in changes if c.kind == "grant" and c.team in state.teams] if args.grants_only else changes
    left = [c for c in changes if c not in todo]
    for c in todo:
        print(c)
        if args.apply:
            apply_change(c, desired)
    for c in left:
        print(f"left for an org admin (`teams --apply`): {c}")
    if not args.grants_only:
        prune, kept = plan_direct(desired, state)
        for line in kept:
            print(line)
        if prune and not args.prune_direct:
            print(f"{len(prune)} direct member grant(s) are covered by teams; `--prune-direct` removes them:")
        for c in prune:
            print(f"  {c}" if not args.prune_direct else c)
            if args.prune_direct and args.apply:
                apply_change(c, desired)
    if not todo and not left:
        print("teams match governance/teams.json")
    if os.environ.get("GITHUB_STEP_SUMMARY") and left:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write("\n## Teams left for an org admin\n\n" + "".join(f"- {c}\n" for c in left))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, labels in [("properties", cmd_properties, True), ("rulesets", cmd_rulesets, False),
                             ("cleanup", cmd_cleanup, False), ("archive", cmd_archive, True),
                             ("teams", cmd_teams, False)]:
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        s.add_argument("--apply", action="store_true", help="make the changes (default: print them)")
        if labels:
            s.add_argument("--labels", required=True)
        if name == "teams":
            s.add_argument("--prune-direct", action="store_true",
                           help="also remove direct grants of org members that the teams cover")
            s.add_argument("--grants-only", action="store_true",
                           help="only add or correct repo grants of existing teams (the nightly sync)")
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

"""Apply the org's branch protection from governance/: properties, org rulesets, repo checks.

Run by an org admin with `gh` logged in. Every step prints what it would do and
changes nothing without --apply:

    python scripts/governance.py properties --labels labels.json [--apply]
    python scripts/governance.py rulesets [--apply]
    python scripts/governance.py cleanup [--apply]
    python scripts/governance.py archive --labels labels.json [--apply]

`labels.json` maps repo -> {"tier": ..., "branch_model": ...}; tier "archive"
archives the repo instead of labelling it. After the first run the properties on
GitHub are the record; the nightly audit reads them there.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
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


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, labels in [("properties", cmd_properties, True), ("rulesets", cmd_rulesets, False),
                             ("cleanup", cmd_cleanup, False), ("archive", cmd_archive, True)]:
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        s.add_argument("--apply", action="store_true", help="make the changes (default: print them)")
        if labels:
            s.add_argument("--labels", required=True)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

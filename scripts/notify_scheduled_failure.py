"""Build the issue a failed scheduled security scan opens.

The title is stable and exact: the workflow lists open `security`-labelled
issues and matches this title verbatim with jq, so weekly failures append to
one thread instead of opening a new issue every Monday. Do not make the title
vary per run, and do not add characters that would need escaping in a jq
comparison.
"""
from __future__ import annotations

TITLE_PREFIX = "Scheduled security scan failing"


def issue_title(repo: str) -> str:
    return f"{TITLE_PREFIX}: {repo}"


def issue_body(repo: str, run_url: str, failed_jobs: list[str]) -> str:
    jobs = "\n".join(f"- `{j}`" for j in failed_jobs) if failed_jobs else "- (see run)"
    return (
        f"The weekly security scan for **{repo}** failed.\n\n"
        f"Failed jobs:\n{jobs}\n\n"
        f"Run: {run_url}\n\n"
        "This is a scheduled run, so it blocks no PR. It still means a new "
        "advisory landed against code already on the branch. Per the exception "
        "policy: upgrade if a fix exists, otherwise replace the package, "
        "otherwise request an exception from @Gradient-DS/security.\n"
    )


IMAGE_TITLE_PREFIX = "Scheduled image scan failing"


def image_issue_title(repo: str, image_name: str) -> str:
    return f"{IMAGE_TITLE_PREFIX}: {repo} / {image_name}"


def image_issue_body(repo: str, image_name: str, image: str, run_url: str,
                     failed_scanners: list[str]) -> str:
    scanners = "\n".join(f"- `{s}`" for s in failed_scanners) if failed_scanners else "- (see run)"
    return (
        f"The scheduled image scan of **{image_name}** in **{repo}** failed.\n\n"
        f"Image: `{image or '(not resolved; see run)'}`\n\n"
        f"Failed scanners:\n{scanners}\n\n"
        f"Run: {run_url}\n\n"
        "This is a scheduled run, so it blocks no PR. It still means a new "
        "advisory landed against an image that is already published. Per the "
        "exception policy: rebuild or upgrade if a fix exists, otherwise replace "
        "the package, otherwise request an exception from @Gradient-DS/security.\n"
    )

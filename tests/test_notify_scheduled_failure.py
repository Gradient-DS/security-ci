from scripts.notify_scheduled_failure import issue_body, issue_title


def test_title_is_stable_across_weeks_so_issues_dedupe():
    assert issue_title("HIPE") == issue_title("HIPE")
    assert "HIPE" in issue_title("HIPE")


def test_body_lists_failed_jobs_and_links_the_run():
    body = issue_body("HIPE", "https://github.com/x/y/actions/runs/1", ["sca-python", "iac"])
    assert "sca-python" in body
    assert "iac" in body
    assert "https://github.com/x/y/actions/runs/1" in body


def test_body_handles_no_named_jobs():
    body = issue_body("HIPE", "https://example.test/run", [])
    assert "https://example.test/run" in body


def test_image_title_is_stable_and_names_the_image():
    from scripts.notify_scheduled_failure import image_issue_title
    assert image_issue_title("soev-gitops", "a") == image_issue_title("soev-gitops", "a")
    assert image_issue_title("soev-gitops", "a") != image_issue_title("soev-gitops", "b")
    assert "soev-gitops" in image_issue_title("soev-gitops", "a")


def test_image_body_names_image_digest_and_scanners():
    from scripts.notify_scheduled_failure import image_issue_body
    ref = "ghcr.io/gradient-ds/x@sha256:" + "0" * 64
    body = image_issue_body("r", "x", ref, "https://example.test/run", ["trivy"])
    assert ref in body and "`trivy`" in body and "https://example.test/run" in body
    assert "(see run)" in image_issue_body("r", "x", "", "u", [])

"""What the guard must catch, and what it must leave alone.

The cases mirror the incident the plugin exists for: a rendered document that
fetched an attacker-chosen URL, and the local-file half of the same primitive.
The last three cases pin platform traps that a naive implementation walks into
-- see the comments on each.
"""

import pathlib
import urllib.request

import pytest

from pytest_egress_guard import EgressDenied


def test_blocks_link_local_metadata_service(deny_egress):
    deny_egress.expect_attempts()
    with pytest.raises(EgressDenied) as exc:
        urllib.request.urlopen("http://169.254.169.254/latest/meta-data/", timeout=1)
    assert "169.254.169.254" in str(exc.value)


def test_blocks_file_scheme(deny_egress):
    """The LFI half: urllib's FileHandler bottoms out in builtins.open."""
    deny_egress.expect_attempts()
    with pytest.raises(EgressDenied):
        urllib.request.urlopen("file:///etc/passwd")


def test_blocks_direct_sensitive_read(deny_egress):
    deny_egress.expect_attempts()
    with pytest.raises(EgressDenied):
        open("/etc/shadow")


def test_blocks_sensitive_read_through_pathlib(deny_egress):
    """`Path.read_text` calls `io.open`, not `builtins.open`.

    They are two module attributes bound to the same function, so patching one
    leaves the other live.  Guarding only `builtins` lets any LFI that happens
    to be written in pathlib walk straight through.
    """
    deny_egress.expect_attempts()
    with pytest.raises(EgressDenied):
        pathlib.Path("/etc/passwd").read_text()


def test_blocks_sensitive_read_through_a_symlinked_prefix(deny_egress, tmp_path):
    """Resolving the path is necessary but not sufficient, in both directions.

    A link to a guarded file must be caught (this case).  And on macOS `/etc`
    is itself a symlink to `/private/etc`, so a guard that checks *only* the
    resolved path stops matching the `/etc/...` prefixes it was given -- which
    is why the literal path is checked too.
    """
    deny_egress.expect_attempts()
    link = tmp_path / "innocent.txt"
    link.symlink_to("/etc/passwd")
    with pytest.raises(EgressDenied):
        open(link)


def test_allows_ordinary_file_read(deny_egress, tmp_path):
    p = tmp_path / "ok.txt"
    p.write_text("fine")
    assert p.read_text() == "fine"


def test_guards_are_removed_after_the_test():
    """monkeypatch must restore open, or every later test is poisoned.

    Reads this file rather than a system path: `/etc/hostname` does not exist
    on macOS, and a teardown check that fails for its own reasons proves
    nothing about teardown.
    """
    with open(__file__) as fh:
        assert fh.read() is not None
    assert pathlib.Path(__file__).read_text() is not None


def test_records_every_attempt(deny_egress):
    """The log is the evidence, and it names what was reached for."""
    deny_egress.expect_attempts()

    with pytest.raises(EgressDenied):
        urllib.request.urlopen("http://169.254.169.254/", timeout=1)
    with pytest.raises(EgressDenied):
        open("/etc/shadow")

    assert [(a.kind, a.target) for a in deny_egress.attempts] == [
        ("dns", "169.254.169.254"),
        ("open", "/etc/shadow"),
    ]


def test_a_swallowed_attempt_still_fails_the_test(pytester):
    """The case that matters: the sink catches the exception and carries on.

    WeasyPrint does exactly this -- it wraps image loading in a bare
    ``except Exception`` and renders the document anyway.  A guard that only
    raises therefore reports a pass on the tree that carried the incident.
    Recording the attempt is what turns that back into a failure.
    """
    pytester.makepyfile(
        """
        import urllib.request

        def test_sink_that_swallows(deny_egress):
            try:
                urllib.request.urlopen("http://169.254.169.254/", timeout=1)
            except Exception:
                pass  # the library shrugs, exactly like WeasyPrint does
        """
    )

    result = pytester.runpytest()

    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*169.254.169.254*"])

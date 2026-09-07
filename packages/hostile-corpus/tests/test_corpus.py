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

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

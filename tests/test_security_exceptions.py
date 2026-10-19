import datetime as dt
import pathlib
import pytest
from scripts.security_exceptions import (
    TRIVY_IGNORE_KINDS,
    ExceptionFileError, NpmAuditError, SecurityException, load,
    expired, gitleaksignore_text, main, npm_unexcepted, pip_audit_args,
    trivyignore_text, trivyignore_yaml_text, write_trivyignore,
)

VALID_ENTRY = """
version: 1
exceptions:
  - id: PYSEC-2026-3412
    package: weasyprint
    scanner: pip-audit
    reason: No fixed release exists; latest 68.1 is still affected.
    replacement_considered: >-
      Evaluated reportlab and wkhtmltopdf; neither supports the CSS
      paged-media features the export templates depend on.
    usage_analysis: >-
      The advisory needs attacker-controlled CSS. We render only
      server-side templates; no user input reaches the stylesheet.
    approved_by: "@some-reviewer"
    recheck: 2026-12-01
"""

def _write(tmp_path, text):
    p = tmp_path / "security-exceptions.yml"
    p.write_text(text)
    return p

def test_missing_file_yields_no_exceptions(tmp_path):
    assert load(tmp_path / "nope.yml") == []

def test_empty_file_yields_no_exceptions(tmp_path):
    assert load(_write(tmp_path, "")) == []

def test_valid_entry_is_parsed(tmp_path):
    (exc,) = load(_write(tmp_path, VALID_ENTRY))
    assert isinstance(exc, SecurityException)
    assert exc.id == "PYSEC-2026-3412"
    assert exc.package == "weasyprint"
    assert exc.scanner == "pip-audit"
    assert exc.recheck == dt.date(2026, 12, 1)

def test_missing_required_field_is_rejected(tmp_path):
    text = VALID_ENTRY.replace('    approved_by: "@some-reviewer"\n', "")
    with pytest.raises(ExceptionFileError, match="approved_by"):
        load(_write(tmp_path, text))

def test_unknown_scanner_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: snyk")
    with pytest.raises(ExceptionFileError, match="snyk"):
        load(_write(tmp_path, text))

def test_duplicate_id_is_rejected(tmp_path):
    doubled = VALID_ENTRY + VALID_ENTRY.split("exceptions:")[1]
    with pytest.raises(ExceptionFileError, match="duplicate"):
        load(_write(tmp_path, doubled))

def test_non_date_recheck_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("recheck: 2026-12-01", 'recheck: "soon"')
    with pytest.raises(ExceptionFileError, match="recheck"):
        load(_write(tmp_path, text))

def test_whitespace_only_required_field_is_rejected(tmp_path):
    text = VALID_ENTRY.replace(
        "    usage_analysis: >-\n", "    usage_analysis: '   '\n"
    )
    # collapse the now-orphaned continuation lines of the folded block
    text = "\n".join(
        l for l in text.split("\n")
        if not l.startswith("      The advisory needs")
        and not l.startswith("      server-side templates")
    )
    with pytest.raises(ExceptionFileError, match="usage_analysis"):
        load(_write(tmp_path, text))


def _exc(id_, scanner="pip-audit", recheck=dt.date(2026, 12, 1)):
    return SecurityException(
        id=id_, package="pkg", scanner=scanner, reason="r",
        replacement_considered="rc", usage_analysis="ua",
        approved_by="@r", recheck=recheck,
    )


def test_expired_returns_only_past_recheck_dates():
    fresh = _exc("A", recheck=dt.date(2026, 12, 1))
    stale = _exc("B", recheck=dt.date(2026, 8, 1))
    assert expired([fresh, stale], today=dt.date(2026, 9, 1)) == [stale]


def test_recheck_date_is_inclusive():
    on_the_day = _exc("A", recheck=dt.date(2026, 9, 1))
    assert expired([on_the_day], today=dt.date(2026, 9, 1)) == []


def test_pip_audit_args_only_include_pip_audit_scanner():
    excs = [_exc("A"), _exc("B", scanner="trivy")]
    assert pip_audit_args(excs) == ["--ignore-vuln", "A"]


def test_pip_audit_args_empty_when_no_exceptions():
    assert pip_audit_args([]) == []


def test_trivyignore_text_lists_ids_with_comments():
    text = trivyignore_text([_exc("CVE-1", scanner="trivy")])
    assert "CVE-1" in text
    assert "pkg" in text


def test_npm_unexcepted_flags_high_and_critical_only():
    audit = {"vulnerabilities": {
        "lodash":  {"severity": "critical", "via": [{"url": "https://github.com/advisories/GHSA-aaa"}]},
        "chalk":   {"severity": "moderate", "via": [{"url": "https://github.com/advisories/GHSA-bbb"}]},
    }}
    assert npm_unexcepted(audit, []) == ["GHSA-aaa"]


def test_npm_unexcepted_respects_exceptions():
    audit = {"vulnerabilities": {
        "lodash": {"severity": "critical", "via": [{"url": "https://github.com/advisories/GHSA-aaa"}]},
    }}
    assert npm_unexcepted(audit, [_exc("GHSA-aaa", scanner="npm")]) == []


def test_npm_unexcepted_handles_mixed_via_shapes():
    audit = {"vulnerabilities": {
        "lodash": {"severity": "critical", "via": [
            "some-transitive-pkg",
            {"url": "https://github.com/advisories/GHSA-aaa"},
        ]},
        "only-string-via": {"severity": "high", "via": ["lodash"]},
    }}
    # The string via resolves to lodash's advisory, reported once.
    assert npm_unexcepted(audit, []) == ["GHSA-aaa"]


def test_npm_unexcepted_inherited_finding_is_covered_by_the_source_advisory():
    audit = {"vulnerabilities": {
        "sharp": {"severity": "high", "via": [
            {"url": "https://github.com/advisories/GHSA-aaa", "severity": "high"},
        ]},
        "onnx": {"severity": "moderate", "via": [
            {"url": "https://github.com/advisories/GHSA-mod", "severity": "moderate"},
        ]},
        "@scope/lib": {"severity": "high", "via": ["onnx", "sharp"]},
        "app": {"severity": "high", "via": ["@scope/lib"]},
    }}
    assert npm_unexcepted(audit, []) == ["GHSA-aaa"]
    assert npm_unexcepted(audit, [_exc("GHSA-aaa", scanner="npm")]) == []


def test_npm_unexcepted_inherited_chain_without_blocking_advisory_falls_back_to_package():
    audit = {"vulnerabilities": {
        "a": {"severity": "high", "via": ["b"]},
        "b": {"severity": "high", "via": ["a"]},
    }}
    # A cycle with no advisory must not loop, and must still fail closed.
    assert npm_unexcepted(audit, []) == ["package:a", "package:b"]


def test_npm_unexcepted_reports_blocking_entry_with_unresolvable_via():
    audit = {"vulnerabilities": {
        "left-pad": {"severity": "critical", "via": [{"source": 123, "title": "t"}]},
    }}
    assert npm_unexcepted(audit, []) == ["package:left-pad"]


def test_npm_unexcepted_package_fallback_respects_exception_on_package_name():
    audit = {"vulnerabilities": {
        "left-pad": {"severity": "critical", "via": [{"source": 123, "title": "t"}]},
    }}
    assert npm_unexcepted(audit, [_exc("left-pad", scanner="npm")]) == []


def test_npm_unexcepted_severity_comparison_is_case_insensitive():
    audit = {"vulnerabilities": {
        "lodash": {"severity": "Critical", "via": [{"url": "https://github.com/advisories/GHSA-aaa"}]},
        "chalk": {"severity": "HIGH", "via": [{"url": "https://github.com/advisories/GHSA-bbb"}]},
        "quiet": {"severity": "Moderate", "via": [{"url": "https://github.com/advisories/GHSA-ccc"}]},
    }}
    assert npm_unexcepted(audit, []) == ["GHSA-aaa", "GHSA-bbb"]


def test_npm_unexcepted_rejects_error_shaped_report():
    """`npm audit` writes {"error": ...} on registry outage / ENOLOCK and still
    exits non-zero; the workflow's `|| true` swallows that, so an audit report
    with no `vulnerabilities` key must fail closed, never read as clean."""
    audit = {"error": {"code": "ENOLOCK", "summary": "no lockfile", "detail": "…"}}
    with pytest.raises(NpmAuditError, match="ENOLOCK"):
        npm_unexcepted(audit, [])


def test_npm_unexcepted_rejects_report_without_vulnerabilities_key():
    with pytest.raises(NpmAuditError, match="vulnerabilities"):
        npm_unexcepted({}, [])


def test_npm_unexcepted_accepts_empty_vulnerabilities_map():
    assert npm_unexcepted({"vulnerabilities": {}}, []) == []


def test_cli_fails_on_error_shaped_npm_audit_json(tmp_path, capsys):
    """End to end: the exit code, not just the function, must be non-zero."""
    report = tmp_path / "audit.json"
    report.write_text('{"error": {"code": "ENOLOCK", "summary": "no lockfile"}}')
    rc = main(["--file", str(tmp_path / "nope.yml"), "--npm-audit-json", str(report)])
    assert rc == 1
    assert "ENOLOCK" in capsys.readouterr().err


def test_exception_id_with_newline_is_rejected(tmp_path):
    """An id carrying a newline would inject extra keys into $GITHUB_OUTPUT."""
    text = VALID_ENTRY.replace(
        "id: PYSEC-2026-3412", 'id: "GHSA-a\\nEVIL=1"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_exception_id_with_trailing_newline_only_is_rejected(tmp_path):
    """Regression test for the match->fullmatch fix.

    `$` without re.MULTILINE matches both at the true end of string AND just
    before a trailing newline at the end of the string. An id that is
    otherwise valid, followed by a single trailing "\\n" and nothing else,
    is the one shape that `ID_PATTERN.match()` would have let through even
    though `ID_PATTERN.fullmatch()` rejects it — the two existing newline
    tests above append content *after* the newline, which `.match()` already
    caught, so neither exercises this quirk.
    """
    text = VALID_ENTRY.replace(
        "id: PYSEC-2026-3412", 'id: "GHSA-a\\n"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


@pytest.mark.parametrize("bad", ["GHSA a", "GHSA-a;rm -rf /", "GHSA-$(id)", "GHSA-a>out"])
def test_exception_ids_with_shell_metacharacters_are_rejected(tmp_path, bad):
    text = VALID_ENTRY.replace("id: PYSEC-2026-3412", f'id: "{bad}"')
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_trivyignore_text_excludes_other_scanners():
    """Negative isolation: a pip-audit exception must never reach trivy."""
    text = trivyignore_text([
        _exc("CVE-1", scanner="trivy"),
        _exc("PYSEC-2026-3412", scanner="pip-audit"),
        _exc("GHSA-aaa", scanner="npm"),
    ])
    assert "CVE-1" in text
    assert "PYSEC-2026-3412" not in text
    assert "GHSA-aaa" not in text


GITLEAKS_FINGERPRINT = (
    "ba0a0dcd23d3a8b864fe258686e77422db7397d4:infrastructure/README.md:"
    "curl-auth-header:70"
)


def test_gitleaks_entry_with_fingerprint_id_is_accepted(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace("id: PYSEC-2026-3412", f"id: {GITLEAKS_FINGERPRINT}")
    (exc,) = load(_write(tmp_path, text))
    assert exc.id == GITLEAKS_FINGERPRINT
    assert exc.scanner == "gitleaks"


def test_gitleaks_fingerprint_id_is_rejected_for_pip_audit_scanner(tmp_path):
    """Proves the strict ID_PATTERN still applies to scanners other than
    gitleaks: a gitleaks-shaped id (colons, slashes) is not a valid pip-audit
    id even though it would be fine for gitleaks itself."""
    text = VALID_ENTRY.replace("id: PYSEC-2026-3412", f"id: {GITLEAKS_FINGERPRINT}")
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaks_id_with_newline_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace(
        "id: PYSEC-2026-3412", 'id: "abc:def:rule:1\\nEVIL=1"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaks_id_with_space_is_rejected(tmp_path):
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace(
        "id: PYSEC-2026-3412", 'id: "abc:def:rule id:1"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaks_id_with_trailing_newline_only_is_rejected(tmp_path):
    """Same regression as test_exception_id_with_trailing_newline_only_is_
    rejected, but for GITLEAKS_ID_PATTERN (`^\\S+$`): a fingerprint followed
    by a single trailing "\\n" and nothing else is exactly the shape
    `.match()` would wrongly accept and `.fullmatch()` correctly rejects.
    """
    text = VALID_ENTRY.replace("scanner: pip-audit", "scanner: gitleaks")
    text = text.replace(
        "id: PYSEC-2026-3412", 'id: "abc:def:rule:1\\n"'
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_gitleaksignore_text_lists_ids_with_comments():
    text = gitleaksignore_text([_exc(GITLEAKS_FINGERPRINT, scanner="gitleaks")])
    assert GITLEAKS_FINGERPRINT in text
    assert "pkg" in text


def test_gitleaksignore_text_excludes_other_scanners():
    """Negative isolation: exceptions for other scanners must never reach
    the gitleaksignore file."""
    text = gitleaksignore_text([
        _exc(GITLEAKS_FINGERPRINT, scanner="gitleaks"),
        _exc("PYSEC-2026-3412", scanner="pip-audit"),
        _exc("CVE-1", scanner="trivy"),
        _exc("GHSA-aaa", scanner="npm"),
    ])
    assert GITLEAKS_FINGERPRINT in text
    assert "PYSEC-2026-3412" not in text
    assert "CVE-1" not in text
    assert "GHSA-aaa" not in text


# --------------------------------------------------------------------------
# Optional `paths`: per-file scoping for trivy exceptions.
#
# The problem it solves: a plain `.trivyignore` matches by check id across the
# whole scanned tree, so an exception written for four known privileged
# DaemonSets silently covers a fifth one added next month. These tests pin the
# validation, the format switch, and — most importantly — that an unscoped
# entry still behaves exactly as it did before the field existed.
# --------------------------------------------------------------------------
import yaml as _yaml

TRIVY_ENTRY = """
version: 1
exceptions:
  - id: KSV017
    package: infrastructure
    scanner: trivy
    reason: The node-tuning DaemonSets configure the host and must be privileged.
    replacement_considered: Capability narrowing is privileged in all but name.
    usage_analysis: Pinned busybox, fixed inline scripts, no external input.
    approved_by: "@some-reviewer"
    recheck: 2026-12-01
"""

SCOPED_PATHS = """    paths:
      - "previder-prod/node-tuning/iscsi-node-seed-daemonset.yaml"
      - "previder-prod/node-tuning/inotify-daemonset.yaml"
"""


def _scoped(extra=SCOPED_PATHS):
    return TRIVY_ENTRY.replace("    recheck: 2026-12-01\n",
                               "    recheck: 2026-12-01\n" + extra)


def test_paths_is_optional_and_defaults_to_tree_wide(tmp_path):
    (exc,) = load(_write(tmp_path, TRIVY_ENTRY))
    assert exc.paths == ()


def test_paths_is_parsed_into_a_tuple(tmp_path):
    (exc,) = load(_write(tmp_path, _scoped()))
    assert exc.paths == (
        "previder-prod/node-tuning/iscsi-node-seed-daemonset.yaml",
        "previder-prod/node-tuning/inotify-daemonset.yaml",
    )


def test_paths_on_a_non_trivy_scanner_is_rejected(tmp_path):
    """A `paths` list on a gitleaks or pip-audit entry would read as scoped
    while actually suppressing tree-wide — the worst possible failure mode for
    this field, so it is a hard error rather than a silent no-op."""
    text = _scoped().replace("scanner: trivy", "scanner: pip-audit")
    with pytest.raises(ExceptionFileError, match="only trivy and semgrep support"):
        load(_write(tmp_path, text))


def test_empty_paths_list_is_rejected(tmp_path):
    text = TRIVY_ENTRY.replace("    recheck: 2026-12-01\n",
                               "    recheck: 2026-12-01\n    paths: []\n")
    with pytest.raises(ExceptionFileError, match="non-empty list"):
        load(_write(tmp_path, text))


def test_paths_must_be_a_list_not_a_bare_string(tmp_path):
    text = TRIVY_ENTRY.replace("    recheck: 2026-12-01\n",
                               '    recheck: 2026-12-01\n    paths: "a.yaml"\n')
    with pytest.raises(ExceptionFileError, match="non-empty list"):
        load(_write(tmp_path, text))


@pytest.mark.parametrize("bad", ["/etc/passwd", "../../etc/passwd", "a/../../b.yaml"])
def test_absolute_and_traversing_paths_are_rejected(tmp_path, bad):
    text = _scoped(f'    paths:\n      - "{bad}"\n')
    with pytest.raises(ExceptionFileError, match="relative to the trivy scan root"):
        load(_write(tmp_path, text))


def test_path_with_embedded_newline_is_rejected(tmp_path):
    text = _scoped('    paths:\n      - "a.yaml\\nb.yaml"\n')
    with pytest.raises(ExceptionFileError, match="whitespace"):
        load(_write(tmp_path, text))


@pytest.mark.parametrize(
    "bad", ["**", "*", "a/*.yaml", "previder-prod/**/x.yaml", "a?.yaml", "a[0-9].yaml"]
)
def test_paths_with_glob_metacharacters_are_rejected(tmp_path, bad):
    """Trivy matches `paths` as a glob, so `["**"]` reads in review as a scoped
    exception while suppressing the entire tree — exactly the failure mode the
    field exists to prevent. A scoped entry must name its files."""
    text = _scoped(f'    paths:\n      - "{bad}"\n')
    with pytest.raises(ExceptionFileError, match="glob metacharacter"):
        load(_write(tmp_path, text))


def test_empty_path_entry_is_rejected(tmp_path):
    text = _scoped('    paths:\n      - "   "\n')
    with pytest.raises(ExceptionFileError, match="non-string or empty"):
        load(_write(tmp_path, text))


def test_yaml_ignorefile_carries_paths_per_entry():
    scoped = SecurityException(
        id="KSV017", package="infra", scanner="trivy", reason="r",
        replacement_considered="rc", usage_analysis="ua", approved_by="@r",
        recheck=dt.date(2026, 12, 1), paths=("a/b.yaml",),
    )
    doc = _yaml.safe_load(trivyignore_yaml_text([scoped]))
    (mis,) = doc["misconfigurations"]
    assert mis["id"] == "KSV017"
    assert mis["paths"] == ["a/b.yaml"]


def test_yaml_ignorefile_omits_paths_for_tree_wide_entries():
    doc = _yaml.safe_load(trivyignore_yaml_text([_exc("CVE-1", scanner="trivy")]))
    (mis,) = doc["misconfigurations"]
    assert "paths" not in mis


def test_yaml_ignorefile_lists_each_id_under_all_four_kinds():
    """The plain format is kind-agnostic — one id there suppresses a finding of
    any kind. Trivy's YAML format has four: vulnerabilities, misconfigurations,
    secrets and licenses. Listing the id under every one of them is what keeps
    the YAML file equivalent rather than narrower."""
    doc = _yaml.safe_load(trivyignore_yaml_text([_exc("CVE-1", scanner="trivy")]))
    assert set(doc) == set(TRIVY_IGNORE_KINDS)
    assert set(TRIVY_IGNORE_KINDS) == {
        "vulnerabilities", "misconfigurations", "secrets", "licenses",
    }
    for kind in TRIVY_IGNORE_KINDS:
        assert [e["id"] for e in doc[kind]] == ["CVE-1"], kind


def test_yaml_ignorefile_excludes_other_scanners():
    doc = _yaml.safe_load(trivyignore_yaml_text([
        _exc("CVE-1", scanner="trivy"),
        _exc("PYSEC-2026-3412", scanner="pip-audit"),
        _exc("GHSA-aaa", scanner="npm"),
    ]))
    assert [e["id"] for e in doc["misconfigurations"]] == ["CVE-1"]
    assert [e["id"] for e in doc["vulnerabilities"]] == ["CVE-1"]


def test_yaml_statement_is_a_single_line():
    """A folded `reason` spans several lines; the statement must not, or the
    generated document changes shape with the wording."""
    multi = SecurityException(
        id="KSV017", package="infra", scanner="trivy",
        reason="first line\nsecond line", replacement_considered="rc",
        usage_analysis="ua", approved_by="@r", recheck=dt.date(2026, 12, 1),
    )
    (mis,) = _yaml.safe_load(trivyignore_yaml_text([multi]))["misconfigurations"]
    assert "\n" not in mis["statement"]
    assert "first line second line" in mis["statement"]


def test_write_trivyignore_uses_plain_format_when_nothing_is_scoped(tmp_path):
    """Regression guard for the other eight repos: adding this field must not
    change the file any repo without `paths` gets."""
    base = tmp_path / "security-exceptions.trivyignore"
    written = write_trivyignore([_exc("CVE-1", scanner="trivy")], str(base))
    assert written == base
    assert not (tmp_path / "security-exceptions.trivyignore.yaml").exists()
    assert written.read_text() == trivyignore_text([_exc("CVE-1", scanner="trivy")])


def test_write_trivyignore_switches_to_yaml_when_any_entry_is_scoped(tmp_path):
    """Trivy picks its parser by extension, so the YAML format has to land on
    a *.yaml path — the switch is a rename, not just a different body."""
    base = tmp_path / "security-exceptions.trivyignore"
    scoped = SecurityException(
        id="KSV017", package="infra", scanner="trivy", reason="r",
        replacement_considered="rc", usage_analysis="ua", approved_by="@r",
        recheck=dt.date(2026, 12, 1), paths=("a/b.yaml",),
    )
    written = write_trivyignore([scoped, _exc("CVE-1", scanner="trivy")], str(base))
    assert written.name.endswith(".trivyignore.yaml")
    assert not base.exists()
    doc = _yaml.safe_load(written.read_text())
    assert {e["id"] for e in doc["misconfigurations"]} == {"KSV017", "CVE-1"}


def test_cli_prints_the_path_it_wrote(tmp_path, capsys):
    """The workflows capture stdout to learn which file to hand trivy, so the
    path must be the only thing on it."""
    base = tmp_path / "security-exceptions.trivyignore"
    rc = main(["--file", str(_write(tmp_path, _scoped())),
               "--emit-trivyignore", str(base)])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == f"{base}.yaml"
    assert _yaml.safe_load(pathlib.Path(out).read_text())["misconfigurations"]


def test_cli_prints_plain_path_when_nothing_is_scoped(tmp_path, capsys):
    base = tmp_path / "security-exceptions.trivyignore"
    rc = main(["--file", str(_write(tmp_path, TRIVY_ENTRY)),
               "--emit-trivyignore", str(base)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == str(base)


def test_yaml_ignorefile_has_no_anchors_or_aliases():
    """Each id is written under both kinds; if the two entries shared one
    `paths` list, PyYAML would emit `paths: *id001` for the second. Valid YAML,
    but a generated file someone reads mid-incident should not need aliases
    resolved to show which files an exception covers."""
    scoped = SecurityException(
        id="KSV017", package="infra", scanner="trivy", reason="r",
        replacement_considered="rc", usage_analysis="ua", approved_by="@r",
        recheck=dt.date(2026, 12, 1), paths=("a/b.yaml", "c/d.yaml"),
    )
    text = trivyignore_yaml_text([scoped])
    assert "&id" not in text and "*id" not in text
    doc = _yaml.safe_load(text)
    assert doc["misconfigurations"][0]["paths"] == ["a/b.yaml", "c/d.yaml"]
    assert doc["vulnerabilities"][0]["paths"] == ["a/b.yaml", "c/d.yaml"]


# --- gitleaks `ids` grouping -------------------------------------------------

GITLEAKS_IDS_ENTRY = """
version: 1
exceptions:
  - ids:
      - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/a.md:generic-api-key:10
      - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/b.md:generic-api-key:12
      - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:docs/a.md:generic-api-key:10
    package: docs
    scanner: gitleaks
    reason: False positive; the same placeholder token in three deleted docs.
    replacement_considered: Deleted files in immutable history.
    usage_analysis: A placeholder; authenticates nothing.
    approved_by: "@some-reviewer"
    recheck: 2026-12-01
"""

def test_gitleaks_ids_expand_to_one_exception_each(tmp_path):
    excs = load(_write(tmp_path, GITLEAKS_IDS_ENTRY))
    assert [e.id for e in excs] == [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/a.md:generic-api-key:10",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/b.md:generic-api-key:12",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:docs/a.md:generic-api-key:10",
    ]
    assert {e.reason for e in excs} == {
        "False positive; the same placeholder token in three deleted docs."
    }
    text = gitleaksignore_text(excs)
    for e in excs:
        assert e.id in text

def test_gitleaks_ids_duplicate_within_group_is_rejected(tmp_path):
    text = GITLEAKS_IDS_ENTRY.replace(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:docs/a.md:generic-api-key:10",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/a.md:generic-api-key:10",
    )
    with pytest.raises(ExceptionFileError, match="duplicate"):
        load(_write(tmp_path, text))

def test_gitleaks_ids_duplicate_across_entries_is_rejected(tmp_path):
    single = GITLEAKS_IDS_ENTRY.split("exceptions:")[1].replace(
        "  - ids:\n      - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/a.md:generic-api-key:10\n"
        "      - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/b.md:generic-api-key:12\n"
        "      - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:docs/a.md:generic-api-key:10\n",
        "  - id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/b.md:generic-api-key:12\n",
    )
    assert "  - id: " in single
    with pytest.raises(ExceptionFileError, match="duplicate"):
        load(_write(tmp_path, GITLEAKS_IDS_ENTRY + single))

def test_gitleaks_ids_with_whitespace_is_rejected(tmp_path):
    text = GITLEAKS_IDS_ENTRY.replace(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:docs/a.md:generic-api-key:10",
        '"bbbbbbbb:docs/a b.md:generic-api-key:10"',
    )
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))

def test_ids_on_non_gitleaks_scanner_is_rejected(tmp_path):
    text = GITLEAKS_IDS_ENTRY.replace("scanner: gitleaks", "scanner: pip-audit")
    with pytest.raises(ExceptionFileError, match="only gitleaks"):
        load(_write(tmp_path, text))

def test_ids_and_id_together_is_rejected(tmp_path):
    text = GITLEAKS_IDS_ENTRY.replace(
        "  - ids:", "  - id: cccccccccccccccccccccccccccccccccccccccc:x:generic-api-key:1\n    ids:"
    )
    with pytest.raises(ExceptionFileError, match="both"):
        load(_write(tmp_path, text))

def test_empty_ids_is_rejected(tmp_path):
    text = GITLEAKS_IDS_ENTRY.replace(
        "  - ids:\n      - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/a.md:generic-api-key:10\n"
        "      - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:docs/b.md:generic-api-key:12\n"
        "      - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:docs/a.md:generic-api-key:10\n",
        "  - ids: []\n",
    )
    with pytest.raises(ExceptionFileError, match="non-empty"):
        load(_write(tmp_path, text))


# --------------------------------------------------------------------------
# Semgrep: rule ids, rule-wide exclusion, and per-file scoping.
#
# An unscoped semgrep exception becomes `--exclude-rule=<id>`, which turns the
# rule off for the whole scan. A scoped one is not excluded at all; its
# findings are waived file by file from semgrep's JSON report, so the same bug
# class in a new file still fails.
# --------------------------------------------------------------------------
import json as _json

from scripts.security_exceptions import (  # noqa: E402
    SemgrepReportError, semgrep_args, semgrep_unexcepted,
)

SHELL_RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
MD5_RULE = "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5"

SEMGREP_ENTRY = f"""
version: 1
exceptions:
  - id: {SHELL_RULE}
    package: ops-scripts
    scanner: semgrep
    reason: The command is a fixed literal; no input reaches it.
    replacement_considered: An argv list loses the pipeline the script needs.
    usage_analysis: Called once at startup with a constant string.
    approved_by: "@some-reviewer"
    recheck: 2026-12-01
"""


def _semgrep_scoped(paths=("src/ops/run.py",)):
    block = "    paths:\n" + "".join(f'      - "{p}"\n' for p in paths)
    return SEMGREP_ENTRY.replace("    recheck: 2026-12-01\n", "    recheck: 2026-12-01\n" + block)


def _sx(id_, paths=()):
    return SecurityException(
        id=id_, package="pkg", scanner="semgrep", reason="r",
        replacement_considered="rc", usage_analysis="ua",
        approved_by="@r", recheck=dt.date(2026, 12, 1), paths=tuple(paths),
    )


def _result(rule, path, severity="ERROR", line=3):
    return {"check_id": rule, "path": path, "start": {"line": line}, "extra": {"severity": severity}}


def test_semgrep_rule_id_entry_is_accepted(tmp_path):
    (exc,) = load(_write(tmp_path, SEMGREP_ENTRY))
    assert exc.scanner == "semgrep" and exc.id == SHELL_RULE and exc.paths == ()


@pytest.mark.parametrize("bad", [
    "-rule", "--config=p/none", "rule id", "rule;id", "rule$(id)", "a/b", "a:b", "rule\n",
])
def test_semgrep_ids_outside_the_strict_pattern_are_rejected(tmp_path, bad):
    # Ids are word-split into the semgrep command line: no option-shaped id,
    # no whitespace, no shell or path characters.
    text = SEMGREP_ENTRY.replace(f"id: {SHELL_RULE}", f"id: {_json.dumps(bad)}")
    with pytest.raises(ExceptionFileError, match="invalid id"):
        load(_write(tmp_path, text))


def test_semgrep_paths_are_parsed_and_repo_relative(tmp_path):
    (exc,) = load(_write(tmp_path, _semgrep_scoped(("src/a.py", "src/b.py"))))
    assert exc.paths == ("src/a.py", "src/b.py")


@pytest.mark.parametrize("bad", ["/src/a.py", "../a.py"])
def test_semgrep_absolute_and_traversing_paths_are_rejected(tmp_path, bad):
    with pytest.raises(ExceptionFileError, match="relative to the repository root"):
        load(_write(tmp_path, _semgrep_scoped((bad,))))


@pytest.mark.parametrize("bad", ["**", "src/*.py"])
def test_semgrep_paths_with_globs_are_rejected(tmp_path, bad):
    with pytest.raises(ExceptionFileError, match="glob metacharacter"):
        load(_write(tmp_path, _semgrep_scoped((bad,))))


def test_semgrep_ids_grouping_is_rejected(tmp_path):
    text = SEMGREP_ENTRY.replace(f"  - id: {SHELL_RULE}\n", f"  - ids: [{SHELL_RULE}]\n")
    with pytest.raises(ExceptionFileError, match="only gitleaks"):
        load(_write(tmp_path, text))


def test_semgrep_args_exclude_only_unscoped_semgrep_rules():
    excs = [_sx("rule.a"), _sx("rule.b", paths=["src/x.py"]), _exc("PYSEC-1"), _exc("KSV017", scanner="trivy")]
    assert semgrep_args(excs) == ["--exclude-rule=rule.a"]


def test_semgrep_args_empty_without_semgrep_entries():
    assert semgrep_args([_exc("PYSEC-1")]) == []


def test_other_emitters_ignore_semgrep_entries():
    excs = [_sx("rule.a"), _sx("rule.b", paths=["src/x.py"])]
    assert pip_audit_args(excs) == []
    assert "rule.a" not in trivyignore_text(excs)
    assert "rule.b" not in trivyignore_yaml_text(excs)
    assert "rule.a" not in gitleaksignore_text(excs)


def test_semgrep_unexcepted_reports_every_unwaived_finding():
    report = {"results": [_result(SHELL_RULE, "src/a.py"), _result(MD5_RULE, "src/b.py", "WARNING", 9)]}
    assert semgrep_unexcepted(report, []) == [f"{SHELL_RULE} at src/a.py:3", f"{MD5_RULE} at src/b.py:9"]


def test_semgrep_scoped_exception_waives_only_its_files():
    report = {"results": [_result(SHELL_RULE, "src/ops/run.py"), _result(SHELL_RULE, "src/new.py")]}
    excs = [_sx(SHELL_RULE, paths=["src/ops/run.py"])]
    assert semgrep_unexcepted(report, excs) == [f"{SHELL_RULE} at src/new.py:3"]


def test_semgrep_scoped_exception_waives_only_its_rule():
    report = {"results": [_result(MD5_RULE, "src/ops/run.py")]}
    excs = [_sx(SHELL_RULE, paths=["src/ops/run.py"])]
    assert semgrep_unexcepted(report, excs) == [f"{MD5_RULE} at src/ops/run.py:3"]


def test_semgrep_dot_slash_paths_match():
    report = {"results": [_result(SHELL_RULE, "./src/ops/run.py")]}
    assert semgrep_unexcepted(report, [_sx(SHELL_RULE, paths=["src/ops/run.py"])]) == []


def test_semgrep_info_findings_do_not_block():
    report = {"results": [_result(SHELL_RULE, "src/a.py", "INFO")]}
    assert semgrep_unexcepted(report, []) == []


@pytest.mark.parametrize("report", [{}, {"errors": []}, {"results": None}, []])
def test_semgrep_report_without_results_fails_closed(report):
    with pytest.raises(SemgrepReportError):
        semgrep_unexcepted(report, [])


def test_cli_semgrep_json_exit_codes(tmp_path, capsys):
    exc_file = _write(tmp_path, _semgrep_scoped())
    report = tmp_path / "semgrep.json"
    report.write_text(_json.dumps({"results": [_result(SHELL_RULE, "src/ops/run.py")], "errors": []}))
    assert main(["--file", str(exc_file), "--semgrep-json", str(report)]) == 0
    report.write_text(_json.dumps({"results": [_result(SHELL_RULE, "src/other.py")]}))
    assert main(["--file", str(exc_file), "--semgrep-json", str(report)]) == 1
    assert "src/other.py:3" in capsys.readouterr().err
    assert main(["--file", str(exc_file), "--semgrep-json", str(tmp_path / "missing.json")]) == 1
    report.write_text("not json")
    assert main(["--file", str(exc_file), "--semgrep-json", str(report)]) == 1


def test_cli_emits_semgrep_args_on_one_line(tmp_path, capsys):
    assert main(["--file", str(_write(tmp_path, SEMGREP_ENTRY)), "--emit-semgrep-args"]) == 0
    assert capsys.readouterr().out == f"--exclude-rule={SHELL_RULE}\n"


def test_cli_semgrep_args_empty_without_a_file(tmp_path, capsys):
    assert main(["--file", str(tmp_path / "nope.yml"), "--emit-semgrep-args"]) == 0
    assert capsys.readouterr().out == "\n"

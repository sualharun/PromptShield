from dependency_scan import (
    parse_package_json,
    parse_requirements_txt,
    scan_dependencies,
    _matches_spec,
    _parse_version,
)


def test_parse_requirements_pins_only():
    content = """
# comment
langchain==0.0.200
openai==0.28.1
requests  # unpinned — skipped
transformers==4.30.0
langchain-community>=0.0.1
"""
    parsed = parse_requirements_txt(content)
    assert parsed == {
        "langchain": "0.0.200",
        "openai": "0.28.1",
        "transformers": "4.30.0",
    }


def test_parse_package_json_exact_versions():
    content = """
    {
      "name": "app",
      "dependencies": {
        "openai": "^3.2.0",
        "langchain": "0.0.150",
        "react": "~18.2.0"
      },
      "devDependencies": {
        "typescript": "5.3.3"
      }
    }
    """
    parsed = parse_package_json(content)
    # exact pins keep their value; caret/tilde ranges resolve to the min-version
    # baseline so we can still match known-bad lower bounds.
    assert parsed.get("langchain") == "0.0.150"
    assert parsed.get("typescript") == "5.3.3"
    assert parsed.get("openai") == "3.2.0"
    assert parsed.get("react") == "18.2.0"


def test_parse_package_json_bad_json_returns_empty():
    assert parse_package_json("not-json") == {}
    assert parse_package_json("") == {}


def test_matches_spec():
    assert _matches_spec("0.0.200", "<0.0.247")
    assert not _matches_spec("0.0.247", "<0.0.247")
    assert _matches_spec("0.0.247", "<=0.0.247")
    assert _matches_spec("0.7.10", "<0.7.21")
    assert not _matches_spec("1.0.0", "<1.0.0")


def test_parse_version_handles_noise():
    assert _parse_version("1.2.3") == (1, 2, 3)
    assert _parse_version("1.2.3-rc1") == (1, 2, 3)
    assert _parse_version("bad") == (0,)


def test_scan_dependencies_flags_langchain_rce():
    findings = scan_dependencies(
        {"requirements.txt": "langchain==0.0.200\nopenai==1.3.0\n"}
    )
    assert any(
        f["cwe"] == "CWE-94" and "langchain" in f["title"] for f in findings
    )
    # openai 1.3.0 is clean — no legacy advisory
    assert not any("openai@1.3.0" in f["title"] for f in findings)


def test_scan_dependencies_dedupes_across_files():
    findings = scan_dependencies(
        {
            "requirements.txt": "transformers==4.30.0\n",
            "other/requirements.txt": "transformers==4.30.0\n",
        }
    )
    t = [f for f in findings if "transformers" in f["title"]]
    assert len(t) == 1


def test_scan_dependencies_ignores_unknown_files():
    findings = scan_dependencies({"Gemfile": "gem 'openai', '0.1.0'\n"})
    assert findings == []


def test_openai_legacy_advisory_fires():
    findings = scan_dependencies({"requirements.txt": "openai==0.28.1\n"})
    assert any("openai" in f["title"] and "1.0.0" in f["remediation"] for f in findings)


def test_supply_chain_owasp_tag_applied():
    findings = scan_dependencies({"requirements.txt": "langchain==0.0.100\n"})
    assert all(f["owasp"].startswith("LLM05") for f in findings)

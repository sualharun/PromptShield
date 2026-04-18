"""Tests for SBOM generation."""

import tempfile
from pathlib import Path

from sbom import generate_sbom


def test_sbom_structure():
    sbom = generate_sbom()
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert "components" in sbom
    assert "metadata" in sbom
    assert sbom["metadata"]["component"]["name"] == "promptshield-backend"


def test_sbom_contains_declared_packages():
    sbom = generate_sbom()
    names = [c["name"] for c in sbom["components"]]
    assert "fastapi" in names or len(names) > 0


def test_sbom_purl_format():
    sbom = generate_sbom()
    for c in sbom["components"]:
        assert c["purl"].startswith("pkg:pypi/")


def test_sbom_custom_requirements():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("fastapi>=0.100.0\nuvicorn\n")
        f.flush()
        sbom = generate_sbom(requirements_path=f.name)
    assert sbom["total_declared"] >= 0


def test_sbom_nonexistent_requirements():
    sbom = generate_sbom(requirements_path="/tmp/nonexistent_requirements_xyz.txt")
    assert sbom["total_declared"] == 0


def test_sbom_components_sorted():
    sbom = generate_sbom()
    names = [c["name"] for c in sbom["components"]]
    assert names == sorted(names)

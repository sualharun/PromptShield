"""Dependency CVE scanner for LLM SDKs.

Scope is narrow on purpose: we only flag known-bad versions of packages that
matter for PromptShield's threat model (LLM provider SDKs, prompt-templating
libraries). No network calls; the knowledge base is an in-repo curated list
documented at the top of `KNOWN_CVES`. Callers pass raw file contents of
`requirements.txt` and/or `package.json`; we return a list of findings
matching the project's Finding shape (type/severity/title/.../remediation).

The intentional non-goal: this is not a general SCA tool. It won't replace
Snyk or Dependabot. It flags a hand-curated set of LLM-adjacent issues so the
PR report can surface supply-chain risk alongside prompt risk.
"""

import json
import re
from typing import Dict, List, Tuple


# curated list: (ecosystem, package, vulnerable_spec, cve_or_advisory,
#                severity, title, description, remediation, cwe)
# Specs use a tiny subset of semver: "<X.Y.Z", "<=X.Y.Z", "==X.Y.Z", or
# "<X.Y.Z,>=A.B.C" (comma = AND). No caret/tilde — keep it honest.
KNOWN_CVES: List[Tuple[str, str, str, str, str, str, str, str, str]] = [
    (
        "pypi",
        "langchain",
        "<0.0.247",
        "CVE-2023-36258",
        "critical",
        "langchain < 0.0.247 arbitrary code execution via PALChain",
        "PALChain and related chains in langchain before 0.0.247 allow arbitrary "
        "Python execution when the model output is fed back as code.",
        "Upgrade langchain to >= 0.0.247 and avoid PALChain-style eval-like chains.",
        "CWE-94",
    ),
    (
        "pypi",
        "langchain",
        "<0.0.312",
        "CVE-2023-44467",
        "high",
        "langchain < 0.0.312 SSRF via SQLDatabaseChain",
        "SQLDatabaseChain in langchain before 0.0.312 can be abused to reach "
        "internal services when the database URL is user-controlled.",
        "Upgrade langchain to >= 0.0.312.",
        "CWE-918",
    ),
    (
        "pypi",
        "llama-index",
        "<0.7.21",
        "CVE-2023-39662",
        "high",
        "llama-index < 0.7.21 unsafe deserialization",
        "Older llama-index versions unpickle untrusted data on load.",
        "Upgrade to llama-index >= 0.7.21.",
        "CWE-502",
    ),
    (
        "pypi",
        "openai",
        "<1.0.0",
        "PS-ADVISORY-2024-OPENAI-LEGACY",
        "medium",
        "openai < 1.0.0 uses deprecated client API",
        "Pre-1.0 openai SDK is deprecated and no longer receives security fixes.",
        "Migrate to the openai v1 client (openai>=1.0.0).",
        "CWE-1104",
    ),
    (
        "pypi",
        "transformers",
        "<4.38.0",
        "CVE-2024-3568",
        "high",
        "transformers < 4.38.0 deserialization vulnerability",
        "HuggingFace transformers before 4.38.0 unpickles remote model weights "
        "which can execute arbitrary code.",
        "Upgrade transformers to >= 4.38.0 and prefer safetensors.",
        "CWE-502",
    ),
    (
        "npm",
        "langchain",
        "<0.0.183",
        "CVE-2023-44467",
        "high",
        "langchain (npm) < 0.0.183 SSRF advisory",
        "Older langchain npm versions have the same SSRF issue as their Python "
        "counterpart.",
        "Upgrade langchain to >= 0.0.183.",
        "CWE-918",
    ),
    (
        "npm",
        "openai",
        "<4.0.0",
        "PS-ADVISORY-2024-OPENAI-NODE-LEGACY",
        "medium",
        "openai (npm) < 4.0.0 legacy client",
        "Pre-4.0 openai node SDK is deprecated.",
        "Upgrade openai to >= 4.0.0.",
        "CWE-1104",
    ),
]


def _parse_version(v: str) -> Tuple[int, ...]:
    # drop pre-release / build suffix (1.2.3-rc1, 1.2.3+build)
    head = re.split(r"[-+]", v, maxsplit=1)[0]
    cleaned = re.sub(r"[^0-9.]", "", head).strip(".")
    if not cleaned:
        return (0,)
    parts = [int(x) for x in cleaned.split(".") if x.isdigit()]
    return tuple(parts) or (0,)


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    pad = max(len(a), len(b))
    a2 = a + (0,) * (pad - len(a))
    b2 = b + (0,) * (pad - len(b))
    if a2 < b2:
        return -1
    if a2 > b2:
        return 1
    return 0


def _matches_spec(installed: str, spec: str) -> bool:
    """Return True if `installed` falls inside `spec`. Spec is comma-AND of
    simple constraints (<, <=, ==, >, >=, !=)."""
    installed_t = _parse_version(installed)
    for piece in spec.split(","):
        piece = piece.strip()
        m = re.match(r"^(<=|>=|==|!=|<|>)(.+)$", piece)
        if not m:
            return False
        op, rhs = m.group(1), m.group(2).strip()
        cmp = _cmp(installed_t, _parse_version(rhs))
        if op == "<" and not cmp < 0:
            return False
        if op == "<=" and not cmp <= 0:
            return False
        if op == ">" and not cmp > 0:
            return False
        if op == ">=" and not cmp >= 0:
            return False
        if op == "==" and cmp != 0:
            return False
        if op == "!=" and cmp == 0:
            return False
    return True


def parse_requirements_txt(content: str) -> Dict[str, str]:
    """Return {package_name_lower: version_string} for pinned entries.
    Lines without an explicit version ("requests", "package[extra]") are skipped
    because we can't honestly flag them."""
    out: Dict[str, str] = {}
    for raw in (content or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]+\])?\s*==\s*([0-9A-Za-z.\-+!]+)", line)
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out


def parse_package_json(content: str) -> Dict[str, str]:
    """Return {package: version} from dependencies + devDependencies. Skips
    ranges we can't honestly resolve to a single version."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return {}
    out: Dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for pkg, spec in section.items():
            if not isinstance(spec, str):
                continue
            clean = spec.strip()
            m = re.match(r"^[\^~>=<]*\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]+)?)$", clean)
            if m:
                out[pkg.lower()] = m.group(1)
    return out


def _finding(advisory: Tuple, installed: str, filename: str) -> Dict:
    ecosystem, pkg, spec, cve, sev, title, desc, remediation, cwe = advisory
    return {
        "type": "VULNERABLE_DEPENDENCY",
        "severity": sev,
        "title": f"{pkg}@{installed}: {title}",
        "description": f"{desc} (from {filename})",
        "remediation": remediation,
        "source": "static",
        "confidence": 0.95,
        "evidence": f"{pkg}=={installed} ({cve})",
        "cwe": cwe,
        "owasp": "LLM05: Supply Chain Vulnerabilities",
    }


def scan_dependencies(files: Dict[str, str]) -> List[Dict]:
    """Scan a mapping of {filename: content}. Returns a de-duplicated list of
    findings. Unknown filenames are ignored."""
    findings: List[Dict] = []
    seen: set = set()
    for name, content in (files or {}).items():
        lower = name.lower()
        if lower.endswith("requirements.txt"):
            parsed = parse_requirements_txt(content)
            ecosystem = "pypi"
        elif lower.endswith("package.json"):
            parsed = parse_package_json(content)
            ecosystem = "npm"
        else:
            continue
        for pkg, version in parsed.items():
            for adv in KNOWN_CVES:
                if adv[0] != ecosystem or adv[1] != pkg:
                    continue
                if _matches_spec(version, adv[2]):
                    key = (ecosystem, pkg, version, adv[3])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_finding(adv, version, name))
    return findings

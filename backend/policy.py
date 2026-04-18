"""Policy-as-code: parse a `.promptshield.yml` file from the repo root and
apply it to a scan result.

The shipped policy grammar is intentionally narrow so we don't over-promise:

    # .promptshield.yml
    min_score: 70           # pass if risk_score < min_score; default from settings
    block_if:
      critical: 1           # any count >= N of the given severity blocks
      high: 3
    ignore:
      types:
        - DATA_LEAKAGE      # drop findings with this type before scoring
      cwes:
        - CWE-359           # drop findings with this cwe
    severity_overrides:
      DATA_LEAKAGE: low     # demote any DATA_LEAKAGE finding to 'low'

Every key is optional. Unknown keys are ignored with a warning in the decision
reasons — we don't fail the PR over an unrecognized field because that would
surprise users on policy upgrades.
"""

from typing import Any, Dict, List, Optional, Tuple

import yaml

from config import settings
from scanner import calculate_risk_score


_SEVERITIES = {"critical", "high", "medium", "low"}
_KNOWN_TOP_KEYS = {"min_score", "block_if", "ignore", "severity_overrides"}


class PolicyError(ValueError):
    """Raised when a policy file is syntactically malformed."""


def default_policy() -> Dict[str, Any]:
    return {
        "min_score": settings.RISK_GATE_THRESHOLD,
        "block_if": {},
        "ignore": {"types": [], "cwes": []},
        "severity_overrides": {},
    }


def parse_policy(yaml_text: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Parse YAML into a validated policy dict. Returns (policy, warnings).

    Raises `PolicyError` on syntactically invalid YAML or wrong top-level type.
    Unknown or malformed fields are coerced or dropped with a warning instead
    of hard-failing, so authors get feedback without their PRs blocking on
    typos.
    """
    policy = default_policy()
    warnings: List[str] = []

    if not yaml_text or not yaml_text.strip():
        return policy, warnings

    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML: {e}") from e

    if data is None:
        return policy, warnings
    if not isinstance(data, dict):
        raise PolicyError("top-level policy must be a mapping")

    for key in data.keys():
        if key not in _KNOWN_TOP_KEYS:
            warnings.append(f"unknown key '{key}' ignored")

    # min_score
    if "min_score" in data:
        try:
            policy["min_score"] = int(data["min_score"])
        except (TypeError, ValueError):
            warnings.append("min_score must be an integer; using default")

    # block_if: {severity: count}
    block_if_raw = data.get("block_if") or {}
    if not isinstance(block_if_raw, dict):
        warnings.append("block_if must be a mapping; ignored")
        block_if_raw = {}
    block_if: Dict[str, int] = {}
    for sev, count in block_if_raw.items():
        sev_l = str(sev).lower()
        if sev_l not in _SEVERITIES:
            warnings.append(f"block_if.{sev}: unknown severity; ignored")
            continue
        try:
            block_if[sev_l] = max(1, int(count))
        except (TypeError, ValueError):
            warnings.append(f"block_if.{sev}: count must be an integer; ignored")
    policy["block_if"] = block_if

    # ignore: {types: [...], cwes: [...]}
    ignore_raw = data.get("ignore") or {}
    if not isinstance(ignore_raw, dict):
        warnings.append("ignore must be a mapping; ignored")
        ignore_raw = {}
    types = ignore_raw.get("types") or []
    cwes = ignore_raw.get("cwes") or []
    if not isinstance(types, list):
        warnings.append("ignore.types must be a list; ignored")
        types = []
    if not isinstance(cwes, list):
        warnings.append("ignore.cwes must be a list; ignored")
        cwes = []
    policy["ignore"] = {
        "types": [str(t) for t in types],
        "cwes": [str(c) for c in cwes],
    }

    # severity_overrides: {type: severity}
    overrides_raw = data.get("severity_overrides") or {}
    if not isinstance(overrides_raw, dict):
        warnings.append("severity_overrides must be a mapping; ignored")
        overrides_raw = {}
    overrides: Dict[str, str] = {}
    for ftype, sev in overrides_raw.items():
        sev_l = str(sev).lower()
        if sev_l not in _SEVERITIES:
            warnings.append(
                f"severity_overrides.{ftype}: '{sev}' is not a valid severity; ignored"
            )
            continue
        overrides[str(ftype)] = sev_l
    policy["severity_overrides"] = overrides

    return policy, warnings


def apply_policy(
    policy: Dict[str, Any],
    findings: List[Dict[str, Any]],
    risk_score: int,
) -> Dict[str, Any]:
    """Apply a parsed policy to a scan result.

    Returns a dict with:
      - effective_findings: findings after ignore + severity_overrides
      - effective_score: recomputed risk score against effective_findings
      - passed: bool (True if nothing trips the gate)
      - reasons: human-readable list of pass/fail drivers
      - counts: severity distribution of effective_findings
    """
    ignore = policy.get("ignore") or {}
    ignore_types = set(ignore.get("types") or [])
    ignore_cwes = set(ignore.get("cwes") or [])
    overrides = policy.get("severity_overrides") or {}

    effective: List[Dict[str, Any]] = []
    for f in findings:
        if f.get("type") in ignore_types:
            continue
        if f.get("cwe") in ignore_cwes:
            continue
        copy = dict(f)
        override = overrides.get(copy.get("type"))
        if override:
            copy["severity"] = override
        effective.append(copy)

    effective_score = (
        calculate_risk_score(effective) if effective != findings else int(risk_score)
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in effective:
        sev = (f.get("severity") or "low").lower()
        if sev in counts:
            counts[sev] += 1

    reasons: List[str] = []
    passed = True

    min_score = int(policy.get("min_score", settings.RISK_GATE_THRESHOLD))
    if effective_score >= min_score:
        reasons.append(
            f"risk score {effective_score} >= min_score {min_score}"
        )
        passed = False
    else:
        reasons.append(
            f"risk score {effective_score} < min_score {min_score}"
        )

    for sev, threshold in (policy.get("block_if") or {}).items():
        actual = counts.get(sev, 0)
        if actual >= threshold:
            reasons.append(
                f"block_if.{sev}: {actual} >= {threshold}"
            )
            passed = False

    return {
        "passed": passed,
        "effective_score": int(effective_score),
        "effective_findings": effective,
        "counts": counts,
        "reasons": reasons,
        "min_score": min_score,
    }


EXAMPLE_POLICY_YAML = """# .promptshield.yml — drop this file in your repo root to customize gating.
# Every field is optional.

min_score: 70            # block the PR when risk_score >= min_score

block_if:
  critical: 1            # any critical finding blocks
  high: 3                # 3+ highs blocks

ignore:
  types:
    - DATA_LEAKAGE       # don't count these finding types
  cwes: []

severity_overrides:
  OVERLY_PERMISSIVE: low # demote this type to 'low'
"""


def render_policy_summary(decision: Dict[str, Any]) -> str:
    """Short markdown block for the Check Run summary."""
    verdict = "✅ policy passed" if decision["passed"] else "❌ policy blocked"
    lines = [
        "",
        f"**Policy**: {verdict}",
        "",
        "| Check | Result |",
        "| --- | --- |",
    ]
    for r in decision.get("reasons") or []:
        lines.append(f"| {r} | — |")
    return "\n".join(lines)

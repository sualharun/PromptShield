"""Finding-suppression helpers — Mongo-backed (v0.4 port).

Signature is a stable, short hash of (type, title, evidence-prefix) so the
same finding recurring across scans can be matched. Repo scoping keeps
suppressions from leaking across unrelated projects.
"""
from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional, Set

import repositories as repos


def finding_signature(finding: Dict) -> str:
    parts = [
        str(finding.get("type") or ""),
        str(finding.get("title") or ""),
        (finding.get("evidence") or "")[:40],
    ]
    raw = "\x1f".join(parts).encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]


def suppressed_signatures(
    _db_unused=None,
    repo_full_name: Optional[str] = None,
) -> Set[str]:
    """Set of suppressed signatures applicable to `repo_full_name`.

    First positional arg is unused (legacy `db` slot). Callers may omit it.
    """
    return repos.suppressed_signatures_set(repo_full_name)


def annotate(
    findings: Iterable[Dict], suppressed: Set[str]
) -> List[Dict]:
    out: List[Dict] = []
    for f in findings:
        copy = dict(f)
        sig = finding_signature(f)
        copy["signature"] = sig
        copy["suppressed"] = sig in suppressed
        out.append(copy)
    return out

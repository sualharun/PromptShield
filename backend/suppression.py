"""Finding-suppression helpers.

Signature is a stable, short hash of (type, title, evidence-prefix) so the same
finding recurring across scans can be matched. Repo scoping keeps suppressions
from leaking across unrelated projects.
"""

import hashlib
from typing import Dict, Iterable, List, Optional, Set

from sqlalchemy.orm import Session

from database import FindingSuppression


def finding_signature(finding: Dict) -> str:
    parts = [
        str(finding.get("type") or ""),
        str(finding.get("title") or ""),
        (finding.get("evidence") or "")[:40],
    ]
    raw = "\x1f".join(parts).encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]


def suppressed_signatures(
    db: Session, repo_full_name: Optional[str]
) -> Set[str]:
    q = db.query(FindingSuppression.signature)
    if repo_full_name:
        q = q.filter(
            (FindingSuppression.repo_full_name == repo_full_name)
            | (FindingSuppression.repo_full_name.is_(None))
        )
    else:
        q = q.filter(FindingSuppression.repo_full_name.is_(None))
    return {row[0] for row in q.all()}


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

"""Seed demo scan data for dependency risk graph showcase.

v0.4: Mongo-backed. Inserts directly into the `scans` collection so the demo
flow exercises the same code path as production.

Run:
  cd backend && python seed_demo.py
"""
from __future__ import annotations

from datetime import datetime, timezone

import repositories as repos


def create_demo_risk_graph_pr() -> str:
    """Create a safe-looking PR demo that hides a risky dependency chain.

    Returns the inserted scan's Mongo `_id` as a string.
    """
    findings = [
        {
            "type": "VULNERABLE_DEPENDENCY",
            "severity": "high",
            "title": "Dependency introduces hidden vulnerable chain",
            "description": "PR adds an image package that pulls transitive vulnerable libraries.",
            "line_number": None,
            "remediation": "Pin patched versions and audit transitive deps before merge.",
            "source": "ai",
            "confidence": 0.88,
            "evidence": "sharp==10.0.0 -> libvips==8.9.0 -> CVE chain",
            "cwe": "CWE-1104",
            "owasp": "A06",
            "signature": "demo-sharp-risk-chain",
        }
    ]

    graph_analysis = {
        "nodes": [
            {
                "id": "user:developer123",
                "name": "developer123",
                "type": "contributor",
                "risk_score": 5,
            },
            {
                "id": "pkg:node/sharp@10.0.0",
                "name": "sharp",
                "version": "10.0.0",
                "type": "dependency",
                "risk_score": 75,
                "ecosystem": "node",
                "vulnerabilities": [
                    {"cve_id": "CVE-2024-1234", "severity": "HIGH"},
                    {"cve_id": "CVE-2024-1235", "severity": "HIGH"},
                ],
            },
            {
                "id": "pkg:node/libvips@8.9.0",
                "name": "libvips",
                "version": "8.9.0",
                "type": "dependency",
                "risk_score": 85,
                "ecosystem": "node",
                "vulnerabilities": [
                    {"cve_id": "CVE-2024-2345", "severity": "CRITICAL"},
                    {"cve_id": "CVE-2024-2346", "severity": "HIGH"},
                    {"cve_id": "CVE-2024-2347", "severity": "HIGH"},
                ],
            },
            {
                "id": "maintainer:maintainer-x",
                "name": "maintainer-x",
                "type": "maintainer",
                "risk_score": 70,
                "risk_level": "HIGH",
                "exploit_history": "Flagged in prior supply-chain incident for delayed security patches.",
            },
            {
                "id": "vulnrepo:libvips-upstream",
                "name": "libvips-upstream",
                "type": "vulnerable_repo",
                "risk_score": 90,
                "severity": "CRITICAL",
                "cve_ids": ["CVE-2024-2345", "CVE-2024-2346", "CVE-2024-2347"],
            },
        ],
        "edges": [
            {
                "source": "user:developer123",
                "target": "pkg:node/sharp@10.0.0",
                "type": "introduces",
                "risk": "high",
            },
            {
                "source": "pkg:node/sharp@10.0.0",
                "target": "pkg:node/libvips@8.9.0",
                "type": "depends_on",
                "risk": "critical",
            },
            {
                "source": "pkg:node/libvips@8.9.0",
                "target": "maintainer:maintainer-x",
                "type": "maintained_by",
                "risk": "high",
            },
            {
                "source": "pkg:node/libvips@8.9.0",
                "target": "vulnrepo:libvips-upstream",
                "type": "connected_to_vulnerable_repo",
                "risk": "critical",
            },
        ],
        "overall_risk_score": 78,
        "threat_level": "HIGH",
        "blast_radius": {
            "affected_count": 2,
            "affected_packages": ["sharp", "libvips"],
            "description": "This PR introduces 2 dependencies with hidden CVE propagation risk.",
        },
        "narrative": (
            "[HIGH] This PR appears safe (image resizing) but introduces sharp@10.0.0, "
            "which links to libvips with multiple high and critical CVEs. "
            "Recommendation: upgrade to sharp@11+ and verify patched transitive versions."
        ),
        "risk_chains": [
            {
                "path": [
                    "PR #42",
                    "developer123",
                    "sharp",
                    "libvips",
                    "libvips-upstream",
                ],
                "risk_score": 90,
                "terminal_type": "vulnerable_repo",
            }
        ],
        "insights": {
            "risky_dependency_count": 2,
            "maintainer_flags": 1,
            "connected_vulnerable_repos": 1,
        },
    }

    doc = repos.insert_scan(
        {
            "input_text": '{"dependencies":{"sharp":"^10.0.0"}}',
            "risk_score": 78,
            "findings": findings,
            "counts": {"static": 0, "ai": 1, "total": 1},
            "source": "github",
            "github": {
                "repo_full_name": "demo/image-app",
                "pr_number": 42,
                "commit_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "pr_title": "Add image resizing with sharp",
                "pr_url": "https://github.com/demo/image-app/pull/42",
                "author_login": "developer123",
            },
            "llm_targets": [],
            "graph_analysis": graph_analysis,
            "created_at": datetime.now(timezone.utc),
        }
    )
    return str(doc["_id"])


if __name__ == "__main__":
    sid = create_demo_risk_graph_pr()
    print(f"Created demo risk graph scan id={sid}")

"""Seed demo scan data for dependency risk graph showcase.

Run:
  cd backend && /Users/sualharun/workspace/PromptShield/.venv/bin/python seed_demo.py
"""

import json

from database import Maintainer, Scan, SessionLocal, VulnerableRepo, init_db


def create_demo_risk_graph_pr() -> int:
    """Create a safe-looking PR demo that hides a risky dependency chain."""
    db = SessionLocal()
    try:
        # Seed graph intelligence sources used by multi-hop enrichment.
        if not db.query(Maintainer).filter(Maintainer.name == "maintainer-x").first():
            db.add(
                Maintainer(
                    name="maintainer-x",
                    repositories_json=json.dumps(["sharp", "libvips"]),
                    exploit_history="Flagged in prior supply-chain incident for delayed security patches.",
                    risk_level="HIGH",
                )
            )

        if not db.query(VulnerableRepo).filter(VulnerableRepo.name == "libvips-upstream").first():
            db.add(
                VulnerableRepo(
                    name="libvips-upstream",
                    cve_ids_json=json.dumps(["CVE-2024-2345", "CVE-2024-2346", "CVE-2024-2347"]),
                    severity="CRITICAL",
                    description="Upstream repo with unresolved image parsing vulnerabilities.",
                    remediation="Pin patched upstream dependency or switch to hardened variant.",
                )
            )
        db.flush()

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

        scan = Scan(
            input_text='{"dependencies":{"sharp":"^10.0.0"}}',
            risk_score=78,
            findings_json=json.dumps(findings),
            static_count=0,
            ai_count=1,
            total_count=1,
            source="github",
            repo_full_name="demo/image-app",
            pr_number=42,
            commit_sha="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            pr_title="Add image resizing with sharp",
            pr_url="https://github.com/demo/image-app/pull/42",
            author_login="developer123",
            graph_analysis_json=json.dumps(graph_analysis),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan.id
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    scan_id = create_demo_risk_graph_pr()
    print(f"Created demo risk graph scan id={scan_id}")

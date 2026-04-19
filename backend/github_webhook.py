"""GitHub App webhook handler.

Flow on a `pull_request` event (opened/synchronize/reopened):
    1. Open an in-progress Check Run on the PR head SHA.
    2. List PR files; for each text file under MAX_INPUT_CHARS:
         a. Fetch its content at the head SHA.
         b. Run static_scan + ai_scan in parallel (same pipeline as the web flow).
         c. Filter findings to lines actually added in the diff.
    3. Aggregate findings, compute risk score, persist a single Scan row
       (source="github") so it surfaces in the dashboard.
    4. Post a PR review with one inline comment per finding.
    5. Update the Check Run with a pass/fail conclusion based on the threshold.
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import httpx
from fastapi import APIRouter, HTTPException, Request

from ai_analyzer import ai_scan
from config import settings
import repositories as repos
from diff_utils import filter_findings_to_lines, parse_added_lines
from github_app import GitHubClient, get_installation_token, sign_app_jwt, verify_webhook_signature
from scanner import (
    calculate_risk_score,
    detect_language_from_filename,
    merge_findings,
    static_scan,
)
from score_breakdown import compute_breakdown, render_breakdown_markdown
from llm_target import detect_llm_targets
from dataflow import scan_dataflow
from dependency_scan import scan_dependencies
from notifications import notify_gate_failure
from policy import PolicyError, apply_policy, parse_policy, render_policy_summary
from mongo import C, col

logger = logging.getLogger("promptshield.webhook")

router = APIRouter(prefix="/api/github", tags=["github"])

ACTIONS_TO_HANDLE = {"opened", "synchronize", "reopened"}

# Patched by tests to inject an httpx.MockTransport.
def _make_client(token: str) -> GitHubClient:
    return GitHubClient(token)


SEVERITY_LABELS = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "🔵 LOW",
}


def _comment_body(f: Dict[str, Any]) -> str:
    sev = SEVERITY_LABELS.get(f.get("severity", "low"), "LOW")
    title = f.get("title") or "Vulnerability"
    desc = f.get("description") or ""
    fix = f.get("remediation") or ""
    confidence = f.get("confidence")
    cwe = f.get("cwe") or ""
    owasp = f.get("owasp") or ""
    refs = " · ".join(x for x in (cwe, owasp.split(":")[0] if owasp else "") if x)
    conf_line = (
        f"\n\n_Detector confidence: {int(round(float(confidence) * 100))}%_"
        if isinstance(confidence, (int, float))
        else ""
    )
    refs_line = f"\n\n_{refs}_" if refs else ""
    return (
        f"**{sev} · `{f.get('type', 'UNKNOWN')}`** — {title}\n\n"
        f"{desc}\n\n**Fix:** {fix}"
        f"{conf_line}{refs_line}\n\n"
        f"<sub>Posted by PromptShield · prompt-security review bot</sub>"
    )


def _scan_one_file(file_obj: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
    language = detect_language_from_filename(file_obj.get("filename") or "")
    with ThreadPoolExecutor(max_workers=3) as pool:
        s_future = pool.submit(static_scan, content, language)
        a_future = pool.submit(ai_scan, content)
        df_future = pool.submit(scan_dataflow, content)
        static_results = s_future.result()
        ai_results = a_future.result()
        dataflow_results = df_future.result()
    merged = merge_findings(static_results + dataflow_results, ai_results)
    added = parse_added_lines(file_obj.get("patch"))
    on_diff = filter_findings_to_lines(merged, added)
    for f in on_diff:
        f["path"] = file_obj["filename"]
        f["language"] = language
    return on_diff


def _is_text_file(filename: str) -> bool:
    binary_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
        ".zip", ".tar", ".gz", ".whl", ".jar", ".woff", ".woff2",
        ".ttf", ".otf", ".mp4", ".mp3", ".mov",
    }
    lower = filename.lower()
    return not any(lower.endswith(ext) for ext in binary_exts)


def _build_check_payload(
    head_sha: str,
    score: int,
    counts: Dict[str, int],
    files_scanned: int,
    scan_id: int | None,
    threshold: int,
    breakdown: Dict[str, Any] | None = None,
    policy_decision: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    # If a policy is active, its verdict drives the conclusion; fall back to the
    # global threshold when no policy file was present.
    if policy_decision is not None:
        failed = not policy_decision.get("passed", True)
    else:
        failed = score >= threshold
    conclusion = "failure" if failed else "success"
    title = f"Risk score: {score}/100"
    detail_url = (
        f"{settings.DASHBOARD_BASE_URL}/?scan={scan_id}" if scan_id else None
    )
    summary_lines = [
        f"**PromptShield** scanned {files_scanned} changed file(s).",
        "",
        f"| Severity | Count |",
        f"| --- | --- |",
        f"| Critical | {counts.get('critical', 0)} |",
        f"| High | {counts.get('high', 0)} |",
        f"| Medium | {counts.get('medium', 0)} |",
        f"| Low | {counts.get('low', 0)} |",
        "",
        f"Threshold: **{threshold}**.  "
        + (
            f"❌ Risk score **{score}** meets or exceeds the gate."
            if failed
            else f"✅ Risk score **{score}** is below the gate."
        ),
    ]
    breakdown_md = render_breakdown_markdown(breakdown) if breakdown else ""
    if breakdown_md:
        summary_lines.append(breakdown_md)
    if policy_decision is not None:
        summary_lines.append(render_policy_summary(policy_decision))
    if detail_url:
        summary_lines.append("")
        summary_lines.append(f"[Open full report in PromptShield]({detail_url})")
    payload = {
        "name": "PromptShield",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": "\n".join(summary_lines),
        },
    }
    if detail_url:
        payload["details_url"] = detail_url
    return payload


def _process_pr(payload: Dict[str, Any]) -> Tuple[int, Dict[str, int], int | None]:
    """Runs the full pipeline. Returns (score, severity_counts, scan_id)."""
    pr = payload["pull_request"]
    repo = payload["repository"]
    installation_id = payload["installation"]["id"]
    owner = repo["owner"]["login"]
    name = repo["name"]
    full = repo["full_name"]
    number = pr["number"]
    head_sha = pr["head"]["sha"]
    pr_title = pr.get("title")
    pr_url = pr.get("html_url")
    author_login = (pr.get("user") or {}).get("login")

    token = get_installation_token(installation_id)
    with _make_client(token) as gh:
        check = gh.create_check_run(
            owner,
            name,
            {
                "name": "PromptShield",
                "head_sha": head_sha,
                "status": "in_progress",
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        )
        check_id = check["id"]

        all_findings: List[Dict[str, Any]] = []
        files_scanned = 0
        target_set: set[str] = set()
        dep_files: Dict[str, str] = {}
        try:
            files = gh.list_pr_files(owner, name, number)
            for f in files:
                filename = f.get("filename") or ""
                if not f.get("patch"):
                    continue
                if not _is_text_file(filename):
                    continue
                if (f.get("changes") or 0) == 0:
                    continue
                content = gh.get_file_content(owner, name, filename, head_sha)
                if not content or len(content) > settings.MAX_INPUT_CHARS:
                    continue
                files_scanned += 1
                all_findings.extend(_scan_one_file(f, content))
                target_set.update(detect_llm_targets(content))
                lower = filename.lower()
                if lower.endswith("requirements.txt") or lower.endswith("package.json"):
                    dep_files[filename] = content

            if dep_files:
                all_findings.extend(scan_dependencies(dep_files))

            score = calculate_risk_score(all_findings)
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for fnd in all_findings:
                sev = (fnd.get("severity") or "low").lower()
                if sev in counts:
                    counts[sev] += 1

            # Fetch .promptshield.yml from the head commit. Absent file => no policy.
            policy_decision = None
            try:
                policy_text = gh.get_file_content(
                    owner, name, ".promptshield.yml", head_sha
                )
                if policy_text:
                    policy, _warnings = parse_policy(policy_text)
                    policy_decision = apply_policy(policy, all_findings, score)
                    # Policy may drop findings / rewrite severities; use those for the Check Run.
                    counts = policy_decision["counts"]
                    score = policy_decision["effective_score"]
            except PolicyError as e:
                logger.warning(
                    "invalid .promptshield.yml; ignoring",
                    extra={"event": "policy_invalid", "repo": full, "error": str(e)},
                )
                policy_decision = None
            except Exception:
                logger.exception(
                    "policy fetch failed",
                    extra={"event": "policy_fetch_error", "repo": full},
                )
                policy_decision = None

            static_count = sum(
                1 for x in all_findings if x.get("source") != "ai"
            )
            ai_count = sum(1 for x in all_findings if x.get("source") == "ai")
            breakdown = compute_breakdown(all_findings, static_count, ai_count)

            llm_targets_list = sorted(target_set) if target_set else []

            scan_doc = repos.insert_scan(
                {
                    "input_text": (
                        f"PR #{number} in {full} · {files_scanned} file(s) · "
                        f"{head_sha[:7]}"
                    ),
                    "risk_score": score,
                    "findings": all_findings,
                    "counts": {
                        "static": static_count,
                        "ai": ai_count,
                        "total": len(all_findings),
                    },
                    "source": "github",
                    "github": {
                        "repo_full_name": full,
                        "pr_number": number,
                        "commit_sha": head_sha,
                        "pr_title": pr_title,
                        "pr_url": pr_url,
                        "author_login": author_login,
                    },
                    "score_breakdown": breakdown,
                    "llm_targets": llm_targets_list,
                }
            )
            scan_id = str(scan_doc["_id"])

            col(C.AUDIT_LOGS).insert_one(
                {
                    "actor": "github-app",
                    "action": "PR_SCAN_COMPLETED",
                    "source": "github",
                    "repo_full_name": full,
                    "pr_number": number,
                    "scan_id": scan_id,
                    "details": {
                        "risk_score": score,
                        "files_scanned": files_scanned,
                        "findings": len(all_findings),
                    },
                    "created_at": datetime.now(timezone.utc),
                }
            )

            comments = [
                {
                    "path": f["path"],
                    "line": int(f["line_number"]),
                    "side": "RIGHT",
                    "body": _comment_body(f),
                }
                for f in all_findings
                if f.get("path") and isinstance(f.get("line_number"), int)
            ]
            if comments:
                review_body = (
                    f"PromptShield found **{len(all_findings)} finding(s)** "
                    f"in this PR (risk score **{score}/100**)."
                )
                gh.create_review(
                    owner, name, number, head_sha, review_body, comments, "COMMENT"
                )

            gh.update_check_run(
                owner,
                name,
                check_id,
                _build_check_payload(
                    head_sha,
                    score,
                    counts,
                    files_scanned,
                    scan_id,
                    settings.RISK_GATE_THRESHOLD,
                    breakdown,
                    policy_decision,
                ),
            )

            # Gate decision: policy wins if present, else threshold.
            gate_failed = (
                (not policy_decision["passed"])
                if policy_decision
                else score >= settings.RISK_GATE_THRESHOLD
            )
            if gate_failed:
                notify_gate_failure(
                    {
                        "repo_full_name": full,
                        "pr_number": number,
                        "pr_title": pr_title,
                        "pr_url": pr_url,
                        "risk_score": score,
                        "threshold": settings.RISK_GATE_THRESHOLD,
                        "counts": counts,
                    }
                )
            logger.info(
                "github PR scan complete",
                extra={
                    "event": "github_webhook",
                    "repo": full,
                    "pr": number,
                    "score": score,
                },
            )
            return score, counts, scan_id
        except Exception:
            logger.exception(
                "github PR scan failed",
                extra={"event": "github_webhook_error", "repo": full, "pr": number},
            )
            try:
                gh.update_check_run(
                    owner,
                    name,
                    check_id,
                    {
                        "name": "PromptShield",
                        "head_sha": head_sha,
                        "status": "completed",
                        "conclusion": "neutral",
                        "output": {
                            "title": "PromptShield error",
                            "summary": "Scan failed; see backend logs.",
                        },
                    },
                )
            except Exception:
                pass
            raise


def _scan_pr_for_sync(
    owner: str, repo_name: str, full: str, pr: Dict[str, Any], token: str
) -> Dict[str, Any] | None:
    """Scan a single PR without creating check runs or posting review comments.
    Used by the sync endpoint to populate the dashboard from existing PRs."""
    number = pr["number"]
    head_sha = pr["head"]["sha"]
    pr_title = pr.get("title")
    pr_url = pr.get("html_url")
    author_login = (pr.get("user") or {}).get("login")

    # Skip if already scanned at this commit
    existing = col(C.SCANS).find_one(
        {"source": "github", "github.repo_full_name": full, "github.pr_number": number, "github.commit_sha": head_sha}
    )
    if existing:
        return None

    with _make_client(token) as gh:
        all_findings: List[Dict[str, Any]] = []
        files_scanned = 0
        target_set: set[str] = set()
        try:
            files = gh.list_pr_files(owner, repo_name, number)
            for f in files:
                filename = f.get("filename") or ""
                if not f.get("patch"):
                    continue
                if not _is_text_file(filename):
                    continue
                if (f.get("changes") or 0) == 0:
                    continue
                content = gh.get_file_content(owner, repo_name, filename, head_sha)
                if not content or len(content) > settings.MAX_INPUT_CHARS:
                    continue
                files_scanned += 1
                all_findings.extend(_scan_one_file(f, content))
                target_set.update(detect_llm_targets(content))

            score = calculate_risk_score(all_findings)
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for fnd in all_findings:
                sev = (fnd.get("severity") or "low").lower()
                if sev in counts:
                    counts[sev] += 1

            static_count = sum(1 for x in all_findings if x.get("source") != "ai")
            ai_count = sum(1 for x in all_findings if x.get("source") == "ai")
            breakdown = compute_breakdown(all_findings, static_count, ai_count)

            scan_doc = repos.insert_scan(
                {
                    "input_text": (
                        f"PR #{number} in {full} · {files_scanned} file(s) · "
                        f"{head_sha[:7]}"
                    ),
                    "risk_score": score,
                    "findings": all_findings,
                    "counts": {"static": static_count, "ai": ai_count, "total": len(all_findings)},
                    "source": "github",
                    "github": {
                        "repo_full_name": full,
                        "pr_number": number,
                        "commit_sha": head_sha,
                        "pr_title": pr_title,
                        "pr_url": pr_url,
                        "author_login": author_login,
                    },
                    "score_breakdown": breakdown,
                    "llm_targets": sorted(target_set) if target_set else [],
                }
            )

            col(C.AUDIT_LOGS).insert_one(
                {
                    "actor": "github-sync",
                    "action": "PR_SCAN_COMPLETED",
                    "source": "github",
                    "repo_full_name": full,
                    "pr_number": number,
                    "scan_id": str(scan_doc["_id"]),
                    "details": {"risk_score": score, "files_scanned": files_scanned, "findings": len(all_findings)},
                    "created_at": datetime.now(timezone.utc),
                }
            )

            logger.info("sync scan complete", extra={"repo": full, "pr": number, "score": score})
            return {"scan_id": str(scan_doc["_id"]), "risk_score": score, "counts": counts, "pr_number": number}
        except Exception:
            logger.exception("sync scan failed", extra={"repo": full, "pr": number})
            return None


@router.post("/sync")
def github_sync():
    """Fetch open PRs from all installed repos and scan them into the dashboard."""
    if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
        raise HTTPException(status_code=503, detail="GitHub App not configured")

    app_jwt = sign_app_jwt()
    # List all installations
    r = httpx.get(
        f"https://api.github.com/app/installations",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "PromptShield/0.3",
        },
        timeout=10.0,
    )
    r.raise_for_status()
    installations = r.json()

    results = []
    for inst in installations:
        inst_id = inst["id"]
        token = get_installation_token(inst_id)
        # List repos for this installation
        repos_r = httpx.get(
            f"https://api.github.com/installation/repositories",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "PromptShield/0.3",
            },
            timeout=10.0,
        )
        repos_r.raise_for_status()
        repo_list = repos_r.json().get("repositories", [])

        for repo_obj in repo_list:
            owner = repo_obj["owner"]["login"]
            repo_name = repo_obj["name"]
            full = repo_obj["full_name"]

            # List open PRs
            prs_r = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo_name}/pulls",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "PromptShield/0.3",
                },
                params={"state": "open", "per_page": 10},
                timeout=10.0,
            )
            if prs_r.status_code != 200:
                continue
            prs = prs_r.json()

            for pr in prs:
                result = _scan_pr_for_sync(owner, repo_name, full, pr, token)
                if result:
                    results.append(result)

    return {"ok": True, "synced": len(results), "scans": results}


@router.post("/webhook")
async def github_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256")
    event = request.headers.get("x-github-event", "")
    delivery = request.headers.get("x-github-delivery", "")

    if not settings.GITHUB_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="GitHub App not configured")
    if not verify_webhook_signature(
        settings.GITHUB_WEBHOOK_SECRET, body, signature
    ):
        logger.warning(
            "rejected webhook signature",
            extra={"event": "github_signature_invalid", "delivery_id": delivery},
        )
        raise HTTPException(status_code=401, detail="Invalid signature")

    if event == "ping":
        return {"ok": True, "msg": "pong"}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if event != "pull_request":
        return {"ok": True, "ignored": event}

    action = payload.get("action")
    if action not in ACTIONS_TO_HANDLE:
        return {"ok": True, "ignored_action": action}

    score, counts, scan_id = _process_pr(payload)
    return {
        "ok": True,
        "scan_id": scan_id,
        "risk_score": score,
        "counts": counts,
    }

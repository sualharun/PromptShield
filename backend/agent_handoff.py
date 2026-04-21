"""
Agent Handoff Inspector
Inspects agent-to-agent instruction envelopes for prompt injection,
dangerous tool scopes, cross-repo boundary violations, scope escalation,
and data sensitivity violations.
Targets coding agents: Cursor, Claude Code, Codex, Copilot.
"""
import pickle
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List

with open("ml_classifier.pkl", "rb") as f:
    model = pickle.load(f)
vectorizer = model["vectorizer"]
clf = model["classifier"]

router = APIRouter(prefix="/api/agent-handoff", tags=["agent-handoff"])

class HandoffEnvelope(BaseModel):
    source_agent: str
    target_agent: str
    source_repo: Optional[str] = None
    target_repo: Optional[str] = None
    instruction_payload: str
    tool_scopes: Optional[List[str]] = []
    expected_scope: Optional[List[str]] = []
    data_sensitivity: Optional[str] = "public"  # public, internal, confidential

DANGEROUS_TOOLS = {"shell", "exec", "bash", "eval", "subprocess", "system", "rm", "curl", "wget"}
DANGEROUS_PATTERNS = [
    "api.openai.com", "api.anthropic.com", "hooks.slack.com", "webhook",
    "requests.get", "requests.post", "fetch(", "axios", "http.get",
    "authorization: bearer", "x-api-key", "access_token", "api_key",
    "s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows",
    "sendgrid", "twilio", "stripe.com", "database_url", "connection_string",
    "ignore previous", "ignore all", "disregard", "override instructions",
    "you are now", "act as", "exfil", "send to", "post to http",
    "curl ", "wget ", "rm -rf", "subprocess", "os.system"
]

@router.post("/inspect")
def inspect_handoff(envelope: HandoffEnvelope):
    payload = envelope.instruction_payload
    cross_repo = (
        envelope.source_repo and envelope.target_repo and
        envelope.source_repo != envelope.target_repo
    )

    X = vectorizer.transform([payload])
    ml_score = float(clf.predict_proba(X)[0][1])

    # Boost ML score for confidential repos
    sensitivity = (envelope.data_sensitivity or "public").lower()
    if sensitivity == "confidential":
        ml_score = min(ml_score * 1.3, 1.0)
    elif sensitivity == "internal":
        ml_score = min(ml_score * 1.1, 1.0)

    violations = []

    # Dangerous tool check
    dangerous_tool_hits = [
        t for t in (envelope.tool_scopes or [])
        if any(d in t.lower() for d in DANGEROUS_TOOLS)
    ]
    if dangerous_tool_hits:
        violations.append({
            "type": "DANGEROUS_TOOL_SCOPE",
            "severity": "critical",
            "detail": f"Handoff requests dangerous tool access: {', '.join(dangerous_tool_hits)}"
        })

    # Scope escalation check
    expected = set(s.lower().strip() for s in (envelope.expected_scope or []))
    requested = set(s.lower().strip() for s in (envelope.tool_scopes or []))
    escalated = requested - expected
    if expected and escalated:
        violations.append({
            "type": "SCOPE_ESCALATION",
            "severity": "critical",
            "detail": f"Agent requesting tools beyond authorized scope: {', '.join(escalated)}"
        })

    # Injection pattern check
    pattern_hits = [
        p for p in DANGEROUS_PATTERNS
        if p.lower() in payload.lower()
    ]
    if pattern_hits:
        violations.append({
            "type": "INJECTION_PATTERN",
            "severity": "critical",
            "detail": f"Injection pattern detected in handoff payload: '{pattern_hits[0]}'"
        })

    # Cross-repo boundary check
    if cross_repo and ml_score >= 0.5:
        sev = "critical" if sensitivity == "confidential" else "high"
        violations.append({
            "type": "CROSS_REPO_BOUNDARY_VIOLATION",
            "severity": sev,
            "detail": f"Risky instruction crossing repo boundary: {envelope.source_repo} → {envelope.target_repo} ({sensitivity} data)"
        })

    # Data sensitivity check
    if sensitivity == "confidential" and cross_repo:
        violations.append({
            "type": "CONFIDENTIAL_DATA_EXPOSURE",
            "severity": "critical",
            "detail": "Handoff targets a confidential repo across a trust boundary. High exfiltration risk."
        })

    if ml_score >= 0.8:
        risk_level = "CRITICAL"
    elif ml_score >= 0.6:
        risk_level = "HIGH"
    elif ml_score >= 0.3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    blocked = any(v["severity"] == "critical" for v in violations)

    return {
        "source_agent": envelope.source_agent,
        "target_agent": envelope.target_agent,
        "cross_repo": cross_repo,
        "data_sensitivity": sensitivity,
        "ml_risk_score": round(ml_score, 3),
        "risk_level": risk_level,
        "violations": violations,
        "blocked": blocked,
        "recommendation": (
            "Block this handoff. Critical violations detected." if blocked else
            "Review before executing. Elevated risk score." if ml_score >= 0.5 else
            "Handoff appears safe to execute."
        )
    }

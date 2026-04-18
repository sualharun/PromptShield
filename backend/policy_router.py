from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from policy import EXAMPLE_POLICY_YAML, PolicyError, apply_policy, parse_policy


router = APIRouter(prefix="/api/policy", tags=["policy"])


class PolicyValidateRequest(BaseModel):
    yaml: str
    findings: Optional[List[Dict[str, Any]]] = None
    risk_score: Optional[int] = None


class PolicyValidateResponse(BaseModel):
    valid: bool
    policy: Optional[Dict[str, Any]] = None
    warnings: List[str] = []
    error: Optional[str] = None
    decision: Optional[Dict[str, Any]] = None


@router.get("/example")
def example_policy():
    return {"yaml": EXAMPLE_POLICY_YAML}


@router.post("/validate", response_model=PolicyValidateResponse)
def validate_policy(body: PolicyValidateRequest):
    try:
        policy, warnings = parse_policy(body.yaml)
    except PolicyError as e:
        return PolicyValidateResponse(valid=False, error=str(e))

    decision = None
    if body.findings is not None:
        decision = apply_policy(policy, body.findings, body.risk_score or 0)

    return PolicyValidateResponse(
        valid=True, policy=policy, warnings=warnings, decision=decision
    )

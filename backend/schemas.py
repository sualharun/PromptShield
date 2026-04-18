"""Pydantic v2 document models for MongoDB collections.

These describe the *new* idiomatic Mongo shapes. Critical differences from the
legacy SQLite schema (flat columns + JSON TEXT blobs):

  • findings, score_breakdown, graph_analysis are NATIVE nested objects/arrays
    (no more findings_json TEXT column + json.dumps round-trips)
  • llm_targets is a real array, queryable with $in (was a CSV string)
  • PR / GitHub fields live under a `github` sub-document (was 8 NULL columns
    on every web scan)
  • org_members and api_keys are EMBEDDED in `organizations`
  • risk_snapshots has the time-series shape Atlas expects: ts + meta + value

These models are also the source of truth for the prompt-vectors corpus that
backs Atlas Vector Search.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Helpers ─────────────────────────────────────────────────────────────────
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _Doc(BaseModel):
    """Base for documents stored in Mongo. Allows extra fields so we can add
    new keys without breaking older readers (one of the reasons we picked Mongo
    in the first place)."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


# ── Scan ────────────────────────────────────────────────────────────────────
class ScanCounts(BaseModel):
    static: int = 0
    ai: int = 0
    total: int = 0


class GitHubScanMeta(_Doc):
    repo_full_name: Optional[str] = None
    pr_number: Optional[int] = None
    commit_sha: Optional[str] = None
    pr_title: Optional[str] = None
    pr_url: Optional[str] = None
    author_login: Optional[str] = None


class SemanticMatch(_Doc):
    """Result of $vectorSearch against the prompts corpus.
    Surfaced inline on every new scan so the UI can show 'similar to <X>'."""

    matched_text: str
    matched_category: Optional[str] = None
    matched_expected: Optional[str] = None  # "vulnerable" | "safe"
    score: float  # cosine similarity, 0..1
    source_id: Optional[str] = None  # _id of the prompt_vectors doc


class ScanDoc(_Doc):
    created_at: datetime = Field(default_factory=_utcnow)
    source: Literal["web", "github", "api", "demo"] = "web"
    risk_score: float = 0.0
    input_text: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    counts: ScanCounts = Field(default_factory=ScanCounts)
    score_breakdown: Optional[dict[str, Any]] = None
    graph_analysis: Optional[dict[str, Any]] = None
    llm_targets: list[str] = Field(default_factory=list)
    org_id: Optional[str] = None  # ObjectId-string of the org
    github: Optional[GitHubScanMeta] = None

    # ── Atlas Vector Search enrichment ──────────────────────────────────────
    embedding: Optional[list[float]] = None  # 384-dim by default
    semantic_matches: list[SemanticMatch] = Field(default_factory=list)


# ── Audit log ───────────────────────────────────────────────────────────────
class AuditLogDoc(_Doc):
    created_at: datetime = Field(default_factory=_utcnow)
    actor: str = "system"
    action: str
    source: Literal["web", "github", "api", "demo"] = "web"
    repo_full_name: Optional[str] = None
    pr_number: Optional[int] = None
    scan_id: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    client_ip: Optional[str] = None


# ── Risk snapshot (time-series) ─────────────────────────────────────────────
class RiskSnapshotMeta(_Doc):
    source: Literal["web", "github", "api", "demo"] = "github"
    repo_full_name: Optional[str] = None


class RiskSnapshotDoc(_Doc):
    """Time-series document. `ts` is the timeField, `meta` is the metaField."""

    ts: datetime = Field(default_factory=_utcnow)
    meta: RiskSnapshotMeta = Field(default_factory=RiskSnapshotMeta)
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_count: int = 0


# ── Finding records / suppressions ──────────────────────────────────────────
class FindingRecordDoc(_Doc):
    signature: str
    scan_id: str
    last_seen_scan_id: str
    repo_full_name: Optional[str] = None
    pr_number: Optional[int] = None
    finding_type: str
    finding_title: str
    severity: str = "low"
    status: str = "new"
    owner: Optional[str] = None
    team: Optional[str] = None
    first_seen_at: datetime = Field(default_factory=_utcnow)
    last_seen_at: datetime = Field(default_factory=_utcnow)
    triaged_at: Optional[datetime] = None
    in_progress_at: Optional[datetime] = None
    fixed_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    suppressed_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    sla_due_at: Optional[datetime] = None
    is_active: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingSuppressionDoc(_Doc):
    signature: str
    finding_type: str
    finding_title: str
    repo_full_name: Optional[str] = None
    reason: Optional[str] = None
    suppressed_by: str = "anonymous"
    created_at: datetime = Field(default_factory=_utcnow)


# ── Users / orgs (members + api_keys EMBEDDED) ──────────────────────────────
class UserDoc(_Doc):
    email: str
    name: str
    password_hash: str
    role: str = "viewer"
    created_at: datetime = Field(default_factory=_utcnow)


class OrgMemberEmbedded(_Doc):
    user_id: str
    role: str = "viewer"
    created_at: datetime = Field(default_factory=_utcnow)


class ApiKeyEmbedded(_Doc):
    name: str
    key_hash: str
    key_prefix: str
    scopes: str = "scan:write,scan:read"
    created_by: str
    created_at: datetime = Field(default_factory=_utcnow)
    last_used_at: Optional[datetime] = None
    revoked: bool = False


class OrganizationDoc(_Doc):
    name: str
    slug: str
    plan: str = "free"
    settings: dict[str, Any] = Field(default_factory=dict)
    members: list[OrgMemberEmbedded] = Field(default_factory=list)
    api_keys: list[ApiKeyEmbedded] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


# ── Atlas-unique: prompt vectors corpus ─────────────────────────────────────
class PromptVectorDoc(_Doc):
    """One document per labeled prompt in our 151-prompt corpus.

    Backed by an Atlas Vector Search index on `embedding`. Every new scan
    looks up its top-k semantic neighbors here.
    """

    text: str
    category: str
    expected: Literal["vulnerable", "safe"]
    embedding: list[float]
    source: str = "prompts.json"
    created_at: datetime = Field(default_factory=_utcnow)


# ── Atlas-unique: benchmark runs (replaces benchmark_results.json file) ────
class BenchmarkRunDoc(_Doc):
    ts: datetime = Field(default_factory=_utcnow)
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion_matrix: dict[str, int]
    sample_count: int
    layers_enabled: list[str] = Field(default_factory=list)  # ["regex","ml","claude","vector"]
    notes: Optional[str] = None

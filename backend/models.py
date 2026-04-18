"""Extended data models for multi-tenant architecture.

Organization → Users → Scans chain. Every tenant-scoped table has an org_id
foreign key. The middleware injects org context from the session.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
    Boolean,
)
from sqlalchemy.orm import relationship

from database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    slug = Column(String(64), unique=True, nullable=False, index=True)
    plan = Column(String(16), nullable=False, default="free")
    settings_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    members = relationship("OrgMember", back_populates="org", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="org", cascade="all, delete-orphan")


class OrgMember(Base):
    __tablename__ = "org_members"
    __table_args__ = (
        Index("ix_org_members_user_org", "user_id", "org_id", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String(16), nullable=False, default="viewer")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    org = relationship("Organization", back_populates="members")


class ApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_key_hash", "key_hash", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    key_hash = Column(String(64), nullable=False)
    key_prefix = Column(String(12), nullable=False)
    scopes = Column(String(255), nullable=False, default="scan:write,scan:read")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)

    org = relationship("Organization", back_populates="api_keys")


class PolicyVersion(Base):
    """Versioned policy snapshots per org/repo."""
    __tablename__ = "policy_versions"
    __table_args__ = (
        Index("ix_policy_versions_org_repo", "org_id", "repo_full_name"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    repo_full_name = Column(String(255), nullable=True)
    version = Column(Integer, nullable=False, default=1)
    yaml_text = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)
    change_summary = Column(Text, nullable=True)


class ScanJob(Base):
    """Async scan job tracking."""
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    status = Column(String(16), nullable=False, default="pending", index=True)
    job_type = Column(String(32), nullable=False, default="scan")
    input_text = Column(Text, nullable=False)
    result_scan_id = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=3)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)


class EvalRun(Base):
    """Benchmark evaluation run for regression tracking."""
    __tablename__ = "eval_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    scanner_version = Column(String(32), nullable=False)
    total_samples = Column(Integer, nullable=False)
    true_positives = Column(Integer, nullable=False)
    true_negatives = Column(Integer, nullable=False)
    false_positives = Column(Integer, nullable=False)
    false_negatives = Column(Integer, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1 = Column(Float, nullable=False)
    accuracy = Column(Float, nullable=False)
    details_json = Column(Text, nullable=False, default="[]")
    regression_from_previous = Column(Boolean, default=False)


class BaselineFinding(Base):
    """Known findings for drift detection — 'only show new regressions'."""
    __tablename__ = "baseline_findings"
    __table_args__ = (
        Index("ix_baseline_repo_sig", "repo_full_name", "signature", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    repo_full_name = Column(String(255), nullable=False, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    signature = Column(String(128), nullable=False)
    finding_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    first_seen_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(128), nullable=True)

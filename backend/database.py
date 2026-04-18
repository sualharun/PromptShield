from datetime import datetime
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    text,
    Index,
)
from sqlalchemy.orm import declarative_base, sessionmaker

from config import settings

connect_args = (
    {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)
engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_source_created", "source", "created_at"),
        Index("ix_scans_repo_created", "repo_full_name", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    input_text = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False, default=0)
    findings_json = Column(Text, nullable=False, default="[]")
    static_count = Column(Integer, nullable=False, default=0)
    ai_count = Column(Integer, nullable=False, default=0)
    total_count = Column(Integer, nullable=False, default=0)

    # GitHub PR scan metadata (nullable so existing rows + web scans are unaffected)
    source = Column(String(16), nullable=False, default="web", index=True)
    repo_full_name = Column(String(255), nullable=True, index=True)
    pr_number = Column(Integer, nullable=True)
    commit_sha = Column(String(40), nullable=True)
    pr_title = Column(Text, nullable=True)
    pr_url = Column(String(512), nullable=True)
    score_breakdown_json = Column(Text, nullable=True)
    author_login = Column(String(128), nullable=True, index=True)
    llm_targets = Column(String(128), nullable=True, index=True)
    org_id = Column(Integer, nullable=True, index=True)
    graph_analysis_json = Column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_created", "created_at"),
        Index("ix_audit_logs_action_created", "action", "created_at"),
        Index("ix_audit_logs_repo_created", "repo_full_name", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    actor = Column(String(128), nullable=False, default="system")
    action = Column(String(64), nullable=False, index=True)
    source = Column(String(16), nullable=False, default="web", index=True)
    repo_full_name = Column(String(255), nullable=True, index=True)
    pr_number = Column(Integer, nullable=True)
    scan_id = Column(Integer, nullable=True)
    details_json = Column(Text, nullable=False, default="{}")
    client_ip = Column(String(64), nullable=True)


class FindingSuppression(Base):
    __tablename__ = "finding_suppressions"
    __table_args__ = (
        Index(
            "ix_finding_suppressions_signature",
            "signature",
            "repo_full_name",
            unique=True,
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    signature = Column(String(128), nullable=False)
    finding_type = Column(String(64), nullable=False)
    finding_title = Column(String(255), nullable=False)
    repo_full_name = Column(String(255), nullable=True, index=True)
    reason = Column(Text, nullable=True)
    suppressed_by = Column(String(128), nullable=False, default="anonymous")
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(128), nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(16), nullable=False, default="viewer")
    created_at = Column(DateTime, default=datetime.utcnow)


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"
    __table_args__ = (
        Index("ix_risk_snapshots_date", "snapshot_date"),
        Index("ix_risk_snapshots_source_date", "source", "snapshot_date"),
    )

    id = Column(Integer, primary_key=True, index=True)
    snapshot_date = Column(String(10), nullable=False, index=True)
    source = Column(String(16), nullable=False, default="github", index=True)
    risk_score = Column(Float, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    scan_count = Column(Integer, nullable=False, default=0)


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(64), nullable=False, default="unknown")
    registry = Column(String(16), nullable=False, default="pypi")
    ecosystem = Column(String(16), nullable=False, default="python")
    risk_score = Column(Float, nullable=False, default=0.0)
    cve_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class VulnerableRepo(Base):
    __tablename__ = "vulnerable_repos"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    cve_ids_json = Column(Text, nullable=False, default="[]")
    severity = Column(String(16), nullable=False, default="MEDIUM")
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)


class Maintainer(Base):
    __tablename__ = "maintainers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    repositories_json = Column(Text, nullable=False, default="[]")
    exploit_history = Column(Text, nullable=True)
    risk_level = Column(String(16), nullable=False, default="LOW")


class FindingDependency(Base):
    __tablename__ = "finding_dependencies"
    __table_args__ = (
        Index("ix_finding_dep_scan_dep", "scan_id", "dependency_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    dependency_id = Column(Integer, nullable=False, index=True)


class FindingRecord(Base):
    __tablename__ = "finding_records"
    __table_args__ = (
        Index("ix_finding_records_repo_status", "repo_full_name", "status"),
        Index("ix_finding_records_sig_repo", "signature", "repo_full_name", unique=True),
        Index("ix_finding_records_sla", "sla_due_at", "status"),
    )

    id = Column(Integer, primary_key=True, index=True)
    signature = Column(String(128), nullable=False, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    last_seen_scan_id = Column(Integer, nullable=False, index=True)
    repo_full_name = Column(String(255), nullable=True, index=True)
    pr_number = Column(Integer, nullable=True)
    finding_type = Column(String(64), nullable=False, index=True)
    finding_title = Column(String(255), nullable=False)
    severity = Column(String(16), nullable=False, default="low", index=True)
    status = Column(String(24), nullable=False, default="new", index=True)
    owner = Column(String(128), nullable=True, index=True)
    team = Column(String(128), nullable=True, index=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen_at = Column(DateTime, default=datetime.utcnow, index=True)
    triaged_at = Column(DateTime, nullable=True)
    in_progress_at = Column(DateTime, nullable=True)
    fixed_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    suppressed_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    sla_due_at = Column(DateTime, nullable=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    metadata_json = Column(Text, nullable=False, default="{}")


class FindingRecordEvent(Base):
    __tablename__ = "finding_record_events"
    __table_args__ = (
        Index("ix_finding_record_events_finding", "finding_record_id", "created_at"),
        Index("ix_finding_record_events_type", "event_type", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_record_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor = Column(String(128), nullable=False, default="system")
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"
    __table_args__ = (
        Index("ix_risk_acceptance_finding", "finding_record_id", "active"),
        Index("ix_risk_acceptance_expiry", "expires_at", "active"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_record_id = Column(Integer, nullable=False, index=True)
    reason = Column(Text, nullable=False)
    approved_by = Column(String(128), nullable=False, default="security")
    expires_at = Column(DateTime, nullable=True, index=True)
    active = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class IntegrationEvent(Base):
    __tablename__ = "integration_events"
    __table_args__ = (
        Index("ix_integration_events_topic", "topic", "created_at"),
        Index("ix_integration_events_delivery", "delivered", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    topic = Column(String(128), nullable=False, index=True)
    payload_json = Column(Text, nullable=False, default="{}")
    delivered = Column(Boolean, nullable=False, default=False, index=True)
    delivery_target = Column(String(255), nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    delivered_at = Column(DateTime, nullable=True)


class GraphNode(Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (
        Index("ix_graph_nodes_scan_node", "scan_id", "node_id", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    node_id = Column(String(255), nullable=False, index=True)
    node_type = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    risk_score = Column(Float, nullable=False, default=0)
    props_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (
        Index("ix_graph_edges_scan_source_target", "scan_id", "source_node_id", "target_node_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    source_node_id = Column(String(255), nullable=False, index=True)
    target_node_id = Column(String(255), nullable=False, index=True)
    edge_type = Column(String(64), nullable=False, index=True)
    risk = Column(String(16), nullable=False, default="low")
    props_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)


# SQLite-safe additive migration: ALTER TABLE ... ADD COLUMN for any new column
# that's missing on an existing dev DB. Idempotent and harmless on fresh DBs.
_ADDITIVE_COLUMNS = [
    ("source", "VARCHAR(16) NOT NULL DEFAULT 'web'"),
    ("repo_full_name", "VARCHAR(255)"),
    ("pr_number", "INTEGER"),
    ("commit_sha", "VARCHAR(40)"),
    ("pr_title", "TEXT"),
    ("pr_url", "VARCHAR(512)"),
    ("score_breakdown_json", "TEXT"),
    ("author_login", "VARCHAR(128)"),
    ("llm_targets", "VARCHAR(128)"),
    ("org_id", "INTEGER"),
    ("graph_analysis_json", "TEXT"),
]


def _apply_additive_migrations() -> None:
    if not settings.DATABASE_URL.startswith("sqlite"):
        return  # Postgres path: rely on a real migration tool when added
    with engine.begin() as conn:
        existing = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(scans)")).fetchall()
        }
        if not existing:
            return  # table doesn't exist yet — create_all will handle it
        for col_name, col_ddl in _ADDITIVE_COLUMNS:
            if col_name in existing:
                continue
            try:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col_name} {col_ddl}"))
            except Exception:
                pass
        # sqlite lacks robust schema evolution in dev mode; ensure hot-path indexes exist.
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_scans_source_created ON scans(source, created_at)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_scans_repo_created ON scans(repo_full_name, created_at)"
            )
        )


def init_db():
    Base.metadata.create_all(bind=engine)
    _apply_additive_migrations()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

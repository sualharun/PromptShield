import os
from pathlib import Path

from dotenv import load_dotenv


_HERE = Path(__file__).resolve().parent
# Prefer backend/.env, then optionally project-root .env; do not overwrite
# already-exported shell variables.
load_dotenv(_HERE / ".env", override=False)
load_dotenv(_HERE.parent / ".env", override=False)


def _normalize_scan_mode(raw: str | None) -> str:
    """fast = static + dataflow only; full = add Gemini + vector enrichment path."""
    v = (raw or "full").strip().lower()
    return v if v in ("fast", "full") else "full"


def _bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _load_pem(env_value: str | None, env_path_value: str | None) -> str | None:
    """GITHUB_APP_PRIVATE_KEY may be the PEM itself or a path; same for *_PATH."""
    if env_path_value:
        try:
            return Path(env_path_value).expanduser().read_text()
        except OSError:
            return None
    if not env_value:
        return None
    # Normalize literal \n (common when pasting into env var consoles like AWS EB)
    normalized = env_value.replace("\\n", "\n")
    if normalized.strip().startswith("-----BEGIN"):
        return normalized
    # Treat as a path if it's not a PEM body
    p = Path(env_value).expanduser()
    if p.is_file():
        try:
            return p.read_text()
        except OSError:
            return None
    return env_value


class Settings:
    # Used only by `scripts/migrate_sqlite_to_mongo.py` (points at a legacy .db file).
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./promptshield.db")
    ALLOWED_ORIGINS: list[str] = [
        o.strip()
        for o in os.environ.get(
            "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if o.strip()
    ]
    # Google Vertex AI (Gemini) — uses Application Default Credentials.
    # GOOGLE_CLOUD_PROJECT being set is the "AI layer enabled" signal.
    GOOGLE_CLOUD_PROJECT: str | None = os.environ.get("GOOGLE_CLOUD_PROJECT")
    GOOGLE_CLOUD_LOCATION: str = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
    GEMINI_MODEL: str = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    AI_PROVIDER: str = "gemini"
    # fast → core detectors only (no Vertex call, no scan vector enrich). full → layered pipeline.
    PROMPTSHIELD_SCAN_MODE: str = _normalize_scan_mode(os.environ.get("PROMPTSHIELD_SCAN_MODE"))
    SCAN_RATE_LIMIT: int = int(os.environ.get("SCAN_RATE_LIMIT", "10"))
    SCAN_RATE_WINDOW: int = int(os.environ.get("SCAN_RATE_WINDOW", "60"))
    MAX_INPUT_CHARS: int = int(os.environ.get("MAX_INPUT_CHARS", "50000"))
    REDACT_PERSISTED_INPUT: bool = _bool("REDACT_PERSISTED_INPUT", True)
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

    # GitHub App
    GITHUB_APP_ID: str | None = os.environ.get("GITHUB_APP_ID")
    GITHUB_APP_PRIVATE_KEY: str | None = _load_pem(
        os.environ.get("GITHUB_APP_PRIVATE_KEY"),
        os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH"),
    )
    GITHUB_WEBHOOK_SECRET: str | None = os.environ.get("GITHUB_WEBHOOK_SECRET")
    RISK_GATE_THRESHOLD: int = int(os.environ.get("RISK_GATE_THRESHOLD", "70"))
    DASHBOARD_BASE_URL: str = os.environ.get(
        "DASHBOARD_BASE_URL", "http://localhost:5173"
    )

    # Auth / sessions
    SESSION_SECRET: str = os.environ.get(
        "SESSION_SECRET", "dev-insecure-change-me-in-prod"
    )
    SESSION_MAX_AGE_SECONDS: int = int(
        os.environ.get("SESSION_MAX_AGE_SECONDS", str(60 * 60 * 24 * 7))
    )
    BOOTSTRAP_ADMIN_EMAIL: str | None = os.environ.get("BOOTSTRAP_ADMIN_EMAIL")
    BOOTSTRAP_ADMIN_PASSWORD: str | None = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")
    BOOTSTRAP_ADMIN_NAME: str = os.environ.get("BOOTSTRAP_ADMIN_NAME", "Admin")

    # Notifications (opt-in: webhook URLs blank means notifications are skipped)
    SLACK_WEBHOOK_URL: str | None = os.environ.get("SLACK_WEBHOOK_URL")
    TEAMS_WEBHOOK_URL: str | None = os.environ.get("TEAMS_WEBHOOK_URL")

    # ── MongoDB Atlas ───────────────────────────────────────────────────────
    # Empty MONGODB_URI falls back to mongomock (tests) or must be set in production.
    MONGODB_URI: str | None = os.environ.get("MONGODB_URI") or None
    MONGODB_DB: str = os.environ.get("MONGODB_DB", "promptshield")
    # Telemetry only (historical: which backing store the API used).
    PRIMARY_STORE: str = os.environ.get("PRIMARY_STORE", "mongo").strip().lower()

    # ── Embeddings / Vector Search ─────────────────────────────────────────
    # "local" → sentence-transformers (no key, runs on CPU)
    # "voyage" → MongoDB-hosted Voyage AI Embedding API (needs VOYAGE_API_KEY)
    EMBEDDING_PROVIDER: str = os.environ.get("EMBEDDING_PROVIDER", "voyage").strip().lower()
    EMBEDDING_MODEL: str = os.environ.get(
        "EMBEDDING_MODEL",
        "voyage-3-large" if os.environ.get("EMBEDDING_PROVIDER", "voyage") == "voyage"
        else "all-MiniLM-L6-v2",
    )
    EMBEDDING_DIMS: int = int(
        os.environ.get(
            "EMBEDDING_DIMS",
            "1024" if os.environ.get("EMBEDDING_PROVIDER", "voyage") == "voyage" else "384",
        )
    )
    VOYAGE_API_KEY: str | None = os.environ.get("VOYAGE_API_KEY") or None

    # TLS to Atlas — macOS / some Python builds lack a proper default CA store.
    # Leave unset to use certifi's bundle (recommended). Override with a PEM path if needed.
    MONGODB_TLS_CA_FILE: str | None = os.environ.get("MONGODB_TLS_CA_FILE") or None
    # Last-resort dev only — insecure; never use in production
    MONGODB_TLS_ALLOW_INVALID: bool = _bool("MONGODB_TLS_ALLOW_INVALID", False)


settings = Settings()

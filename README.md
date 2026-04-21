# PromptShield

**LLM and AI-agent security for the SDLC.** PromptShield scans prompts, application code, and pull requests for prompt injection, unsafe tool exposure, and improper handling of LLM output. It combines static rules, AST-based dataflow analysis, and (optionally) Google Gemini for deeper semantic review. Findings map to **CWE** and **OWASP LLM Top 10** with evidence, remediation hints, and confidence scores.

---

## Capabilities

| Area | What you get |
| --- | --- |
| **Detection** | Layered pipeline: static rules, dataflow/taint to dangerous sinks, optional Gemini audit, optional vector “similar jailbreak” enrichment |
| **Risk** | Single **0–100** score from merged findings; per-finding severity and category |
| **PR workflow** | **GitHub App**: scan changed files, inline comments, check runs, configurable risk gate |
| **Data** | **MongoDB Atlas** primary store: scans, search, vectors, benchmarks, agent-tool registry, alerts (see below) |
| **Governance** | Policy-as-code (`.promptshield.yml`), suppressions, CSV/PDF exports, audit-oriented dashboards |
| **Ops** | Per-IP rate limits, structured JSON logs with `request_id`, role-based auth (admin / PM / viewer) |

---

## Stack

| Layer | Technology |
| --- | --- |
| **API** | FastAPI (`backend/`), Uvicorn |
| **Database** | MongoDB Atlas (Motor); **mongomock** when `MONGODB_URI` is unset (local/CI) |
| **AI** | Google **Vertex AI** + **Gemini** via `google-genai` (Application Default Credentials) |
| **Embeddings** | MongoDB **Voyage AI** or local **sentence-transformers** (configurable) |
| **Frontend** | React 18, Vite, Tailwind, Recharts, `react-force-graph-2d` |
| **Deploy** | Root `requirements.txt` matches `backend/requirements.txt` for Railway/Nixpacks-style builds; `nixpacks.toml` starts the API from `backend/` |

---

## MongoDB Atlas (optional but recommended for full features)

Atlas powers semantic and full-text search, hybrid ranking, vector similarity for jailbreak-like matches, change-stream live updates, time-series style analytics, and agent-focused collections (tool registry, exploit corpus, alerts). Apply search/vector **index definitions** under `backend/scripts/atlas_indexes/` (use Atlas UI or `mongosh` as documented in scripts).

**Minimal setup:** create a cluster → database user → network access → set `MONGODB_URI` and `PRIMARY_STORE=mongo` in `backend/.env` → run:

```bash
python backend/scripts/setup_atlas_indexes.py
```

Optional: Atlas **Triggers** in `backend/scripts/atlas_triggers/` (e.g. redaction on insert, critical agent alerts). If triggers are not installed, Python-side fallbacks still run where implemented.

---

## Run locally

### Backend (port 8000)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # edit as needed; see below
gcloud auth application-default login   # once, if using Vertex AI
uvicorn main:app --reload --port 8000
```

- Without `GOOGLE_CLOUD_PROJECT`, the Gemini layer is off. `PROMPTSHIELD_SCAN_MODE=fast` skips Gemini and vector enrichment on `/api/scan` even when a project is set (see `.env.example`).
- Without `MONGODB_URI`, storage uses **mongomock** for development.

**Auth:** There is no public signup. If `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` are set and the `users` collection is empty, an admin is created on startup. Use the app’s sign-in page or `POST /api/auth/login`.

```bash
cd backend && pytest
```

### Frontend (port 5173)

```bash
cd frontend
npm install
npm run dev
```

Vite proxies `/api` and WebSocket paths to `http://localhost:8000`. Open `http://localhost:5173`.

---

## GitHub App (PR scanning)

1. Create a GitHub App at [github.com/settings/apps/new](https://github.com/settings/apps/new): webhook `https://<your-host>/api/github/webhook`, permissions for pull requests and checks (read/write as required), subscribe to pull request events.
2. Install the app on repositories and add the private key.
3. Set in `backend/.env` (see `.env.example`): `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY` or `GITHUB_APP_PRIVATE_KEY_PATH`, `GITHUB_WEBHOOK_SECRET`, plus `DASHBOARD_BASE_URL` and optional `RISK_GATE_THRESHOLD`.

For local webhooks, expose port 8000 (e.g. `backend/scripts/ngrok_http_8000.sh`) and point the App’s webhook URL at `/api/github/webhook`.

Confirm `GET /api/health` reports GitHub App configuration when env is correct.

---

## Configuration

All important variables are documented in **`backend/.env.example`**. Typical groups:

- **Vertex / Gemini:** `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `GEMINI_MODEL`, `GOOGLE_GENAI_USE_VERTEXAI`
- **MongoDB:** `MONGODB_URI`, `MONGODB_DB`, `PRIMARY_STORE`
- **Embeddings:** `EMBEDDING_PROVIDER`, `VOYAGE_API_KEY` (if using Voyage), dimensions aligned with Atlas indexes
- **HTTP:** `ALLOWED_ORIGINS`, `SCAN_RATE_LIMIT`, `SCAN_RATE_WINDOW`, `MAX_INPUT_CHARS`, `REDACT_PERSISTED_INPUT`, `LOG_LEVEL`

---

## API overview

Interactive docs: **`http://localhost:8000/docs`** (OpenAPI/Swagger) when the server is running.

Rough map:

- **`/api/scan`** — main scan (static + dataflow + optional AI/vector path)
- **`/api/scans`, `/api/dashboard/*`, `/api/reports/*`** — history, dashboards, exports
- **`/api/v2/*`** — Atlas-backed search, similar scans, hybrid search, benchmarks, live scans (`/api/live/scans`), agent tools/alerts/timeline
- **`/api/github/*`** — webhook and sync
- **`/api/auth/*`, `/api/policy/*`, `/api/suppressions/*`** — sessions, policy validation, suppressions

Responses include an **`x-request-id`** header aligned with structured logs.

---

## Detection and agentic findings

**Static layer** covers categories such as direct injection, secrets in prompts, system prompt exposure, role confusion, over-permissive behavior, data leakage, and indirect injection—each tied to CWE and OWASP LLM labels where applicable.

**Agent tools:** Functions exposed to the LLM (e.g. `@tool`, LangChain-style tool lists) are analyzed as privileged entry points; arguments are traced into sinks such as `subprocess`, `eval`, SQL execution, or unsafe HTML. Representative finding types include dangerous capabilities, unvalidated arguments, excessive scope, and taint from tool parameters or LLM output into execution, shell, SQL, or XSS-prone sinks.

**Examples:** `GET /api/examples` lists demo files (e.g. vulnerable agent, unsafe output, unsafe RAG) you can load in the UI or inspect under `backend/examples/`.

---

## Benchmarks

`backend/three_layer_benchmark.py` evaluates labeled prompts in `backend/prompts.json` against static rules, the optional ML classifier artifact, and the live `POST /api/scan` API. Results can be recorded via the benchmark API and Mongo collections when Atlas is configured. Run with the API up on port 8000 as documented in the script.

---

## Positioning

PromptShield is meant to **shift security left** on LLM and agent features: catch risky changes in review before merge. It complements runtime guardrails (e.g. in-production monitoring) by reducing what reaches production. The project is **self-hostable** and intended for internal SDLC workflows.

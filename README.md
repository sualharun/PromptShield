# PromptShield

**Secure the AI agent attack surface.** PromptShield scans prompts, code, and pull requests for prompt-injection, dangerous AI-exposed tools, and unsafe LLM output handling — then comments directly on the PR before merge. It runs static pattern analysis, AST-based dataflow taint tracking, and a Gemini-powered semantic audit in parallel, mapping findings to **CWE** and **OWASP LLM Top 10 (2025)** with remediation, evidence snippets, and confidence scores.

- **v0.5 — Agentic Security.** Traces AI-controlled inputs into dangerous sinks (`subprocess`, `eval`, `cursor.execute`, `os.remove`, `requests.get`) at PR-time, catching excessive-agency (LLM06) and improper-output-handling (LLM05) bugs before production.
- **v0.4 — MongoDB Atlas.** Semantic similarity (Vector Search), fuzzy search (Atlas Search), fused ranking (`$rankFusion`), live dashboards via change streams, time-series risk analytics, and server-side redaction triggers.

UI is built on the **IBM Carbon Design System**.

## Stack

- **Frontend** — React + Vite + Tailwind + Recharts (Vitest + RTL)
- **Backend** — FastAPI + **MongoDB Atlas** (primary store); optional SQLite import via stdlib `sqlite3`
- **Embeddings** — `sentence-transformers` (local) or **MongoDB Voyage AI** (`voyage-3-large`, 1024d)
- **AI** — **Google Vertex AI (Gemini 2.5 Flash)** via `google-genai` SDK with Application Default Credentials

## MongoDB Atlas — what we use

| Feature | Where it shows up |
| --- | --- |
| **Vector Search** (`$vectorSearch`) | `SEMANTIC_JAILBREAK_MATCH` findings; similarity badge in `FindingCard`; `/api/v2/similar` |
| **Atlas Search** (`$search`) | Dashboard search bar with autocomplete + facets; `/api/v2/search*` |
| **Hybrid Search** (`$rankFusion`) | Dashboard `HybridSearchBar`; `/api/v2/search/hybrid` |
| **Time-series** + `$setWindowFields` | `/api/v2/risk-timeline` (7-day rolling avg) |
| **Change Streams** → WebSocket | Dashboard `AtlasLiveBadge`; `WS /api/live/scans` |
| **Atlas Triggers** (server-side JS) | `redact_on_scan_insert` + `alert_on_critical_agent_finding` (with Python fallback) |
| **JSON Schema validation** | Enforces `scans` doc shape on insert |
| **Voyage AI embeddings** | Powers all vector workflows (local sentence-transformers fallback) |
| **Benchmark / model registry** | `benchmark_runs` collection tracks every evaluation run |
| **Agent tool registry** *(v0.5)* | `agent_tools` — every `@tool` / `tools=[...]` we've seen, with risk, framework, embedding |
| **Tool-exploit knowledge base** *(v0.5)* | `agent_exploit_corpus` vector store of curated dangerous-tool patterns |
| **Agent alert fan-out** *(v0.5)* | `agent_alerts` collection, written by Atlas trigger or Python fallback |
| **Agent surface time-series** *(v0.5)* | `agent_surface_timeline` — attack-surface drift over time |

## Features

- **Layered detection** — 7 static-rule categories + Gemini semantic auditor, run in parallel
- **Risk score 0–100** — weighted by severity (critical 40, high 20, medium 8, low 3), capped at 100
- **CWE / OWASP mapping** — every finding ships with `CWE-xxx` and `LLMxx` chips
- **AST-based dataflow** — taint tracking from sources through assignments/f-strings to LLM sinks
- **Privacy by default** — secrets, emails, SSNs, phones redacted before persistence
- **Per-IP rate limiting** + structured JSON logs (every request has an echoed `request_id`)
- **Dashboard** — animated risk gauge, bar/radar/trend charts, CWE/OWASP compliance view, PM analytics
- **Exportable reports** — CSV + PDF for governance teams
- **AI fix suggestions** — one-click secure refactor guidance per finding
- **Jailbreak simulator** — 14 attack payloads across 6 categories
- **Dependency CVE scanning** — checks LLM SDK versions (langchain, openai, transformers, etc.)
- **False-positive suppression** — signature-matched across future scans
- **Evaluation benchmark** — 100-sample ground-truth suite (96% F1)
- **Policy-as-code** — `.promptshield.yml` per repo for gates, overrides, ignores
- **Role-based auth** — admin/pm/viewer with signed-cookie sessions
- **Cross-repo intelligence** + **Slack/Teams webhooks**

## Run locally

### 1. Backend (port 8000)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill in GOOGLE_CLOUD_PROJECT (optional)
gcloud auth application-default login   # one-time, for Vertex AI
uvicorn main:app --reload --port 8000
pytest
```

Works without `GOOGLE_CLOUD_PROJECT` (skips AI layer) and without `MONGODB_URI` (falls back to `mongomock` for dev/CI).

**Login.** No public signup. On first startup, if `users` is empty and `BOOTSTRAP_ADMIN_EMAIL` + `BOOTSTRAP_ADMIN_PASSWORD` are set in `.env`, an admin user is created automatically. Log in via `POST /api/auth/login` or the **Sign in** page. Add more users via `POST /api/admin/users`.

### 2. MongoDB Atlas (5 min, free tier)

1. Create a free **M0 cluster** at [cloud.mongodb.com](https://cloud.mongodb.com).
2. Add a DB user with read/write; allow `0.0.0.0/0` on Network Access.
3. Copy the `mongodb+srv://…` URI into `backend/.env`:
   ```
   MONGODB_URI=mongodb+srv://<user>:<pass>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   PRIMARY_STORE=mongo
   ```
4. Provision indexes:
   ```bash
   python backend/scripts/setup_atlas_indexes.py
   ```
5. *(Optional)* Migrate SQLite history: `python backend/scripts/migrate_sqlite_to_mongo.py`
6. *(Optional)* Install the `redact_on_scan_insert` Atlas Trigger from `backend/scripts/atlas_triggers/redact_on_scan_insert.js`.

Verify with `GET /api/health` — `mongo.ok` should be `true` and `corpus_size` should be `151`.

### 3. Frontend (port 5173)

```bash
cd frontend
npm install
npm run dev
npm test
```

Open http://localhost:5173. Vite proxies `/api/*` to port 8000.

## GitHub App setup (PR review bot)

PromptShield auto-reviews PRs, posts inline comments on risky lines, and creates a Check Run gate.

1. **Create the App** at `https://github.com/settings/apps/new`:
   - Webhook URL: `https://YOUR_HOST/api/github/webhook`
   - Permissions: Pull requests (R/W), Checks (R/W), Contents (R), Metadata (R)
   - Subscribe to: Pull request events
2. Generate a private key (`.pem`) and install the App on a test repo.
3. Set backend env in `backend/.env`:
   ```env
   GITHUB_APP_ID=123456
   GITHUB_APP_PRIVATE_KEY_PATH=/absolute/path/to/your-app.private-key.pem
   GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
   RISK_GATE_THRESHOLD=70
   DASHBOARD_BASE_URL=http://localhost:5173
   ```
4. **Local webhook forwarding** (ngrok):
   - Terminal A: `cd backend && uvicorn main:app --reload --port 8000`
   - Terminal B: `./backend/scripts/ngrok_http_8000.sh`
   - Terminal C: `./backend/scripts/github_webhook_url.sh` — prints the exact URL to paste into GitHub
   - Alternative: `npx smee-client --url https://smee.io/YOUR_CHANNEL --target http://localhost:8000/api/github/webhook`
5. Open a PR with vulnerable changes and confirm inline comments + a `PromptShield` check run appear.

**Troubleshooting.** If PR scans don't show up: verify `github_app_configured: true` in `/api/health`, App is installed on the repo, webhook deliveries are `2xx`, secret matches, private key path is readable, forwarder points to `/api/github/webhook`, and the PR has new/changed lines.

## Configuration

All backend settings are env-driven (see `backend/.env.example`):

| Var | Default | Purpose |
| --- | --- | --- |
| `GOOGLE_CLOUD_PROJECT` | — | Vertex AI project. Empty = static-only. |
| `GOOGLE_CLOUD_LOCATION` | `us-central1` | Vertex region |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Override with `gemini-2.5-pro` for higher quality |
| `MONGODB_URI` | — | Atlas SRV connection string |
| `MONGODB_DB` | `promptshield` | Atlas database name |
| `PRIMARY_STORE` | `mongo` | `mongo` \| `sql` \| `dual` |
| `EMBEDDING_PROVIDER` | `voyage` | `voyage` \| `local` |
| `EMBEDDING_MODEL` / `EMBEDDING_DIMS` | `voyage-3-large` / `1024` | Must match Atlas index dims |
| `VOYAGE_API_KEY` | — | Required when `EMBEDDING_PROVIDER=voyage` |
| `ALLOWED_ORIGINS` | `localhost:5173` | CORS allow-list |
| `SCAN_RATE_LIMIT` / `SCAN_RATE_WINDOW` | `10` / `60s` | Per-IP rate limit |
| `MAX_INPUT_CHARS` | `50000` | Input size cap |
| `REDACT_PERSISTED_INPUT` | `true` | Redact secrets/PII before write |
| `LOG_LEVEL` | `INFO` | Structured JSON logs |

## API

**Core:**

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/scan` | Runs static + dataflow + Gemini in parallel; rate-limited |
| `GET` | `/api/scans[?source=web\|github]` | Recent scan summaries |
| `GET/DELETE` | `/api/scans/{id}` | Fetch or delete a scan |
| `GET` | `/api/examples` | Demo vulnerable-agent files |
| `GET` | `/api/dashboard/{github,compliance,pm,cross-repo}` | Dashboard views |
| `GET` | `/api/audit-logs`, `/api/risk-timeline` | Audit events + risk trend |
| `GET` | `/api/reports/compliance.{csv,pdf}` | Governance exports |
| `GET` | `/api/enterprise/readiness` | Scale posture |
| `POST` | `/api/findings/suggest-fix` | AI-backed secure fix |
| `POST` | `/api/jailbreak/simulate[/v2]` | Heuristic / structural jailbreak simulation |
| `POST` | `/api/dependency-scan` | CVE scan for `requirements.txt`, `package.json` |
| `GET/POST/DELETE` | `/api/suppressions[/{id}]` | False-positive suppressions |
| `POST` | `/api/auth/{login,logout}`, `GET /api/auth/me` | Session auth |
| `POST/GET` | `/api/policy/{validate,example}` | Policy-as-code |
| `POST` | `/api/github/webhook`, `POST /api/github/sync` | GitHub App webhook + backfill |
| `GET` | `/api/health`, `/api/benchmark/results` | Liveness + benchmark |

**MongoDB Atlas (`/api/v2/*`):**

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v2/health` | Atlas status + feature flags + corpus size |
| `POST` | `/api/v2/similar`, `/api/v2/corpus/seed` | Vector Search + seed `prompt_vectors` |
| `GET` | `/api/v2/search[/autocomplete\|/facets]` | Atlas `$search` + autocomplete + facets |
| `POST` | `/api/v2/search/hybrid` | `$rankFusion` across scans |
| `GET` | `/api/v2/risk-timeline` | 7-day rolling time-series |
| `GET` | `/api/v2/scans[/{id}[/similar]]` | Scans from Mongo |
| `GET` | `/api/v2/aggregations/{repos,llm-targets,top-cwes}` | `$group` analytics |
| `GET/POST` | `/api/v2/benchmark/runs` | Benchmark model registry |
| `WS` | `/api/live/scans` | Change-stream feed |
| `GET` | `/api/v2/agent-tools[/aggregations/{capabilities,frameworks}]` | Tool catalog + donuts |
| `POST` | `/api/v2/agent-tools/{similar-exploits,search,exploit-corpus/seed}` | Match known exploits, hybrid search, seed corpus |
| `GET/POST` | `/api/v2/agent-alerts[/{id}/acknowledge]` | Critical agentic findings inbox |
| `GET` | `/api/v2/agent-surface-timeline` | Attack-surface drift |

Every response includes an `x-request-id` header matching the `request_id` in JSON logs.

## Detection coverage

**Static layer:** `DIRECT_INJECTION`, `SECRET_IN_PROMPT`, `SYSTEM_PROMPT_EXPOSED`, `ROLE_CONFUSION`, `OVERLY_PERMISSIVE`, `DATA_LEAKAGE`, `INDIRECT_INJECTION` — each mapped to CWE + OWASP LLM. Enhanced leakage includes DB creds, PII (email/SSN/phone/cards), and user-data flow into LLM API calls. The AI layer adds semantic findings the regex layer cannot catch.

## Agent tool security (v0.5)

PromptShield is one of the few PR-time scanners that models the **agent-tool attack surface**. Any function exposed to an LLM (`@tool`, `@mcp.tool`, `tools=[...]`, `Tool(...)`, `@agent.tool`) is treated as a privileged entry point, and its arguments are traced into dangerous sinks at AST level.

| Finding type | What we catch | CWE | OWASP |
| --- | --- | --- | --- |
| `DANGEROUS_TOOL_CAPABILITY` | `@tool` performs `subprocess`, `os.remove`, raw SQL with no safeguards | CWE-78 | LLM06 |
| `TOOL_UNVALIDATED_ARGS` | Tool param → dangerous sink, no validation | CWE-78 | LLM06 |
| `TOOL_EXCESSIVE_SCOPE` | Arbitrary paths/URLs/table names, no allowlist | CWE-732 | LLM06 |
| `TOOL_PARAM_TO_{EXEC,SHELL,SQL}` | Taint trace from tool param → `eval`/`subprocess`/`cursor.execute` | CWE-95/78/89 | LLM06 |
| `LLM_OUTPUT_TO_EXEC` | LLM response passed to `eval()` / `exec()` | CWE-95 | LLM05 |
| `LLM_OUTPUT_TO_SHELL` | LLM output → `subprocess.run`, `os.system` | CWE-78 | LLM05 |
| `LLM_OUTPUT_TO_SQL` | LLM output interpolated into raw `cursor.execute` | CWE-89 | LLM05 |
| `LLM_OUTPUT_UNESCAPED` | LLM response rendered via `innerHTML` / `dangerouslySetInnerHTML` | CWE-79 | LLM05 |
| `RAG_UNSANITIZED_CONTEXT` | Vector-store results concatenated into prompt without sanitization | CWE-74 | LLM01 |

These surface on every PR check as two categories: **Agent tool security** (`DANGEROUS_TOOL_*`, `TOOL_*`) and **LLM output handling** (`LLM_OUTPUT_*`).

**Try it.** `GET /api/examples` exposes four one-click vulnerable-agent demos: `vulnerable_agent.py`, `unsafe_output.py`, `unsafe_rag.py`, `exploit_demo.py`.

### Atlas hand-off for the agent surface

Every agentic scan lights up four Atlas surfaces simultaneously: `agent_tools` registry write, `agent_alerts` write (dual-written by trigger + Python), `agent_surface_timeline` snapshot, and the existing `scans`/`prompt_vectors` writes. `/api/v2/agent-tools/search` is `$rankFusion` of vector + lexical, so queries like "shell exec without allowlist" match semantically *and* lexically.

**Index files** (apply via `mongosh` or Atlas UI):

- `backend/scripts/atlas_indexes/agent_exploit_corpus_idx.json` → Vector Search on `agent_exploit_corpus`
- `backend/scripts/atlas_indexes/agent_tools_vector_idx.json` → Vector Search on `agent_tools`
- `backend/scripts/atlas_indexes/agent_tools_text_idx.json` → Atlas Search on `agent_tools`

**Trigger:** paste `backend/scripts/atlas_triggers/alert_on_critical_agent_finding.js` into Atlas UI → Triggers → Database Trigger on `scans`. When not installed, `agent_alerts.fan_out_critical_alerts` writes from Python — tell them apart via `_written_by` (`atlas_trigger` vs `python_fallback`).

## Three-layer benchmark

`backend/three_layer_benchmark.py` evaluates all 151 labeled samples in `prompts.json` against three detectors + ensemble:

1. **Static rules** — regex patterns
2. **ML classifier** — TF-IDF + logistic regression (`ml_classifier.pkl`)
3. **PromptShield API** — `POST /api/scan` (Gemini + Atlas Vector Search enrichment)

Results post to `/api/v2/benchmark/runs` (timestamped model registry in Atlas). Per-prompt results write to `backend/three_layer_results.json`.

```bash
cd backend
python three_layer_benchmark.py            # ~3–7 min, needs uvicorn on :8000
curl http://localhost:8000/api/v2/benchmark/runs | python -m json.tool
```

## Positioning

- **Shift-left by design** — catch risky prompt/code changes during PR review, before merge.
- **Complementary to runtime tools** — Protect AI / Lakera monitor after deploy; PromptShield prevents issues from landing.
- **Open-source friendly** — self-hostable, community-extensible, designed for internal SDLC.

## Demo

Click **Load demo** on the scan page for a single prompt triggering every severity tier. The four example tiles below the textarea each cover one vulnerability class.

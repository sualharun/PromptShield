# PromptShield

**Secure the AI agent attack surface.** PromptShield scans prompts, code, and pull requests for prompt-injection, dangerous AI-exposed tools, and unsafe LLM output handling — then comments directly on the PR before merge. It runs static pattern analysis, AST-based dataflow taint tracking, and a Gemini-powered semantic audit in parallel and returns findings mapped to **CWE** and the **OWASP LLM Top 10 (2025)**, with concrete remediation, evidence snippets, and detector confidence.

**v0.5 — Agentic Security.** New detectors and AI prompt categories surface the agent-tool attack surface that runtime guards miss. We trace AI-controlled inputs into dangerous sinks (`subprocess`, `eval`, `cursor.execute`, `os.remove`, `requests.get`) at PR-time, so excessive-agency bugs (LLM06) and improper-output-handling bugs (LLM05) are caught before they reach production. See **[Agent tool security](#agent-tool-security-v05)** below.

In v0.4 the data layer moved to **MongoDB Atlas**, adding semantic similarity (Vector Search), fuzzy/full-text search (Atlas Search), a fused ranked search bar (`$rankFusion`), live dashboard updates over change streams, time-series risk analytics, and a server-side redaction trigger. See **[MongoDB Atlas — what we use, and why](#mongodb-atlas--what-we-use-and-why)** below.

UI is built on the **IBM Carbon Design System** (IBM Plex Sans, sharp corners, Carbon palette).

## Stack

- **Frontend** — React + Vite + Tailwind CSS + Recharts (Vitest + React Testing Library)
- **Backend** — FastAPI + **MongoDB Atlas** (primary store, v0.4+); optional one-shot SQLite import via stdlib `sqlite3`
- **Embeddings** — `sentence-transformers` (local, default) or **MongoDB Voyage AI** (`https://ai.mongodb.com/v1`)
- **AI** — **Google Vertex AI (Gemini 2.5 Flash)** via the unified `google-genai` SDK with Application Default Credentials

### MongoDB Atlas — what we use, and why

| Feature | Where it shows up | What it replaces |
| --- | --- | --- |
| **Atlas Vector Search** (`$vectorSearch`) | `SEMANTIC_JAILBREAK_MATCH` finding on every scan; `◆ Atlas · NN%` similarity badge in `FindingCard`; `/api/v2/similar`; `/api/v2/scans/{id}/similar` | Catches paraphrased attacks the regex layer misses |
| **Atlas Search** (`$search`, Lucene) | Dashboard search bar with autocomplete + facets; `/api/v2/search*` | Replaces SQL `LIKE` with fuzzy + relevance scoring |
| **Hybrid Search** (`$rankFusion`) | Dashboard "◆ Atlas" `HybridSearchBar`; `/api/v2/search/hybrid` | Single ranked list combining keyword + semantic |
| **Time-series collections** + `$setWindowFields` | `/api/v2/risk-timeline` with 7-day rolling avg, charted on the dashboard | Risk-snapshot SQL table + manual window calc |
| **Change Streams** → WebSocket | Dashboard `AtlasLiveBadge` (pulses green on every new scan), `WS /api/live/scans` | Polling-based dashboards |
| **Atlas Triggers** (server-side JS) | `redact_on_scan_insert` strips secrets/PII inside the DB and writes an `audit_logs` row proving it ran | Defense-in-depth against missed redactor calls |
| **JSON Schema validation** | `scans` collection enforces shape on insert | Prevents malformed scan docs without ORM-side checks |
| **Voyage AI Embeddings** (`voyage-3-large`, 1024d) | Powers all vector workflows above | Local `sentence-transformers` (still supported as fallback) |
| **Benchmark / model registry** | `benchmark_runs` collection — `three_layer_benchmark.py` posts every evaluation (accuracy / precision / recall / F1 / confusion matrix) via `/api/v2/benchmark/runs` | Ad-hoc results in stdout / JSON files |
| **Agent tool registry** *(v0.5)* | `agent_tools` collection — every `@tool` / `tools=[...]` we've ever scanned, with risk level, framework, capabilities, embedding; `/api/v2/agent-tools*` and hybrid `$rankFusion` search over it | Ephemeral findings list per scan |
| **Tool-exploit knowledge base** *(v0.5)* | `agent_exploit_corpus` time-series-ish vector store of curated dangerous-tool patterns; `POST /api/v2/agent-tools/similar-exploits` matches a tool to known exploits via Atlas Vector Search | Static rule list with no semantic match |
| **Agent alert fan-out** *(v0.5)* | Atlas **Trigger** `alert_on_critical_agent_finding` + Python fallback writer → `agent_alerts` collection; `/api/v2/agent-alerts*` | Lossy logs + missed pages |
| **Agent surface time-series** *(v0.5)* | `agent_surface_timeline` time-series collection + `$setWindowFields` (7-day rolling agentic risk); `/api/v2/agent-surface-timeline` | No way to see attack-surface drift over time |
| **GridFS** *(planned)* | `ml_classifier.pkl` model registry | Filesystem `.pkl` files |

## Features

- **Layered detection** — 7 static-rule categories run in parallel with a Gemini semantic auditor
- **Risk score 0–100** — weighted by severity (critical 40, high 20, medium 8, low 3), capped at 100
- **CWE / OWASP mapping** — every finding ships with `CWE-xxx` and `LLMxx` chips
- **Evidence snippets** — short quoted excerpt from the input shown next to each finding
- **Detector confidence** — surfaced per-finding in the UI, used as secondary sort key
- **Filter & search** — severity chips and full-text search on the report
- **Privacy by default** — secrets, emails, SSNs, phone numbers redacted before persistence
- **Per-IP rate limiting** — sliding-window limiter on `POST /api/scan` (configurable)
- **Structured JSON logging** — every request gets a `request_id` echoed in headers and logs
- **Persistent history** — last 10 scans, click any to reload
- **Animated risk gauge + analytics** — bar / radar / trend (all Carbon-themed)
- **Compliance dashboard** — CWE / OWASP LLM mappings, compliance ratio, language coverage
- **Audit trail** — immutable-style event log for scans, fix suggestions, and jailbreak simulations
- **Multi-language scanning** — Python + JavaScript/TypeScript heuristics in PR and manual scan flows
- **Exportable reports** — CSV and PDF compliance reports for governance teams
- **AI fix suggestions** — one-click secure refactor guidance per finding
- **Jailbreak simulator** — test whether flagged prompts are likely exploitable
- **Structural jailbreak engine** — 14 attack payloads across 6 categories with structural analysis
- **AST-based dataflow analysis** — taint tracking from sources through assignments/f-strings to LLM sinks
- **Dependency CVE scanning** — checks LLM SDK versions (langchain, openai, transformers, etc.) against known advisories
- **False-positive suppression** — mark findings as false positives; suppressed across future scans via signature matching
- **Evaluation benchmark** — 100-sample ground-truth suite (50 vulnerable, 50 safe) achieving 96% F1
- **Policy-as-code** — `.promptshield.yml` per repo for gates, severity overrides, and ignore rules
- **PM dashboard** — author leaderboards, blocked PRs, remediation deltas (role-gated)
- **Role-based auth** — admin/pm/viewer roles with signed-cookie sessions
- **Cross-repo intelligence** — recurring findings and trending vuln types across repositories
- **Slack/Teams notifications** — webhook alerts on gate failures
- **Enterprise readiness view** — scaling indicators and 1000-repo target progress

## Run locally

### 1. Backend (port 8000)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill in GOOGLE_CLOUD_PROJECT (optional)
gcloud auth application-default login   # one-time, for Vertex AI
uvicorn main:app --reload --port 8000
```

The backend works without `GOOGLE_CLOUD_PROJECT` — it skips the AI layer and returns static-only + dataflow findings.
The backend also works without `MONGODB_URI` — Mongo features fall back to in-process equivalents (mongomock) so dev / CI keeps working.

**Login.** PromptShield does not expose a public signup endpoint (private deployment / hackathon-grade). On first startup, if the `users` collection is empty and `BOOTSTRAP_ADMIN_EMAIL` + `BOOTSTRAP_ADMIN_PASSWORD` are set in `.env`, an admin user is created automatically:

```env
BOOTSTRAP_ADMIN_EMAIL=demo@promptshield.dev
BOOTSTRAP_ADMIN_PASSWORD=change-me-please
BOOTSTRAP_ADMIN_NAME=Demo Admin
```

After the first startup you can log in via `POST /api/auth/login` (or the **Sign in** page in the UI) with those credentials. To add more users, hit `POST /api/admin/users` while authenticated as the bootstrap admin.

Run tests:
```bash
pytest
```

### 1b. MongoDB Atlas setup (5 min, free tier)

1. Create a free **M0 cluster** at [cloud.mongodb.com](https://cloud.mongodb.com).
2. **Database Access** → add a user with read/write to any database.
3. **Network Access** → add `0.0.0.0/0` (open to internet, fine for hackathon demo).
4. **Connect → Drivers → Python** → copy the `mongodb+srv://…` URI into `backend/.env`:
   ```
   MONGODB_URI=mongodb+srv://<user>:<pass>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   PRIMARY_STORE=mongo
   ```
5. Provision the Atlas Search + Vector Search indexes:
   ```bash
   python backend/scripts/setup_atlas_indexes.py
   ```
   (If your driver can't auto-create indexes, the script prints the JSON and step-by-step UI instructions.)
6. *(Optional)* Migrate existing SQLite history into Atlas:
   ```bash
   python backend/scripts/migrate_sqlite_to_mongo.py
   ```
7. *(Optional)* Install the **`redact_on_scan_insert`** Atlas Trigger by following the header comment in [`backend/scripts/atlas_triggers/redact_on_scan_insert.js`](backend/scripts/atlas_triggers/redact_on_scan_insert.js).

After restart, hit `GET /api/health` — `mongo.ok` should be `true` and `corpus_size` should be `151` (the seeded prompts).

### 2. Frontend (port 5173)

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Vite proxies `/api/*` to the backend on port 8000.

## GitHub App setup (PR review bot)

PromptShield can auto-review pull requests, post inline comments on risky lines,
and create a Check Run gate.

### 1. Create the GitHub App

Go to `https://github.com/settings/apps/new` and set:

- **Webhook URL**: `https://YOUR_HOST/api/github/webhook`
- **Webhook secret**: choose a strong value (store it for `.env`)

Permissions:

- Pull requests: **Read and write**
- Checks: **Read and write**
- Contents: **Read-only**
- Metadata: **Read-only**

Subscribe to events:

- Pull request

### 2. Install and key material

- Generate a private key (`.pem`) from the GitHub App page.
- Install the app on a test repository.

### 3. Configure backend env

Create/edit `backend/.env`:

```env
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PATH=/absolute/path/to/your-app.private-key.pem
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
RISK_GATE_THRESHOLD=70
DASHBOARD_BASE_URL=http://localhost:5173
```

`backend/config.py` auto-loads `backend/.env`, so no manual export is required.

### 4. Local webhook forwarding

**ngrok (recommended)** — from the repo root, with `uvicorn` already on port 8000:

1. Terminal A: `cd backend && uvicorn main:app --reload --port 8000`
2. Terminal B: `./backend/scripts/ngrok_http_8000.sh` (or `ngrok http 8000`)
3. Terminal C: `./backend/scripts/github_webhook_url.sh` — prints the exact **Webhook URL** to paste into your GitHub App settings (`…/api/github/webhook`). Re-run step 3 whenever ngrok restarts with a new hostname.

Alternatives:

- `npx smee-client --url https://smee.io/YOUR_CHANNEL --target http://localhost:8000/api/github/webhook`
- `ngrok http 8000` manually, then set GitHub webhook URL to `https://<ngrok-id>.ngrok-free.app/api/github/webhook` (must end with `/api/github/webhook`).

### 5. Validate end-to-end

1. Open a PR with intentionally vulnerable prompt/code changes.
2. Confirm PromptShield posts inline review comments only on added diff lines.
3. Confirm a Check Run named `PromptShield` appears with score and gate result.
4. Confirm Dashboard shows a new PR scan row in `Dashboard` tab.

### 6. Quick health check

```bash
curl http://localhost:8000/api/health
```

Expected after config is complete:

```json
{
  "status": "ok",
  "version": "0.5.0",
  "github_app_configured": true,
  "mongo": { "ok": true, "db": "promptshield" },
  "primary_store": "mongo",
  "embedding_provider": "voyage",
  "ai": {
    "provider": "gemini",
    "model": "gemini-2.5-flash",
    "configured": true,
    "vertex_location": "us-central1"
  },
  "agent_security": true
}
```

### 7. Troubleshooting checklist

If PR scans are not showing up, verify each item in order:

1. `GET /api/health` returns `"github_app_configured": true`.
2. App is **installed** on the target repository (not just created).
3. Webhook delivery in GitHub App settings shows `2xx` responses.
4. `GITHUB_WEBHOOK_SECRET` in `backend/.env` matches the App webhook secret.
5. Private key path is valid and readable by backend process.
6. Webhook forwarding (`ngrok`/`smee`) points to `http://localhost:8000/api/github/webhook`.
7. PR contains new/changed lines; PromptShield only comments on added diff lines.

Run tests:
```bash
npm test
```

## Configuration

All backend settings are env-driven (see `backend/.env.example`):

| Var | Default | Purpose |
| --- | --- | --- |
| `GOOGLE_CLOUD_PROJECT` | — | Required for AI layer (Vertex AI). Empty = static-only mode. |
| `GOOGLE_CLOUD_LOCATION` | `us-central1` | Vertex region |
| `GOOGLE_GENAI_USE_VERTEXAI` | `true` | Tells `google-genai` SDK to use Vertex (vs. AI Studio key) |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Override model (`gemini-2.5-pro` for higher quality) |
| `DATABASE_URL` | `sqlite:///./promptshield.db` | Only for `scripts/migrate_sqlite_to_mongo.py` (legacy `.db` path) |
| `MONGODB_URI` | — | Atlas SRV connection string (enables all `/api/v2/*` features) |
| `MONGODB_DB` | `promptshield` | Atlas database name |
| `PRIMARY_STORE` | `mongo` | `mongo` \| `sql` \| `dual` |
| `EMBEDDING_PROVIDER` | `voyage` | `voyage` \| `local` (sentence-transformers) |
| `EMBEDDING_MODEL` | `voyage-3-large` | Voyage model id |
| `EMBEDDING_DIMS` | `1024` | Must match `numDimensions` in the Atlas Vector Search index |
| `VOYAGE_API_KEY` | — | Required when `EMBEDDING_PROVIDER=voyage` |
| `ALLOWED_ORIGINS` | `localhost:5173` | CORS allow-list |
| `SCAN_RATE_LIMIT` / `SCAN_RATE_WINDOW` | `10` / `60s` | Per-IP rate limit |
| `MAX_INPUT_CHARS` | `50000` | Input size cap |
| `REDACT_PERSISTED_INPUT` | `true` | Redact secrets/PII before write |
| `LOG_LEVEL` | `INFO` | Structured JSON logs |

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/scan` | Body `{text}`. Runs static + dataflow + Gemini layers in parallel, persists, returns full report. Rate-limited. |
| `GET` | `/api/scans` | Last 10 scan summaries. Accepts `?source=web|github` (limit bumps to 25 for github). |
| `GET` | `/api/examples` | Returns the demo vulnerable-agent files for one-click "Try with..." buttons on the scan page. |
| `GET` | `/api/scans/{id}` | Full scan by id. |
| `DELETE` | `/api/scans/{id}` | Delete a stored scan. |
| `GET` | `/api/dashboard/github` | KPIs + recent PR scans + per-repo aggregates. |
| `GET` | `/api/dashboard/compliance` | Compliance view (CWE / OWASP / language breakdown). |
| `GET` | `/api/audit-logs` | Audit trail events (`source`, `action`, `limit` filters). |
| `GET` | `/api/risk-timeline` | Risk trend points and trend delta (`source`, `days`). |
| `GET` | `/api/reports/compliance.csv` | Export detailed compliance findings as CSV. |
| `GET` | `/api/reports/compliance.pdf` | Export compliance summary report as PDF. |
| `GET` | `/api/enterprise/readiness` | Scale posture and 1000-repo readiness indicators. |
| `POST` | `/api/findings/suggest-fix` | Generate AI-backed secure fix suggestion for one finding. |
| `POST` | `/api/jailbreak/simulate` | Heuristic jailbreak exploitability simulation. |
| `POST` | `/api/jailbreak/simulate/v2` | Structural jailbreak simulation (14 payloads, 6 categories). |
| `GET` | `/api/benchmark/results` | Run 100-sample evaluation benchmark. |
| `POST` | `/api/dependency-scan` | Scan dependency manifests (requirements.txt, package.json) for CVEs. |
| `GET/POST` | `/api/suppressions` | List or create false-positive suppressions. |
| `DELETE` | `/api/suppressions/{id}` | Remove a suppression. |
| `GET` | `/api/dashboard/pm` | PM analytics — authors, blocked PRs, remediation deltas (auth required). |
| `GET` | `/api/dashboard/cross-repo` | Cross-repo recurring findings and trending vuln types. |
| `POST` | `/api/auth/login` | Email/password login (sets session cookie). |
| `POST` | `/api/auth/logout` | Clear session. |
| `GET` | `/api/auth/me` | Current user info. |
| `POST` | `/api/policy/validate` | Validate a `.promptshield.yml` policy file. |
| `GET` | `/api/policy/example` | Example policy YAML. |
| `POST` | `/api/github/webhook` | GitHub App webhook (signature-verified). |
| `POST` | `/api/github/sync` | Backfill scans: walks **all** App installations, **all** installed repos (paginated), and **all open PRs** per repo. Optional `?include_closed=true` scans up to 500 recently-updated **closed** PRs per repo (webhook misses). Branch-only pushes never appear — only pull requests. |
| `GET` | `/api/health` | Liveness + version + `github_app_configured` + Mongo status. |

#### MongoDB Atlas-powered endpoints (`/api/v2/*`)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v2/health` | Atlas connection + per-feature flags + corpus size |
| `POST` | `/api/v2/similar` | Vector Search — top-k semantic neighbors of a prompt |
| `POST` | `/api/v2/corpus/seed` | Re-embed `prompts.json` into `prompt_vectors` (idempotent) |
| `GET` | `/api/v2/search` | Atlas `$search` — fuzzy + multi-field over scans/findings |
| `GET` | `/api/v2/search/autocomplete` | Atlas Search autocomplete tokenizer for the search bar |
| `GET` | `/api/v2/search/facets` | `$searchMeta` facet counts (severity, CWE) |
| `POST` | `/api/v2/search/hybrid` | `$rankFusion` of `$vectorSearch` + `$search` over `scans` |
| `GET` | `/api/v2/risk-timeline` | Time-series collection + `$setWindowFields` (7-day rolling avg) |
| `GET` | `/api/v2/scans` | List scans straight from Mongo |
| `GET` | `/api/v2/scans/{id}` | Single scan from Mongo |
| `GET` | `/api/v2/scans/{id}/similar` | Find historical scans semantically close to this one |
| `GET` | `/api/v2/aggregations/repos` | `$group` aggregate of repos by avg/max risk |
| `GET` | `/api/v2/aggregations/llm-targets` | LLM target distribution |
| `GET` | `/api/v2/aggregations/top-cwes` | Top CWEs in last N days |
| `POST` | `/api/v2/benchmark/runs` | Persist a benchmark run (model registry) |
| `GET` | `/api/v2/benchmark/runs` | List recent benchmark runs |
| `WS`   | `/api/live/scans` | Live change-stream feed (drives the dashboard `AtlasLiveBadge`) |
| `GET` | `/api/v2/agent-tools` | Catalog of AI-exposed tools observed across all scans (filterable by repo / risk_level / framework / capability) |
| `GET` | `/api/v2/agent-tools/aggregations/capabilities` | `$unwind`+`$group` over capabilities — the "what kinds of dangerous things have we seen" tile |
| `GET` | `/api/v2/agent-tools/aggregations/frameworks` | LangChain vs MCP vs OpenAI vs CrewAI exposure |
| `POST` | `/api/v2/agent-tools/similar-exploits` | Atlas `$vectorSearch` over `agent_exploit_corpus` — match a tool to known dangerous patterns |
| `POST` | `/api/v2/agent-tools/exploit-corpus/seed` | Embed + upsert the curated exploit knowledge base (idempotent unless `force=true`) |
| `POST` | `/api/v2/agent-tools/search` | Hybrid `$rankFusion` of `$vectorSearch` + `$search` over the tool registry |
| `GET` | `/api/v2/agent-alerts` | Recent critical / high agentic findings (written by the Atlas Trigger or the Python fallback) |
| `POST` | `/api/v2/agent-alerts/{id}/acknowledge` | Acknowledge an agent alert |
| `GET` | `/api/v2/agent-surface-timeline` | Time-series of agent attack-surface size + 7-day rolling risk |

Every response includes an `x-request-id` header that matches the `request_id` field in the JSON logs.

## Detection coverage (static layer)

`DIRECT_INJECTION`, `SECRET_IN_PROMPT`, `SYSTEM_PROMPT_EXPOSED`, `ROLE_CONFUSION`, `OVERLY_PERMISSIVE`, `DATA_LEAKAGE`, `INDIRECT_INJECTION` — each mapped to a CWE and an OWASP LLM category. The AI layer adds semantic findings the regex layer cannot catch.

Enhanced leakage coverage includes DB credential patterns, PII classes (email, SSN, phone, card-like values), and likely user-data flow into external LLM API calls.

## Agent tool security (v0.5)

PromptShield is one of the few PR-time scanners that models the **agent-tool attack surface**. We treat any function exposed to an LLM (`@tool`, `@mcp.tool`, OpenAI/Anthropic `tools=[...]`, LangChain `Tool(...)`, CrewAI / Pydantic-AI `@agent.tool`) as a privileged entry point and trace its arguments into dangerous sinks at AST level.

| Finding type                | What we catch                                                                          | CWE     | OWASP                              |
| --------------------------- | -------------------------------------------------------------------------------------- | ------- | ---------------------------------- |
| `DANGEROUS_TOOL_CAPABILITY` | `@tool` body performs `subprocess`, `os.remove`, raw SQL, etc. with no safeguards      | CWE-78  | LLM06 — Excessive Agency           |
| `TOOL_UNVALIDATED_ARGS`     | Tool parameter flows directly into a dangerous sink with no validation                 | CWE-78  | LLM06 — Excessive Agency           |
| `TOOL_EXCESSIVE_SCOPE`      | Tool accepts arbitrary paths / URLs / table names with no allowlist                    | CWE-732 | LLM06 — Excessive Agency           |
| `TOOL_PARAM_TO_EXEC/SHELL/SQL` | Dataflow taint trace from tool param → `eval`/`subprocess`/`cursor.execute`         | CWE-95/78/89 | LLM06 — Excessive Agency      |
| `LLM_OUTPUT_TO_EXEC`        | LLM response (`response.text`, `completion.choices`) passed to `eval()` / `exec()`     | CWE-95  | LLM05 — Improper Output Handling   |
| `LLM_OUTPUT_TO_SHELL`       | LLM output piped into `subprocess.run`, `os.system`, `os.popen`                        | CWE-78  | LLM05 — Improper Output Handling   |
| `LLM_OUTPUT_TO_SQL`         | LLM output interpolated into raw `cursor.execute` (no parameterized query)             | CWE-89  | LLM05 — Improper Output Handling   |
| `LLM_OUTPUT_UNESCAPED`      | LLM response rendered as HTML (`innerHTML`, `dangerouslySetInnerHTML`) without escape  | CWE-79  | LLM05 — Improper Output Handling   |
| `RAG_UNSANITIZED_CONTEXT`   | Vector-store retrieval results concatenated into prompt with no sanitization           | CWE-74  | LLM01 — Prompt Injection           |

The score breakdown surfaces these as two new categories on every PR check run:

| Category              | Source                                       |
| --------------------- | -------------------------------------------- |
| **Agent tool security** | All `DANGEROUS_TOOL_*` and `TOOL_*` types  |
| **LLM output handling** | All `LLM_OUTPUT_*` types                   |

**Try it.** The scan page exposes four one-click vulnerable-agent demos via `GET /api/examples`: `vulnerable_agent.py`, `unsafe_output.py`, `unsafe_rag.py`, and `exploit_demo.py` (an end-to-end attack chain). Load any of them and run a scan to see the new categories light up.

### Atlas, applied to the agent attack surface (v0.5)

The agentic detectors don't just produce findings — they hydrate four new MongoDB Atlas collections that turn one-off PR scans into a queryable knowledge base of every AI tool surface across every repo we've ever scanned. Each collection is exposed via dedicated endpoints (see the `/api/v2/agent-*` table above) and is wired into the scan pipeline automatically — no extra calls required from the frontend or webhook.

| Collection | Atlas feature | What it gives us |
| --- | --- | --- |
| `agent_tools` | Atlas Search (Lucene) + Vector Search + `$rankFusion` | A live registry of every `@tool` / `tools=[...]` function we've ever seen, with risk level, framework, capabilities, missing safeguards, and an embedding for hybrid lookup |
| `agent_exploit_corpus` | Atlas Vector Search (`numDimensions: 1024`, cosine) | 12 curated dangerous-tool patterns (LangChain `PythonREPLTool`, MCP shell-exec, RAG injection, etc.); `POST /api/v2/agent-tools/similar-exploits` returns the top-k semantically closest exploits to any tool you describe |
| `agent_alerts` | **Atlas Trigger** (`scripts/atlas_triggers/alert_on_critical_agent_finding.js`) — fan-out of any `scans` insert that contains a critical/high agentic finding, with a Python fallback writer for local / mongomock dev | A deduped feed of the highest-severity agentic findings, acknowledgeable via API |
| `agent_surface_timeline` | **Time-series collection** + `$setWindowFields` (7-day rolling avg) | A timeline of how big each repo's agent attack surface is and how risky it's getting over time |

**Why this matters for the demo:** every agentic scan lights up four Atlas surfaces simultaneously — registry write (`agent_tools`), alert write (`agent_alerts`, dual-written by trigger + Python), timeline snapshot (`agent_surface_timeline`), and the existing `scans`/`prompt_vectors` writes. The `/api/v2/agent-tools/search` endpoint is `$rankFusion` of vector + lexical search, the same primitive we use for the global scan search bar — but scoped to the tool registry, so judges can type "shell exec without allowlist" and pull back every `@tool` in the catalog that matches semantically *and* lexically.

**Index files** — apply with `mongosh` or the Atlas UI:

| File | Index type | Collection |
| --- | --- | --- |
| `backend/scripts/atlas_indexes/agent_exploit_corpus_idx.json` | Vector Search | `agent_exploit_corpus` |
| `backend/scripts/atlas_indexes/agent_tools_vector_idx.json`   | Vector Search | `agent_tools` |
| `backend/scripts/atlas_indexes/agent_tools_text_idx.json`     | Atlas Search  | `agent_tools` |

**Trigger file** — paste into Atlas UI → Triggers → Database Trigger on `scans`:

```
backend/scripts/atlas_triggers/alert_on_critical_agent_finding.js
```

When the trigger isn't installed (local dev, mongomock, or sandboxed CI) the same write happens from `agent_alerts.fan_out_critical_alerts` inside the Python scan path — so the API contract is identical in both modes; you can tell them apart via the `_written_by` field (`atlas_trigger` vs `python_fallback`).

**Frontend hand-off (new endpoints to wire up).** All endpoints are read-only except where noted; everything below is already covered by integration tests in `backend/tests/test_phase8_atlas.py`.

| UI surface | Endpoint | Notes |
| --- | --- | --- |
| Tool catalog page (per repo or global) | `GET /api/v2/agent-tools?repo_full_name=&risk_level=&framework=&capability=&limit=` | Returns `{ tools: [...], total }` with `risk_level`, `capabilities[]`, `missing_safeguards[]`, `evidence_samples[]`, `framework`, `last_seen_scan_id`, `cwe`, `owasp` |
| Capability donut / framework donut | `GET /api/v2/agent-tools/aggregations/capabilities`, `.../frameworks` | Pre-aggregated counts |
| "Match this tool to known exploits" panel | `POST /api/v2/agent-tools/similar-exploits` body `{ "text": "...", "k": 5 }` | Returns top-k from `agent_exploit_corpus` with similarity scores and remediation guidance |
| Tool search bar | `POST /api/v2/agent-tools/search` body `{ "query": "...", "k": 10 }` | `$rankFusion` over tool registry; falls back to lexical regex if Atlas Search index isn't present |
| Critical agentic alerts inbox | `GET /api/v2/agent-alerts?status=open&limit=` | Each alert has `severity`, `tool_name`, `repo_full_name`, `cwe`, `owasp`, `_written_by` (use this to badge "Atlas Trigger" vs "Python fallback") |
| Acknowledge alert | `POST /api/v2/agent-alerts/{id}/acknowledge` | |
| Attack-surface trend chart | `GET /api/v2/agent-surface-timeline?repo_full_name=&days=30` | Returns `[{ ts, tool_count, output_count, rag_count, risk_score, risk_score_7d_avg }]` |
| Seed exploit corpus (admin / first-run) | `POST /api/v2/agent-tools/exploit-corpus/seed` body `{ "force": false }` | Idempotent; needed once per Atlas environment so similar-exploits returns results |

The Atlas-status indicator on the dashboard will already light up green for the new collections once they're populated by a single scan against any of the three demo files in `/api/examples`.

## Three-layer benchmark (Atlas as a model registry)

`backend/three_layer_benchmark.py` evaluates every prompt in `prompts.json` (151 labeled samples) against three independent detectors and an ensemble:

1. **Static rules** — regex patterns
2. **ML classifier** — TF-IDF + logistic regression (`ml_classifier.pkl`)
3. **PromptShield API** — `POST /api/scan` (Gemini semantic + Atlas Vector Search enrichment)

It computes accuracy / precision / recall / F1 / confusion matrix for the ensemble and `POST`s the summary to `/api/v2/benchmark/runs`, persisting it in the Atlas `benchmark_runs` collection. Treat that collection as a versioned model registry — every evaluation is timestamped and queryable.

```bash
cd backend
python three_layer_benchmark.py            # ~3–7 min, needs uvicorn running on :8000
curl http://localhost:8000/api/v2/benchmark/runs | python -m json.tool
```

The terminal also writes per-prompt results to `backend/three_layer_results.json`.

## Positioning

- **Shift-left by design**: PromptShield catches risky prompt/code changes during PR review, before merge.
- **Runtime tools are complementary**: Protect AI / Lakera style runtime monitoring is useful after deploy; PromptShield prevents known issues from landing in production in the first place.
- **Open-source friendly**: self-hostable, community-extensible, and designed for internal SDLC workflows.

## Demo

Click **Load demo** on the scan page for a single prompt that triggers every severity tier. The four example tiles below the textarea cover one vulnerability class each.

## GitHub App (real-time PR scanning)

PromptShield ships a GitHub App that auto-reviews pull requests, comments on risky lines, and creates a Check Run gate. For full setup instructions, see **GitHub App setup (PR review bot)** above.

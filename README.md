# PromptShield

AI-powered prompt security scanner. Paste a prompt or code snippet — PromptShield runs static pattern analysis and a Claude-powered semantic audit in parallel and returns ranked vulnerabilities mapped to **CWE** and the **OWASP LLM Top 10**, with concrete remediation, evidence snippets, and detector confidence.

In v0.4 the data layer moved to **MongoDB Atlas**, adding semantic similarity (Vector Search), fuzzy/full-text search (Atlas Search), a fused ranked search bar (`$rankFusion`), live dashboard updates over change streams, time-series risk analytics, and a server-side redaction trigger. See **[MongoDB Atlas — what we use, and why](#mongodb-atlas--what-we-use-and-why)** below.

UI is built on the **IBM Carbon Design System** (IBM Plex Sans, sharp corners, Carbon palette).

## Stack

- **Frontend** — React + Vite + Tailwind CSS + Recharts (Vitest + React Testing Library)
- **Backend** — FastAPI + **MongoDB Atlas** (primary store, v0.4+); optional one-shot SQLite import via stdlib `sqlite3`
- **Embeddings** — `sentence-transformers` (local, default) or **MongoDB Voyage AI** (`https://ai.mongodb.com/v1`)
- **AI** — Anthropic Claude (`claude-sonnet-4-20250514`)

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
| **GridFS** *(planned)* | `ml_classifier.pkl` model registry | Filesystem `.pkl` files |

## Features

- **Layered detection** — 7 static-rule categories run in parallel with a Claude semantic auditor
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
cp .env.example .env  # fill in ANTHROPIC_API_KEY (optional)
uvicorn main:app --reload --port 8000
```

The backend works without `ANTHROPIC_API_KEY` — it skips the AI layer and returns static-only findings.
The backend also works without `MONGODB_URI` — Mongo features fall back to in-process equivalents (mongomock) so dev / CI keeps working.

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

Use one of these:

- `npx smee-client --url https://smee.io/YOUR_CHANNEL --target http://localhost:8000/api/github/webhook`
- `ngrok http 8000` then set GitHub webhook URL to `https://<ngrok-id>.ngrok.io/api/github/webhook`

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
  "version": "0.3.0",
  "github_app_configured": true,
  "mongo": { "ok": true, "db": "promptshield" },
  "primary_store": "mongo",
  "embedding_provider": "voyage"
}
```

Run tests:
```bash
npm test
```

## Configuration

All backend settings are env-driven (see `backend/.env.example`):

| Var | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | — | Required for AI layer |
| `AI_MODEL` | `claude-sonnet-4-20250514` | Override model |
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
| `POST` | `/api/scan` | Body `{text}`. Runs both layers, persists, returns full report. Rate-limited. |
| `GET` | `/api/scans` | Last 10 scan summaries. Accepts `?source=web|github` (limit bumps to 25 for github). |
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

Every response includes an `x-request-id` header that matches the `request_id` field in the JSON logs.

## Detection coverage (static layer)

`DIRECT_INJECTION`, `SECRET_IN_PROMPT`, `SYSTEM_PROMPT_EXPOSED`, `ROLE_CONFUSION`, `OVERLY_PERMISSIVE`, `DATA_LEAKAGE`, `INDIRECT_INJECTION` — each mapped to a CWE and an OWASP LLM category. The AI layer adds semantic findings the regex layer cannot catch.

Enhanced leakage coverage includes DB credential patterns, PII classes (email, SSN, phone, card-like values), and likely user-data flow into external LLM API calls.

## Three-layer benchmark (Atlas as a model registry)

`backend/three_layer_benchmark.py` evaluates every prompt in `prompts.json` (151 labeled samples) against three independent detectors and an ensemble:

1. **Static rules** — regex patterns
2. **ML classifier** — TF-IDF + logistic regression (`ml_classifier.pkl`)
3. **PromptShield API** — `POST /api/scan` (Claude semantic + Atlas Vector Search enrichment)

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

PromptShield ships a GitHub App that auto-reviews every pull request: it scans only the lines the author added, posts inline review comments on risky prompt code, and writes a **Check Run** that can block merges when the risk score crosses `RISK_GATE_THRESHOLD` (default `70`). Every PR scan also lands in the **Dashboard** tab of the React app alongside web scans.

### 1. Create the GitHub App

Go to https://github.com/settings/apps/new and configure:

- **Webhook URL** — `https://YOUR_PUBLIC_HOST/api/github/webhook` (use `smee.io` or `ngrok` for local dev).
- **Webhook secret** — a strong random string. Set the same value as `GITHUB_WEBHOOK_SECRET`.
- **Repository permissions** — Pull requests: **Read & write**, Checks: **Read & write**, Contents: **Read-only**, Metadata: **Read-only**.
- **Subscribe to events** — `Pull request`.
- After creating, **Generate a private key** (downloads a `.pem`).

Install the App on a test repo from the App's **Install App** tab.

### 2. Set the env vars

Add to `backend/.env`:

```env
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PATH=/abs/path/to/your-app.private-key.pem
# or paste the PEM inline:
# GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"
GITHUB_WEBHOOK_SECRET=your-webhook-secret
RISK_GATE_THRESHOLD=70
DASHBOARD_BASE_URL=https://your-dashboard.example.com
```

`GET /api/health` returns `"github_app_configured": true` once all three (App ID, private key, webhook secret) are set.

### 3. Try it

Open a PR that adds a vulnerable prompt (e.g. one of the demo strings). Within a few seconds:

- Inline review comments appear **only on lines you added** (never on unchanged code).
- A `PromptShield` Check Run shows the risk score and fails the gate when it crosses the threshold.
- A new row appears in the **Dashboard** tab; click it to load the full report.

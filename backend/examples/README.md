# Vulnerable agent demo files

These files are loaded by `GET /api/examples` and rendered as one-click
"Try with..." buttons on the scan page. Each file MUST trigger at least one
finding from the agentic-security detector layer (static rules + dataflow +
Gemini AI audit) so the demo is reliably reproducible.

## Conventions

- Filename = lowercase snake_case, ends in `.py`.
- File stem matches a key in `_EXAMPLE_DESCRIPTIONS` (`backend/main.py`); add
  a description there when adding a new file.
- Keep files under 50 KB and self-contained (no external imports beyond
  stdlib + the framework being demo'd).
- Files starting with `_` are ignored by the endpoint.

## Required demo files (owned by Dev 1 / Cyber)

| File                  | What it demonstrates                                              |
| --------------------- | ----------------------------------------------------------------- |
| `vulnerable_agent.py` | `@tool` / `@mcp.tool` exposing shell, file, and SQL capabilities  |
| `unsafe_output.py`    | LLM response piped into `eval()`, `subprocess`, raw SQL           |
| `unsafe_rag.py`       | Vector retrieval results concatenated into prompt unsanitized     |

When all three are present, the integration test suite in
`backend/tests/test_integration_agentic.py` should pass end-to-end.

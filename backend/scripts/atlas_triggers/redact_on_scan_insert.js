/**
 * Atlas Trigger: redact_on_scan_insert
 *
 * Fires AFTER an insert on `promptshield.scans`. Strips secrets / PII from
 * `input_text` and writes a redacted copy back into the same document, plus
 * sets `_redacted_by_db: true` so the audit log can prove the database
 * itself sanitized the data.
 *
 * This is a defense-in-depth layer: the Python backend's redactor in
 * `redaction.py` runs first, but if any code path ever forgets to call it
 * (or a future contributor disables it), Atlas catches the leak server-side.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * To install (one-time, ~3 min in the Atlas UI):
 *
 *   1) cloud.mongodb.com → your project → "App Services" → "Triggers"
 *   2) "Add a Trigger" → Trigger Type: Database
 *   3) Name: redact_on_scan_insert
 *   4) Cluster: Cluster0   Database: promptshield   Collection: scans
 *   5) Operation Type: Insert    Full Document: ON
 *   6) Function → "+ New Function" → paste this whole file as the body
 *   7) Save → Enable Trigger
 *
 * Verify: insert a scan with a fake API key in input_text, then re-fetch
 * the document — the API key should be replaced with [REDACTED:SECRET].
 * ──────────────────────────────────────────────────────────────────────────
 */
// Name of the *Linked Data Source* in App Services → Linked Data Sources.
// By default this matches the cluster name (e.g. "Cluster0"). If yours is
// different, change it here. Getting this wrong is the #1 cause of the error
//   "non-recoverable error processing event: Cannot access member 'db' of undefined"
const LINKED_DATA_SOURCE = "Cluster0";

exports = async function (changeEvent) {
  const fullDoc = changeEvent.fullDocument;
  if (!fullDoc || !fullDoc.input_text) return;

  const original = fullDoc.input_text;

  // Patterns mirror backend/redaction.py to keep behavior consistent.
  const patterns = [
    // OpenAI / Anthropic / generic bearer secrets
    { re: /sk-[A-Za-z0-9_\-]{16,}/g, label: "[REDACTED:SECRET]" },
    { re: /ghp_[A-Za-z0-9]{20,}/g, label: "[REDACTED:GITHUB_TOKEN]" },
    { re: /AKIA[0-9A-Z]{16}/g, label: "[REDACTED:AWS_KEY]" },
    { re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, label: "[REDACTED:SLACK_TOKEN]" },
    // Generic api-key style
    { re: /(api[_-]?key|secret|token|password|bearer)[\s:=]+['"]?[A-Za-z0-9_\-]{12,}['"]?/gi,
      label: "[REDACTED:CREDENTIAL]" },
    // Email
    { re: /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g, label: "[REDACTED:EMAIL]" },
    // SSN-like
    { re: /\b\d{3}-\d{2}-\d{4}\b/g, label: "[REDACTED:SSN]" },
    // Credit-card-like (16 consecutive digits, no spaces)
    { re: /\b(?:\d[ -]*?){13,16}\b/g, label: "[REDACTED:CARD]" },
    // US phone
    { re: /\b(?:\+?1[ -]?)?(?:\(\d{3}\)|\d{3})[ -]?\d{3}[ -]?\d{4}\b/g,
      label: "[REDACTED:PHONE]" },
  ];

  let redacted = original;
  let hits = 0;
  for (const { re, label } of patterns) {
    redacted = redacted.replace(re, () => {
      hits += 1;
      return label;
    });
  }

  if (hits === 0 && fullDoc._redacted_by_db) return;

  const collection = context.services
    .get(LINKED_DATA_SOURCE)
    .db(changeEvent.ns.db)
    .collection(changeEvent.ns.coll);

  const update = {
    $set: {
      input_text: redacted,
      _redacted_by_db: true,
      _redacted_at: new Date(),
      _redaction_hits: hits,
    },
  };

  await collection.updateOne({ _id: fullDoc._id }, update);

  // Drop a row in audit_logs so the redaction is provable.
  if (hits > 0) {
    const audit = context.services
      .get(LINKED_DATA_SOURCE)
      .db(changeEvent.ns.db)
      .collection("audit_logs");
    await audit.insertOne({
      created_at: new Date(),
      actor: "atlas-trigger",
      action: "scan.redacted_server_side",
      source: fullDoc.source || "web",
      scan_id: fullDoc._id.toString(),
      details: { hits, doc_id: fullDoc._id.toString() },
    });
  }
};

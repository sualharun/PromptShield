"""Seed the `atlas_search_synonyms` collection used by `scans_text_idx`.

Why this exists:
  Atlas Search supports synonym groups (a la WordNet). Each group makes the
  Search index treat several surface forms as equivalent at query time —
  searching "DAN" matches docs that only contain the word "jailbreak", etc.

  PromptShield's domain has a lot of these (jailbreak ≡ DAN ≡ AIM ≡ STAN,
  prompt injection ≡ system prompt override, RCE ≡ remote code execution).
  We materialize them once into a small collection that the Search index
  references via `definition.synonyms[].source.collection`.

Usage:
  python backend/scripts/seed_synonyms.py            # idempotent upsert
  python backend/scripts/seed_synonyms.py --replace  # truncate + reinsert

After running, re-run `setup_atlas_indexes.py` so the index picks up the
synonym source. Atlas re-builds in ~30-90s.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
BACKEND = HERE.parent.parent
sys.path.insert(0, str(BACKEND))

from mongo import get_db  # noqa: E402

SYNONYM_COLLECTION = "atlas_search_synonyms"

# `mappingType: equivalent` means every term in `synonyms[]` matches every
# other term. Use `explicit` (with `input` + `synonyms`) when you want
# directional rewrites instead.
SYNONYM_GROUPS = [
    {
        "mappingType": "equivalent",
        "synonyms": ["jailbreak", "DAN", "AIM", "STAN", "DUDE", "do anything now"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": [
            "prompt injection",
            "prompt-injection",
            "system prompt override",
            "instruction override",
            "ignore previous instructions",
        ],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["api key", "apikey", "access token", "bearer token", "credential"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["secret", "password", "passphrase", "private key"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["PII", "personal data", "personally identifiable information"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["RCE", "remote code execution", "code injection"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["SSRF", "server side request forgery", "server-side request forgery"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["data leak", "data exfiltration", "exfil", "leak"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["LLM", "large language model", "llm provider", "model"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["GPT", "ChatGPT", "OpenAI", "openai gpt"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["Claude", "Anthropic", "claude-3"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["Gemini", "Google Gemini", "Bard"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["XSS", "cross site scripting", "cross-site scripting"],
    },
    {
        "mappingType": "equivalent",
        "synonyms": ["SQLi", "SQL injection", "sql injection"],
    },
    {
        "mappingType": "explicit",
        "input": ["unsafe", "vulnerable", "exploitable"],
        "synonyms": ["risky", "insecure", "unsafe", "vulnerable", "exploitable"],
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Drop existing synonym docs before re-seeding.",
    )
    args = parser.parse_args()

    db = get_db()
    coll = db[SYNONYM_COLLECTION]

    if args.replace:
        deleted = coll.delete_many({}).deleted_count
        print(f"  · removed {deleted} existing synonym group(s)")

    inserted = 0
    updated = 0
    for group in SYNONYM_GROUPS:
        # Use first synonym as the stable upsert key so re-runs are idempotent.
        key_terms = group.get("input") or group.get("synonyms", [])
        key = "::".join(sorted(t.lower() for t in key_terms))[:120] or repr(group)
        res = coll.update_one(
            {"_key": key},
            {"$set": {**group, "_key": key}},
            upsert=True,
        )
        if res.upserted_id:
            inserted += 1
        elif res.modified_count:
            updated += 1

    total = coll.count_documents({})
    print(f"✓ Synonym groups: +{inserted} inserted, ~{updated} updated, {total} total")
    print(f"  Collection: {SYNONYM_COLLECTION}")
    print(
        "\nNext step:\n  Re-run `python backend/scripts/setup_atlas_indexes.py`\n"
        "  so `scans_text_idx` picks up the synonym source. Atlas rebuilds in ~30-90s."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

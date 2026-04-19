"""Create or update the Atlas Search + Vector Search indexes from JSON files.

Two ways to run this:

  1) Programmatic (recommended) — once your cluster is on MongoDB 7.0+ you can
     create Search & Vector Search indexes through the regular driver:

         python backend/scripts/setup_atlas_indexes.py

     This iterates `backend/scripts/atlas_indexes/*.json` and calls
     `db.<collection>.create_search_index(model)` for each one.

  2) Manual UI fallback — if your cluster is older or your driver doesn't
     support `create_search_index` yet, this script prints a step-by-step
     "paste this JSON into Atlas UI → Search → Create Index" guide.

Idempotent: existing indexes with the same name are updated rather than
re-created.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from repo root: `python backend/scripts/setup_atlas_indexes.py`
HERE = Path(__file__).resolve()
BACKEND = HERE.parent.parent  # backend/
sys.path.insert(0, str(BACKEND))

from pymongo.operations import SearchIndexModel  # noqa: E402

from config import settings  # noqa: E402
from mongo import get_client, init_collections  # noqa: E402

INDEX_DIR = HERE.parent / "atlas_indexes"


def _print_manual_instructions(spec: dict, error: Exception) -> None:
    print("\n" + "=" * 72)
    print(f"⚠ Could not auto-create index '{spec['name']}': {error}")
    print("=" * 72)
    print("Manual steps (Atlas UI):")
    print("  1) cloud.mongodb.com → your cluster → 'Atlas Search' tab")
    print("  2) 'Create Search Index' → JSON Editor")
    print(f"  3) Database: {settings.MONGODB_DB}   Collection: {spec['collection']}")
    print(f"  4) Index name: {spec['name']}")
    print(f"  5) Index type: {spec['type']}")
    print("  6) Paste this JSON definition:")
    print("-" * 72)
    print(json.dumps(spec["definition"], indent=2))
    print("-" * 72)


def main() -> int:
    if not settings.MONGODB_URI:
        print("✗ MONGODB_URI not set. Add it to backend/.env first.")
        return 2

    print(f"→ Connecting to {settings.MONGODB_URI.split('@')[-1].split('/')[0]}…")
    client = get_client()
    try:
        client.admin.command("ping")
    except Exception as e:
        print(f"✗ Could not reach Atlas: {e}")
        return 1
    print(f"✓ Connected.  Database: {settings.MONGODB_DB}")

    init_collections()
    print("✓ Collections + btree indexes ensured.")

    db = client[settings.MONGODB_DB]
    success = 0
    failed = 0
    for spec_path in sorted(INDEX_DIR.glob("*.json")):
        with spec_path.open() as f:
            spec = json.load(f)
        coll = db[spec["collection"]]
        model = SearchIndexModel(
            name=spec["name"],
            type=spec["type"],
            definition=spec["definition"],
        )
        try:
            existing = {idx["name"] for idx in coll.list_search_indexes()}
            if spec["name"] in existing:
                print(f"  · {spec['name']:<22} (already exists, updating definition)")
                coll.update_search_index(spec["name"], spec["definition"])
            else:
                print(f"  + {spec['name']:<22} (creating on {spec['collection']})")
                coll.create_search_index(model)
            success += 1
        except Exception as e:
            failed += 1
            _print_manual_instructions(spec, e)

    print("\n" + "=" * 72)
    print(f"Done.  {success} index(es) ok, {failed} need manual setup.")
    if success:
        print("\nNote: Atlas Search/Vector indexes take ~30-90s to become queryable.")
        print("      Watch the 'Status' column in cloud.mongodb.com → Atlas Search.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

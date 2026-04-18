import os
import sys
import tempfile

# Make backend/ importable regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(__file__))

# Use a temp DB so tests never touch a developer's promptshield.db.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp_db.name}")
os.environ.setdefault("REDACT_PERSISTED_INPUT", "true")
os.environ.setdefault("SCAN_RATE_LIMIT", "1000")  # don't trip during tests

from database import init_db  # noqa: E402

init_db()

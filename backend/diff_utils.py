"""Helpers for mapping scan findings onto the lines actually changed in a PR.

GitHub returns each changed file's `patch` in unified-diff format. We only want
to comment on lines the PR author *added* (lines beginning with "+" on the new
side), never on context or removed lines.
"""

import re
from typing import Dict, List, Set

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_added_lines(patch: str | None) -> Set[int]:
    """Return the set of line numbers (in the new file) that this patch adds."""
    if not patch:
        return set()
    added: Set[int] = set()
    new_line: int | None = None
    for raw in patch.splitlines():
        # New hunk header — reset the running new-side line counter.
        m = _HUNK_HEADER.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if new_line is None:
            continue
        # Skip the file headers a unified diff occasionally embeds inside the patch.
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("\\"):
            # "\ No newline at end of file" — informational, no line consumed.
            continue
        if raw.startswith("+"):
            added.add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            # Removed line — does not consume a new-side line number.
            continue
        else:
            # Context line (starts with " " or anything else) — consumes one new line.
            new_line += 1
    return added


def filter_findings_to_lines(
    findings: List[Dict], added_lines: Set[int]
) -> List[Dict]:
    """Drop findings whose line_number is not part of the diff's added lines.

    Findings without a line_number are dropped too — the bot only comments where
    it can pin a precise location, since unanchored comments quickly become noise.
    """
    if not added_lines:
        return []
    out: List[Dict] = []
    for f in findings:
        ln = f.get("line_number")
        if isinstance(ln, int) and ln in added_lines:
            out.append(f)
    return out

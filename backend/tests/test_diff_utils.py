from diff_utils import filter_findings_to_lines, parse_added_lines


SIMPLE_PATCH = """\
@@ -1,4 +1,5 @@
 def greet(name):
-    return "hi " + name
+    safe = sanitize(name)
+    return f"hi {safe}"

 # done
"""

MULTI_HUNK = """\
@@ -10,3 +10,4 @@
 a = 1
-b = 2
+b = 3
+c = 4
@@ -50,2 +51,3 @@
 x = 9
+y = 10
"""

DELETION_ONLY = """\
@@ -1,3 +1,1 @@
 keep
-removed1
-removed2
"""

WITH_NO_NEWLINE_MARKER = """\
@@ -1,2 +1,2 @@
 first
-old
+new
\\ No newline at end of file
"""


def test_simple_patch_returns_added_lines():
    assert parse_added_lines(SIMPLE_PATCH) == {2, 3}


def test_multi_hunk_patch():
    assert parse_added_lines(MULTI_HUNK) == {11, 12, 52}


def test_deletion_only_returns_empty():
    assert parse_added_lines(DELETION_ONLY) == set()


def test_no_newline_marker_does_not_consume_a_line():
    assert parse_added_lines(WITH_NO_NEWLINE_MARKER) == {2}


def test_none_or_empty_patch_returns_empty():
    assert parse_added_lines(None) == set()
    assert parse_added_lines("") == set()


def test_filter_drops_findings_off_diff():
    findings = [
        {"line_number": 5, "title": "in diff"},
        {"line_number": 99, "title": "not in diff"},
        {"line_number": None, "title": "no line"},
        {"title": "no key"},
    ]
    out = filter_findings_to_lines(findings, {5, 6})
    assert len(out) == 1
    assert out[0]["title"] == "in diff"


def test_filter_with_empty_added_lines_returns_nothing():
    assert filter_findings_to_lines([{"line_number": 1}], set()) == []

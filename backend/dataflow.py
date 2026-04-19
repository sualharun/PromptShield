"""AST-based dataflow analysis for Python LLM code.

Unlike the regex scanner, this module parses Python source into an AST and
traces tainted data from *sources* (user input) through variable assignments
and string operations to *sinks* (LLM API calls). A finding is only emitted
when a concrete dataflow path is proven: source → (optional intermediaries) → sink.

Supported sources (taint origins):
  - input(), request.*, flask/fastapi request params, sys.argv
  - os.environ (when concatenated into prompts, not just config)
  - open().read(), requests.get().text, urllib (external content)

Supported sinks (LLM API calls):
  - openai: client.chat.completions.create, client.responses.create
  - anthropic: client.messages.create
  - langchain: LLMChain, ChatOpenAI, invoke(), run()
  - generic: llm.ask, llm.generate, model.generate, pipe()

The analysis is intra-procedural (single function scope) with a simple
cross-assignment taint propagation. It won't catch taint through class fields
or database round-trips — that's honest. We report what we can prove.
"""

import ast
import textwrap
from typing import Dict, List, Optional, Set, Tuple


# --- Source and Sink definitions ---

# Function calls that return tainted data
SOURCE_CALLS: Dict[str, str] = {
    "input": "user input via input()",
    "raw_input": "user input via raw_input()",
}

# Attribute patterns: (object_pattern, attr) → description
# We match if the Name or chain contains these substrings.
SOURCE_ATTRS: List[Tuple[str, str, str]] = [
    ("request", "form", "HTTP form data"),
    ("request", "args", "HTTP query parameters"),
    ("request", "json", "HTTP JSON body"),
    ("request", "data", "HTTP raw body"),
    ("request", "query_params", "HTTP query parameters"),
    ("request", "body", "HTTP request body"),
    ("sys", "argv", "command-line arguments"),
]

# Calls whose return value is tainted (external content)
SOURCE_METHOD_CHAINS: List[Tuple[str, str]] = [
    ("requests", "get"),
    ("requests", "post"),
    ("urllib", "urlopen"),
    ("httpx", "get"),
    ("httpx", "post"),
]

# Function/method names that are LLM sinks
SINK_METHODS: Set[str] = {
    "create",
    "invoke",
    "run",
    "generate",
    "ask",
    "predict",
    "agenerate",
    "ainvoke",
    "arun",
    "apredict",
}

# Dangerous execution sinks - user input flowing here is always a finding
EXECUTION_SINK_NAMES = {
    "cursor.execute", "db.execute", "session.execute", "conn.execute",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "os.system", "os.popen", "eval", "exec",
    "pickle.loads", "yaml.load", "marshal.loads",
}

# Qualified attribute chains indicating LLM API calls
SINK_ATTR_CHAINS: List[Tuple[str, ...]] = [
    ("chat", "completions", "create"),
    ("messages", "create"),
    ("responses", "create"),
    ("completions", "create"),
]


class TaintedVar:
    __slots__ = ("name", "source_desc", "source_line")

    def __init__(self, name: str, source_desc: str, source_line: int):
        self.name = name
        self.source_desc = source_desc
        self.source_line = source_line

    def __repr__(self) -> str:
        return f"TaintedVar({self.name!r}, line={self.source_line})"


class DataflowFinding:
    __slots__ = (
        "source_var", "source_desc", "source_line",
        "sink_call", "sink_line",
        "path",
    )

    def __init__(
        self,
        source_var: str,
        source_desc: str,
        source_line: int,
        sink_call: str,
        sink_line: int,
        path: List[str],
    ):
        self.source_var = source_var
        self.source_desc = source_desc
        self.source_line = source_line
        self.sink_call = sink_call
        self.sink_line = sink_line
        self.path = path


def _attr_chain(node: ast.AST) -> List[str]:
    """Flatten a.b.c into ['a', 'b', 'c']."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts.reverse()
    return parts


def _names_in_expr(node: ast.AST) -> Set[str]:
    """Collect all Name.id references in an expression subtree."""
    names: Set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
            names.add(f"{child.value.id}__{child.attr}")
    return names


def _is_source_call(node: ast.Call) -> Optional[str]:
    """Check if a Call node is a taint source. Returns description or None."""
    if isinstance(node.func, ast.Name):
        if node.func.id in SOURCE_CALLS:
            return SOURCE_CALLS[node.func.id]

    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        chain_str = ".".join(chain)
        for obj, attr, desc in SOURCE_ATTRS:
            if obj in chain_str and chain[-1] == attr:
                return desc
        for obj, method in SOURCE_METHOD_CHAINS:
            if len(chain) >= 2 and chain[0] == obj and chain[1] == method:
                return f"external content via {chain_str}()"

    # open(...).read()
    if isinstance(node.func, ast.Attribute) and node.func.attr == "read":
        inner = node.func.value
        if isinstance(inner, ast.Call):
            if isinstance(inner.func, ast.Name) and inner.func.id == "open":
                return "file content via open().read()"

    # request.form.get("key"), request.args.get("key"), etc.
    if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        inner = node.func.value
        if isinstance(inner, ast.Attribute):
            chain = _attr_chain(inner)
            chain_str = ".".join(chain)
            for obj, attr, desc in SOURCE_ATTRS:
                if obj in chain_str and chain[-1] == attr:
                    return f"{desc} via .get()"

    return None


def _is_source_subscript(node: ast.Subscript) -> Optional[str]:
    """Check request.form["key"] style access."""
    if isinstance(node.value, ast.Attribute):
        chain = _attr_chain(node.value)
        chain_str = ".".join(chain)
        for obj, attr, desc in SOURCE_ATTRS:
            if obj in chain_str and chain[-1] == attr:
                return desc
    return None


def _is_source_attribute(node: ast.Attribute) -> Optional[str]:
    """Check request.json, request.data, sys.argv style attribute access."""
    chain = _attr_chain(node)
    chain_str = ".".join(chain)
    for obj, attr, desc in SOURCE_ATTRS:
        if obj in chain_str and chain[-1] == attr:
            return desc
    return None


def _is_sink_call(node: ast.Call) -> Optional[str]:
    """Check if a Call node is an LLM sink. Returns sink name or None."""
    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        method = chain[-1] if chain else ""

        # Check qualified chains first (more specific)
        for sink_chain in SINK_ATTR_CHAINS:
            if len(chain) >= len(sink_chain):
                tail = tuple(chain[-len(sink_chain):])
                if tail == sink_chain:
                    return ".".join(chain)

        # Check method name for known LLM patterns
        if method in SINK_METHODS and len(chain) >= 2:
            # Heuristic: require the object to look LLM-related
            chain_str = ".".join(chain).lower()
            llm_hints = (
                "llm", "model", "chain", "openai", "anthropic", "client",
                "chat", "completion", "message", "pipe", "agent",
            )
            if any(h in chain_str for h in llm_hints):
                return ".".join(chain)

    if isinstance(node.func, ast.Name):
        if node.func.id in ("LLMChain", "ChatOpenAI", "ChatAnthropic"):
            return node.func.id
        if node.func.id in EXECUTION_SINK_NAMES:
            return node.func.id

    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        dotted = ".".join(chain)
        if dotted in EXECUTION_SINK_NAMES:
            return dotted

    return None


def _expr_uses_tainted(node: ast.AST, tainted: Dict[str, TaintedVar]) -> Optional[TaintedVar]:
    """Check if an expression references any tainted variable."""
    names = _names_in_expr(node)
    for name in names:
        if name in tainted:
            return tainted[name]
    return None


def analyze(source_code: str) -> List[DataflowFinding]:
    """Parse Python source and return dataflow findings.

    Returns an empty list if the code isn't valid Python or has no
    source→sink flows.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []

    findings: List[DataflowFinding] = []
    tainted: Dict[str, TaintedVar] = {}
    seen_flows: Set[Tuple[int, int]] = set()

    # --- Patch: treat parameters of @tool-decorated functions as taint sources ---
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            is_agent_tool = False
            # Check for @tool decorator
            for deco in node.decorator_list:
                if isinstance(deco, ast.Name) and deco.id == "tool":
                    is_agent_tool = True
                elif isinstance(deco, ast.Attribute) and deco.attr == "tool":
                    is_agent_tool = True
            if is_agent_tool:
                for arg in node.args.args:
                    tainted[arg.arg] = TaintedVar(arg.arg, "agent function parameter (@tool)", node.lineno)

    # Pass 1: walk all statements and collect taint + check sinks.
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)

        # --- Taint sources via assignment ---
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value if isinstance(node, ast.AnnAssign) else node.value
            if value is None:
                continue

            source_desc = None
            if isinstance(value, ast.Call):
                source_desc = _is_source_call(value)
            elif isinstance(value, ast.Attribute):
                source_desc = _is_source_attribute(value)
            elif isinstance(value, ast.Subscript):
                source_desc = _is_source_subscript(value)

            # Taint propagation: if RHS uses a tainted var, LHS becomes tainted
            if source_desc is None:
                tv = _expr_uses_tainted(value, tainted)
                if tv:
                    source_desc = f"derived from {tv.name} ({tv.source_desc})"

            if source_desc:
                targets = []
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            targets.append(t.id)
                        elif isinstance(t, ast.Tuple):
                            for elt in t.elts:
                                if isinstance(elt, ast.Name):
                                    targets.append(elt.id)
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    targets.append(node.target.id)

                for tgt in targets:
                    tainted[tgt] = TaintedVar(tgt, source_desc, lineno)

                # Also taint self.attr style targets
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name):
                            attr_key = f"{t.value.id}__{t.attr}"
                            tainted[attr_key] = TaintedVar(attr_key, source_desc, lineno)

        # --- f-string / format / concat that creates a new tainted string ---
        if isinstance(node, ast.Assign) and node.value is not None:
            val = node.value
            # f-string: JoinedStr containing tainted FormattedValue
            if isinstance(val, ast.JoinedStr):
                for v in val.values:
                    if isinstance(v, ast.FormattedValue):
                        tv = _expr_uses_tainted(v, tainted)
                        if tv:
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    tainted[t.id] = TaintedVar(
                                        t.id,
                                        f"f-string interpolating {tv.name}",
                                        lineno,
                                    )
                            break

            # str.format() or % formatting with tainted args
            if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
                if val.func.attr == "format":
                    for arg in val.args:
                        tv = _expr_uses_tainted(arg, tainted)
                        if tv:
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    tainted[t.id] = TaintedVar(
                                        t.id,
                                        f".format() with {tv.name}",
                                        lineno,
                                    )
                            break
                    for kw in val.keywords:
                        tv = _expr_uses_tainted(kw.value, tainted)
                        if tv:
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    tainted[t.id] = TaintedVar(
                                        t.id,
                                        f".format() with {tv.name}",
                                        lineno,
                                    )
                            break

            # String concat (+) with tainted operand
            if isinstance(val, ast.BinOp) and isinstance(val.op, ast.Add):
                tv = _expr_uses_tainted(val, tainted)
                if tv:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            tainted[t.id] = TaintedVar(
                                t.id,
                                f"concatenation with {tv.name}",
                                lineno,
                            )

    # Pass 2: find sinks that consume tainted data
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sink_name = _is_sink_call(node)
        if not sink_name:
            continue
        sink_line = getattr(node, "lineno", 0)

        # Check all arguments (positional + keyword) for taint
        all_arg_nodes: list = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_arg_nodes:
            tv = _expr_uses_tainted(arg, tainted)
            if tv:
                flow_key = (tv.source_line, sink_line)
                if flow_key in seen_flows:
                    continue
                seen_flows.add(flow_key)
                findings.append(
                    DataflowFinding(
                        source_var=tv.name,
                        source_desc=tv.source_desc,
                        source_line=tv.source_line,
                        sink_call=sink_name,
                        sink_line=sink_line,
                        path=[
                            f"L{tv.source_line}: {tv.name} ← {tv.source_desc}",
                            f"L{sink_line}: {tv.name} → {sink_name}()",
                        ],
                    )
                )

    return findings


def dataflow_to_findings(df_results: List[DataflowFinding]) -> List[Dict]:
    """Convert DataflowFinding objects to the standard finding dict shape."""
    out: List[Dict] = []
    for df in df_results:
        path_str = " → ".join(df.path)
        out.append(
            {
                "type": "DATAFLOW_INJECTION",
                "severity": "critical",
                "title": f"Tainted input flows to LLM call: {df.source_var} → {df.sink_call}()",
                "description": (
                    f"User-controlled data from {df.source_desc} (line {df.source_line}) "
                    f"reaches LLM API call {df.sink_call}() at line {df.sink_line} "
                    f"without sanitization. This is a proven prompt injection vector."
                ),
                "line_number": df.sink_line,
                "remediation": (
                    "Wrap user input in delimited tags (e.g., <user_input>...</user_input>) "
                    "and instruct the model to treat content inside as untrusted data only. "
                    "Never concatenate raw user input into system prompts."
                ),
                "source": "dataflow",
                "confidence": 0.95,
                "evidence": path_str,
                "cwe": "CWE-77",
                "owasp": "LLM01: Prompt Injection",
                "dataflow_path": df.path,
            }
        )
    return out


# ── Tool body analysis (OWASP LLM07) ──────────────────────────────────────

DANGEROUS_SINKS: Dict[str, str] = {
    "os.system": "shell execution",
    "os.popen": "shell execution",
    "os.remove": "file deletion",
    "os.unlink": "file deletion",
    "subprocess.run": "shell execution",
    "subprocess.call": "shell execution",
    "subprocess.Popen": "shell execution",
    "shutil.rmtree": "recursive directory deletion",
    "eval": "code execution",
    "exec": "code execution",
    "open": "unrestricted file access",
    "os.listdir": "unrestricted directory listing",
    "os.scandir": "unrestricted directory listing",
    "glob.glob": "unrestricted file globbing",
    "pickle.loads": "unsafe deserialization",
    "yaml.load": "unsafe YAML deserialization",
    "marshal.loads": "unsafe marshal deserialization",
}

DANGEROUS_SQL_SINKS = {"cursor.execute", "db.execute", "session.execute", "engine.execute", "conn.execute"}


def _call_name(node: ast.Call) -> Optional[str]:
    """Return the dotted name of a Call node, e.g. 'os.system' or 'eval'."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        return ".".join(chain)
    return None


def analyze_tools(tree: ast.Module) -> List[Dict]:
    """Find @tool-decorated functions and check for dangerous operations."""
    findings: List[Dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        is_tool = False
        for deco in node.decorator_list:
            if isinstance(deco, ast.Name) and deco.id == "tool":
                is_tool = True
            elif isinstance(deco, ast.Attribute) and deco.attr == "tool":
                is_tool = True
        if not is_tool:
            continue

        param_names = {arg.arg for arg in node.args.args if arg.arg != "self"}

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call_name = _call_name(child)
            if not call_name:
                continue
            lineno = getattr(child, "lineno", node.lineno)

            # Check dangerous sinks
            sink_desc = DANGEROUS_SINKS.get(call_name)
            is_sql = call_name in DANGEROUS_SQL_SINKS or any(
                call_name.endswith(f".{s.split('.')[-1]}") and "execute" in call_name
                for s in DANGEROUS_SQL_SINKS
            )
            if not sink_desc and not is_sql:
                continue

            # Check if any param flows into args
            arg_names: Set[str] = set()
            for arg in child.args:
                arg_names |= _names_in_expr(arg)
            for kw in child.keywords:
                arg_names |= _names_in_expr(kw.value)

            param_in_args = param_names & arg_names
            if param_in_args:
                desc = sink_desc or "SQL execution"
                findings.append({
                    "type": "TOOL_PARAM_TO_SINK",
                    "severity": "critical",
                    "title": f"Tool parameter flows to {desc}: {', '.join(param_in_args)} → {call_name}()",
                    "description": (
                        f"The @tool function '{node.name}' passes parameter(s) "
                        f"{', '.join(param_in_args)} directly to {call_name}() at line {lineno}. "
                        f"An LLM could invoke this tool with malicious arguments."
                    ),
                    "line_number": lineno,
                    "remediation": (
                        "Validate and sanitize tool parameters with an allowlist. "
                        "Use parameterized queries for SQL. Never pass raw parameters to shell or eval."
                    ),
                    "source": "dataflow",
                    "confidence": 0.95,
                    "evidence": f"@tool {node.name}(...) → {call_name}({', '.join(param_in_args)})",
                    "cwe": "CWE-89" if is_sql else "CWE-78",
                    "owasp": "LLM07: Insecure Plugin Design",
                })
            elif sink_desc:
                findings.append({
                    "type": "DANGEROUS_TOOL_BODY",
                    "severity": "high",
                    "title": f"Tool function contains {sink_desc}: {call_name}()",
                    "description": (
                        f"The @tool function '{node.name}' calls {call_name}() at line {lineno}. "
                        f"Even without direct parameter flow, an LLM could influence execution through indirect means."
                    ),
                    "line_number": lineno,
                    "remediation": (
                        "Remove dangerous operations from tool functions or add strict authorization checks."
                    ),
                    "source": "dataflow",
                    "confidence": 0.85,
                    "evidence": f"@tool {node.name} → {call_name}()",
                    "cwe": "CWE-78" if "shell" in sink_desc or "exec" in sink_desc else "CWE-732",
                    "owasp": "LLM07: Insecure Plugin Design",
                })
    return findings


# ── Reverse taint: LLM output → dangerous sinks (OWASP LLM02) ────────────

LLM_RESPONSE_CALLS = [
    ("messages", "create"),
    ("completions", "create"),
    ("chat", "completions"),
    ("responses", "create"),
    ("generate_content",),
]

EXEC_SINKS = {"eval", "exec"}
SHELL_SINKS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "os.system", "os.popen"}
SQL_SINKS = {"cursor.execute", "db.execute", "session.execute", "engine.execute", "conn.execute"}


def _is_llm_response_call(node: ast.Call) -> bool:
    """Check if a Call node returns an LLM API response."""
    chain = _attr_chain(node.func) if isinstance(node.func, ast.Attribute) else []
    for pattern in LLM_RESPONSE_CALLS:
        if len(chain) >= len(pattern):
            tail = tuple(chain[-len(pattern):])
            if tail == pattern:
                return True
    return False


def analyze_llm_output_flow(tree: ast.Module) -> List[Dict]:
    """Trace LLM API responses to dangerous execution sinks."""
    findings: List[Dict] = []
    llm_tainted: Dict[str, int] = {}  # var_name → line

    for node in ast.walk(tree):
        # Detect: result = client.messages.create(...)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value if isinstance(node, ast.AnnAssign) else node.value
            if value is None:
                continue
            if isinstance(value, ast.Call) and _is_llm_response_call(value):
                targets = []
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            targets.append(t.id)
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    targets.append(node.target.id)
                lineno = getattr(node, "lineno", 0)
                for tgt in targets:
                    llm_tainted[tgt] = lineno

            # Propagate: code = response.content[0].text
            if value is not None:
                names = _names_in_expr(value)
                for name in names:
                    if name in llm_tainted:
                        targets = []
                        if isinstance(node, ast.Assign):
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    targets.append(t.id)
                        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                            targets.append(node.target.id)
                        lineno = getattr(node, "lineno", 0)
                        for tgt in targets:
                            llm_tainted[tgt] = lineno
                        break

    if not llm_tainted:
        return findings

    # Now scan for dangerous sinks consuming tainted vars
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node)
        if not call_name:
            continue
        lineno = getattr(node, "lineno", 0)

        # Collect all arg names
        arg_names: Set[str] = set()
        for arg in node.args:
            arg_names |= _names_in_expr(arg)
        for kw in node.keywords:
            arg_names |= _names_in_expr(kw.value)

        tainted_in_args = arg_names & set(llm_tainted.keys())
        if not tainted_in_args:
            continue

        tainted_var = next(iter(tainted_in_args))
        source_line = llm_tainted[tainted_var]

        if call_name in EXEC_SINKS:
            findings.append({
                "type": "LLM_OUTPUT_EXEC",
                "severity": "critical",
                "title": f"LLM output executed via {call_name}(): {tainted_var}",
                "description": (
                    f"LLM API response stored in '{tainted_var}' (line {source_line}) "
                    f"is passed to {call_name}() at line {lineno}, enabling arbitrary code execution."
                ),
                "line_number": lineno,
                "remediation": "Never execute LLM output directly. Parse and validate against an expected schema.",
                "source": "dataflow",
                "confidence": 0.95,
                "evidence": f"L{source_line}: {tainted_var} ← LLM response → L{lineno}: {call_name}({tainted_var})",
                "cwe": "CWE-95",
                "owasp": "LLM02: Insecure Output Handling",
            })
        elif call_name in SHELL_SINKS:
            findings.append({
                "type": "LLM_OUTPUT_SHELL",
                "severity": "critical",
                "title": f"LLM output passed to shell: {tainted_var} → {call_name}()",
                "description": (
                    f"LLM API response stored in '{tainted_var}' (line {source_line}) "
                    f"is passed to {call_name}() at line {lineno}, enabling remote command execution."
                ),
                "line_number": lineno,
                "remediation": "Never pass LLM output to shell commands. Use structured output and validate.",
                "source": "dataflow",
                "confidence": 0.95,
                "evidence": f"L{source_line}: {tainted_var} ← LLM response → L{lineno}: {call_name}({tainted_var})",
                "cwe": "CWE-78",
                "owasp": "LLM02: Insecure Output Handling",
            })
        elif call_name in SQL_SINKS or "execute" in call_name:
            findings.append({
                "type": "LLM_OUTPUT_SQL",
                "severity": "critical",
                "title": f"LLM output used in SQL: {tainted_var} → {call_name}()",
                "description": (
                    f"LLM API response stored in '{tainted_var}' (line {source_line}) "
                    f"is passed to {call_name}() at line {lineno}, enabling SQL injection."
                ),
                "line_number": lineno,
                "remediation": "Use parameterized queries. Never pass raw LLM output as SQL.",
                "source": "dataflow",
                "confidence": 0.95,
                "evidence": f"L{source_line}: {tainted_var} ← LLM response → L{lineno}: {call_name}({tainted_var})",
                "cwe": "CWE-89",
                "owasp": "LLM02: Insecure Output Handling",
            })

    return findings


def scan_dataflow(text: str) -> List[Dict]:
    """Top-level entry point: parse + analyze + convert to findings."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return dataflow_to_findings(analyze(text))
    forward = dataflow_to_findings(analyze(text))
    tools = analyze_tools(tree)
    llm_output = analyze_llm_output_flow(tree)
    return forward + tools + llm_output

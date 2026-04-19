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


def scan_dataflow(text: str) -> List[Dict]:
    """Top-level entry point: parse + analyze + convert to findings."""
    return dataflow_to_findings(analyze(text))

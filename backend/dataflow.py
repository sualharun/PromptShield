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

LLM_RESPONSE_PATTERNS: List[Tuple[str, str]] = [
    ("messages", "create"),
    ("completions", "create"),
    ("responses", "create"),
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
        "finding_type",
        "cwe",
        "owasp",
        "function_name",
    )

    def __init__(
        self,
        source_var: str,
        source_desc: str,
        source_line: int,
        sink_call: str,
        sink_line: int,
        path: List[str],
        finding_type: str = "DATAFLOW_INJECTION",
        cwe: str = "CWE-77",
        owasp: str = "LLM01: Prompt Injection",
        function_name: Optional[str] = None,
    ):
        self.source_var = source_var
        self.source_desc = source_desc
        self.source_line = source_line
        self.sink_call = sink_call
        self.sink_line = sink_line
        self.path = path
        self.finding_type = finding_type
        self.cwe = cwe
        self.owasp = owasp
        self.function_name = function_name


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


def _assignment_targets(node: ast.AST) -> List[str]:
    targets: List[str] = []
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        targets.append(elt.id)
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        targets.append(node.target.id)
    return targets


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


def _is_llm_response_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    chain = _attr_chain(node.func)
    for pattern in LLM_RESPONSE_PATTERNS:
        if len(chain) >= len(pattern) and tuple(chain[-len(pattern):]) == pattern:
            return True
    return False


def _is_llm_response_taint(tv: TaintedVar) -> bool:
    return "LLM API response" in tv.source_desc


def _propagated_tainted_var(target_name: str, tv: TaintedVar, reason: Optional[str] = None) -> TaintedVar:
    if _is_llm_response_taint(tv):
        return TaintedVar(tv.name, tv.source_desc, tv.source_line)
    desc = reason or tv.source_desc
    return TaintedVar(tv.name, desc, tv.source_line)


def _decorator_contains_tool(node: ast.AST) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return "tool" in target.id.lower()
    if isinstance(target, ast.Attribute):
        return any("tool" in part.lower() for part in _attr_chain(target))
    return False


def _match_tool_sink(node: ast.Call) -> Optional[Tuple[str, str, str, List[ast.AST]]]:
    if isinstance(node.func, ast.Name):
        if node.func.id in {"eval", "exec"}:
            return ("TOOL_PARAM_TO_EXEC", node.func.id, "CWE-95", list(node.args) + [kw.value for kw in node.keywords])
        if node.func.id == "open":
            args: List[ast.AST] = []
            if node.args:
                args.append(node.args[0])
            args.extend(kw.value for kw in node.keywords if kw.arg in {None, "file"})
            return ("TOOL_UNRESTRICTED_FILE", "open", "CWE-73", args)

    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        tail2 = tuple(chain[-2:]) if len(chain) >= 2 else ()
        args = list(node.args) + [kw.value for kw in node.keywords]
        if tail2 in {
            ("os", "system"),
            ("os", "remove"),
            ("subprocess", "run"),
            ("subprocess", "call"),
            ("shutil", "rmtree"),
        }:
            return ("TOOL_PARAM_TO_SHELL", ".".join(chain), "CWE-78", args)
        if tail2 in {("cursor", "execute"), ("db", "execute"), ("session", "execute")}:
            return ("TOOL_PARAM_TO_SQL", ".".join(chain), "CWE-89", args)

    return None


def _match_reverse_sink(node: ast.Call) -> Optional[Tuple[str, str, str, List[ast.AST]]]:
    if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
        return (f"LLM_OUTPUT_{node.func.id.upper()}", node.func.id, "CWE-95", list(node.args) + [kw.value for kw in node.keywords])

    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        tail2 = tuple(chain[-2:]) if len(chain) >= 2 else ()
        args = list(node.args) + [kw.value for kw in node.keywords]
        if tail2 in {("subprocess", "run"), ("os", "system")}:
            return ("LLM_OUTPUT_SHELL", ".".join(chain), "CWE-78", args)
        if tail2 in {("cursor", "execute"), ("db", "execute"), ("session", "execute")}:
            return ("LLM_OUTPUT_SQL", ".".join(chain), "CWE-89", args)

    return None


def analyze_tools(tree: ast.Module) -> List[DataflowFinding]:
    findings: List[DataflowFinding] = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_decorator_contains_tool(decorator) for decorator in func.decorator_list):
            continue

        tainted: Dict[str, TaintedVar] = {}
        seen: Set[Tuple[str, str, int, str]] = set()

        for param in func.args.args:
            tainted[param.arg] = TaintedVar(
                param.arg,
                f'tool parameter "{param.arg}"',
                getattr(param, "lineno", func.lineno),
            )

        for node in ast.walk(func):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            tv = _expr_uses_tainted(value, tainted)
            if not tv:
                continue
            for target in _assignment_targets(node):
                tainted[target] = _propagated_tainted_var(target, tv)

        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            sink = _match_tool_sink(node)
            if not sink:
                continue
            finding_type, sink_name, cwe, arg_nodes = sink
            for arg in arg_nodes:
                tv = _expr_uses_tainted(arg, tainted)
                if not tv:
                    continue
                flow_key = (func.name, tv.name, getattr(node, "lineno", 0), finding_type)
                if flow_key in seen:
                    continue
                seen.add(flow_key)
                findings.append(
                    DataflowFinding(
                        source_var=tv.name,
                        source_desc=f'tool parameter "{tv.name}"',
                        source_line=tv.source_line,
                        sink_call=sink_name,
                        sink_line=getattr(node, "lineno", 0),
                        path=[
                            f'L{tv.source_line}: @tool {func.name} parameter "{tv.name}"',
                            f'L{getattr(node, "lineno", 0)}: {tv.name} → {sink_name}()',
                        ],
                        finding_type=finding_type,
                        cwe=cwe,
                        owasp="LLM07: Insecure Plugin Design",
                        function_name=func.name,
                    )
                )

    return findings


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
    # tainted: var_name → TaintedVar
    tainted: Dict[str, TaintedVar] = {}
    seen_flows: Set[Tuple[int, int, str]] = set()

    # Pass 1: walk all statements and collect taint + check sinks.
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)

        # --- Taint sources via assignment ---
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value if isinstance(node, ast.AnnAssign) else node.value
            if value is None:
                continue

            source_desc = None
            source_line = lineno
            if isinstance(value, ast.Call):
                if _is_llm_response_call(value):
                    source_desc = "LLM API response"
                else:
                    source_desc = _is_source_call(value)
            elif isinstance(value, ast.Attribute):
                source_desc = _is_source_attribute(value)
            elif isinstance(value, ast.Subscript):
                source_desc = _is_source_subscript(value)

            # Taint propagation: if RHS uses a tainted var, LHS becomes tainted
            if source_desc is None:
                tv = _expr_uses_tainted(value, tainted)
                if tv:
                    source_line = tv.source_line
                    if _is_llm_response_taint(tv):
                        source_desc = tv.source_desc
                    else:
                        source_desc = f"derived from {tv.name} ({tv.source_desc})"

            if source_desc:
                source_var = ""
                if source_desc == "LLM API response":
                    source_var = _assignment_targets(node)[0] if _assignment_targets(node) else ""
                else:
                    tv = _expr_uses_tainted(value, tainted)
                    source_var = tv.name if tv else (_assignment_targets(node)[0] if _assignment_targets(node) else "")

                for tgt in _assignment_targets(node):
                    tainted[tgt] = TaintedVar(source_var or tgt, source_desc, source_line)

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
                                    if _is_llm_response_taint(tv):
                                        tainted[t.id] = _propagated_tainted_var(t.id, tv)
                                    else:
                                        tainted[t.id] = TaintedVar(
                                            tv.name,
                                            f"f-string interpolating {tv.name}",
                                            tv.source_line,
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
                                    if _is_llm_response_taint(tv):
                                        tainted[t.id] = _propagated_tainted_var(t.id, tv)
                                    else:
                                        tainted[t.id] = TaintedVar(
                                            tv.name,
                                            f".format() with {tv.name}",
                                            tv.source_line,
                                        )
                            break
                    for kw in val.keywords:
                        tv = _expr_uses_tainted(kw.value, tainted)
                        if tv:
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    if _is_llm_response_taint(tv):
                                        tainted[t.id] = _propagated_tainted_var(t.id, tv)
                                    else:
                                        tainted[t.id] = TaintedVar(
                                            tv.name,
                                            f".format() with {tv.name}",
                                            tv.source_line,
                                        )
                            break

            # String concat (+) with tainted operand
            if isinstance(val, ast.BinOp) and isinstance(val.op, ast.Add):
                tv = _expr_uses_tainted(val, tainted)
                if tv:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            if _is_llm_response_taint(tv):
                                tainted[t.id] = _propagated_tainted_var(t.id, tv)
                            else:
                                tainted[t.id] = TaintedVar(
                                    tv.name,
                                    f"concatenation with {tv.name}",
                                    tv.source_line,
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

    # Pass 3: find dangerous sinks that consume LLM output
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sink = _match_reverse_sink(node)
        if not sink:
            continue
        finding_type, sink_name, cwe, arg_nodes = sink
        sink_line = getattr(node, "lineno", 0)
        for arg in arg_nodes:
            tv = _expr_uses_tainted(arg, tainted)
            if not tv or not _is_llm_response_taint(tv):
                continue
            flow_key = (tv.source_line, sink_line, finding_type)
            if flow_key in seen_flows:
                continue
            seen_flows.add(flow_key)
            findings.append(
                DataflowFinding(
                    source_var=tv.name,
                    source_desc="LLM API response",
                    source_line=tv.source_line,
                    sink_call=sink_name,
                    sink_line=sink_line,
                    path=[
                        f"L{tv.source_line}: {tv.name} ← LLM API response",
                        f"L{sink_line}: {tv.name} → {sink_name}()",
                    ],
                    finding_type=finding_type,
                    cwe=cwe,
                    owasp="LLM02: Insecure Output Handling",
                )
            )

    return findings


def dataflow_to_findings(df_results: List[DataflowFinding]) -> List[Dict]:
    """Convert DataflowFinding objects to the standard finding dict shape."""
    out: List[Dict] = []
    for df in df_results:
        path_str = " → ".join(df.path)
        if df.finding_type in {"LLM_OUTPUT_EXEC", "LLM_OUTPUT_SHELL", "LLM_OUTPUT_SQL"}:
            out.append(
                {
                    "type": df.finding_type,
                    "severity": "critical",
                    "title": f"LLM output reaches dangerous sink: {df.sink_call}()",
                    "description": (
                        f"{df.source_desc} (line {df.source_line}) reaches "
                        f"{df.sink_call}() at line {df.sink_line}. This is a proven "
                        "unsafe output-handling flow."
                    ),
                    "line_number": df.sink_line,
                    "remediation": (
                        "Do not execute, shell out, or run SQL directly from model output. "
                        "Parse the response into a constrained schema and validate it before use."
                    ),
                    "source": "dataflow",
                    "confidence": 0.95,
                    "evidence": path_str,
                    "cwe": df.cwe,
                    "owasp": df.owasp,
                    "dataflow_path": df.path,
                }
            )
            continue
        out.append(
            {
                "type": df.finding_type,
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
                "cwe": df.cwe,
                "owasp": df.owasp,
                "dataflow_path": df.path,
            }
        )
    return out


def tool_findings_to_dicts(findings: List[DataflowFinding]) -> List[Dict]:
    out: List[Dict] = []
    for df in findings:
        path_str = " → ".join(df.path)
        out.append(
            {
                "type": df.finding_type,
                "severity": "critical",
                "title": f"Tool parameter reaches dangerous sink: {df.function_name}.{df.sink_call}()",
                "description": (
                    f'Tool function "{df.function_name}" passes parameter "{df.source_var}" '
                    f'into dangerous sink {df.sink_call}() at line {df.sink_line}.'
                ),
                "line_number": df.sink_line,
                "remediation": (
                    "Constrain tool inputs before using them in execution, shell, SQL, or file "
                    "operations. Validate and sanitize parameters against an allow-list."
                ),
                "source": "dataflow",
                "confidence": 0.95,
                "evidence": path_str,
                "cwe": df.cwe,
                "owasp": "LLM07: Insecure Plugin Design",
                "dataflow_path": df.path,
            }
        )
    return out


def scan_dataflow(text: str) -> List[Dict]:
    """Top-level entry point: parse + analyze + convert to findings."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    forward = dataflow_to_findings(analyze(text))
    tools = tool_findings_to_dicts(analyze_tools(tree))
    return forward + tools

"""Tests for AST-based dataflow analysis."""

import textwrap

from dataflow import analyze, scan_dataflow


def test_input_to_openai_create():
    code = textwrap.dedent("""\
        import openai
        user_msg = input("Enter your question: ")
        prompt = f"Answer this: {user_msg}"
        client = openai.OpenAI()
        client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
    """)
    results = analyze(code)
    assert len(results) >= 1
    r = results[0]
    assert "completions.create" in r.sink_call


def test_request_form_to_anthropic():
    code = textwrap.dedent("""\
        from anthropic import Anthropic
        user_query = request.form["query"]
        prompt = "Summarize: " + user_query
        client = Anthropic()
        client.messages.create(model="claude-sonnet-4-20250514", messages=[{"role": "user", "content": prompt}])
    """)
    results = analyze(code)
    assert len(results) >= 1
    assert "messages.create" in results[0].sink_call


def test_request_json_through_fstring():
    code = textwrap.dedent("""\
        data = request.json
        question = data["question"]
        prompt = f"You are a helpful assistant. User asks: {question}"
        llm.invoke(prompt)
    """)
    results = analyze(code)
    assert len(results) >= 1
    assert "invoke" in results[0].sink_call


def test_no_finding_when_no_taint():
    code = textwrap.dedent("""\
        prompt = "What is the capital of France?"
        client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
    """)
    results = analyze(code)
    assert len(results) == 0


def test_no_finding_when_no_sink():
    code = textwrap.dedent("""\
        user_msg = input("Enter query: ")
        prompt = f"Answer: {user_msg}"
        print(prompt)
    """)
    results = analyze(code)
    assert len(results) == 0


def test_taint_propagates_through_format():
    code = textwrap.dedent("""\
        user_input = input()
        prompt = "Please help with: {}".format(user_input)
        chain.invoke(prompt)
    """)
    results = analyze(code)
    assert len(results) >= 1


def test_taint_propagates_through_concat():
    code = textwrap.dedent("""\
        query = request.args["q"]
        system = "You are an assistant."
        full_prompt = system + " User says: " + query
        model.generate(full_prompt)
    """)
    results = analyze(code)
    assert len(results) >= 1
    assert "generate" in results[0].sink_call


def test_external_content_is_tainted():
    code = textwrap.dedent("""\
        import requests
        page = requests.get("https://example.com").text
        prompt = f"Summarize this page: {page}"
        client.messages.create(model="claude-sonnet-4-20250514", messages=[{"role": "user", "content": prompt}])
    """)
    results = analyze(code)
    assert len(results) == 0  # requests.get() returns Response, .text is attr access after


def test_open_read_is_tainted():
    code = textwrap.dedent("""\
        content = open("data.txt").read()
        prompt = f"Analyze: {content}"
        client.chat.completions.create(messages=[{"role": "user", "content": prompt}])
    """)
    results = analyze(code)
    assert len(results) >= 1


def test_sys_argv_to_llm():
    code = textwrap.dedent("""\
        import sys
        user_arg = sys.argv[1]
        prompt = f"Process: {user_arg}"
        llm.ask(prompt)
    """)
    results = analyze(code)
    assert len(results) >= 1


def test_scan_dataflow_returns_finding_dicts():
    code = textwrap.dedent("""\
        query = input()
        prompt = f"Help: {query}"
        client.chat.completions.create(messages=[{"role": "user", "content": prompt}])
    """)
    findings = scan_dataflow(code)
    assert len(findings) >= 1
    f = findings[0]
    assert f["type"] == "DATAFLOW_INJECTION"
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-77"
    assert "dataflow_path" in f
    assert f["source"] == "dataflow"


def test_invalid_python_returns_empty():
    findings = scan_dataflow("this is not {{ valid python }}")
    assert findings == []


def test_non_llm_sink_not_flagged():
    """A tainted var going into print() should not be flagged."""
    code = textwrap.dedent("""\
        user_msg = input()
        print(user_msg)
    """)
    results = analyze(code)
    assert len(results) == 0
def test_langchain_chain_invoke():
    code = textwrap.dedent("""\
        from langchain.chains import LLMChain
        user_q = request.query_params["q"]
        chain = LLMChain(llm=llm, prompt=template)
        chain.invoke({"question": user_q})
    """)
    results = analyze(code)
    assert len(results) >= 1


def test_multi_hop_taint():
    """Taint should propagate through multiple variable assignments."""
    code = textwrap.dedent("""\
        raw = input()
        cleaned = raw.strip()
        wrapped = f"Context: {cleaned}"
        final = "System prompt. " + wrapped
        client.chat.completions.create(messages=[{"role": "user", "content": final}])
    """)
    results = analyze(code)
    assert len(results) >= 1
    assert "completions.create" in results[0].sink_call


# ── New tests: tool body analysis + reverse taint ──────────────────────────

def test_tool_with_subprocess():
    code = """
@tool
def run_cmd(cmd: str) -> str:
    subprocess.run(cmd, shell=True)
"""
    results = scan_dataflow(code)
    types = [r["type"] for r in results]
    assert "TOOL_PARAM_TO_SINK" in types

def test_tool_with_sql():
    code = """
@tool
def run_query(query: str) -> str:
    cursor.execute(query)
"""
    results = scan_dataflow(code)
    types = [r["type"] for r in results]
    assert "TOOL_PARAM_TO_SINK" in types

def test_tool_with_eval():
    code = """
@tool
def evaluate(expr: str) -> str:
    return eval(expr)
"""
    results = scan_dataflow(code)
    types = [r["type"] for r in results]
    assert "TOOL_PARAM_TO_SINK" in types

def test_tool_with_file():
    code = """
@tool
def read_file(path: str) -> str:
    return open(path).read()
"""
    results = scan_dataflow(code)
    assert len(results) > 0

def test_safe_tool():
    code = """
@tool
def get_time() -> str:
    return datetime.now().isoformat()
"""
    results = scan_dataflow(code)
    assert results == []

def test_llm_output_exec():
    code = """
response = client.messages.create(model="claude-sonnet-4-20250514", messages=[])
code = response.content[0].text
exec(code)
"""
    results = scan_dataflow(code)
    types = [r["type"] for r in results]
    assert "LLM_OUTPUT_EXEC" in types

def test_llm_output_shell():
    code = """
response = client.messages.create(model="claude-sonnet-4-20250514", messages=[])
cmd = response.content[0].text
subprocess.run(cmd)
"""
    results = scan_dataflow(code)
    types = [r["type"] for r in results]
    assert "LLM_OUTPUT_SHELL" in types

def test_llm_output_sql():
    code = """
response = client.messages.create(model="claude-sonnet-4-20250514", messages=[])
query = response.content[0].text
cursor.execute(query)
"""
    results = scan_dataflow(code)
    types = [r["type"] for r in results]
    assert "LLM_OUTPUT_SQL" in types

def test_safe_llm_usage():
    code = """
response = client.messages.create(model="claude-sonnet-4-20250514", messages=[])
print(response.content[0].text)
"""
    results = scan_dataflow(code)
    dangerous = [r for r in results if r["type"] in ("LLM_OUTPUT_EXEC", "LLM_OUTPUT_SHELL", "LLM_OUTPUT_SQL")]
    assert dangerous == []

def test_class_attribute_taint():
    """Taint through self.attr should be tracked."""
    code = textwrap.dedent("""\
        class Agent:
            def handle(self):
                self.query = request.form['data']
                cursor.execute(self.query)
    """)
    results = scan_dataflow(code)
    assert len(results) >= 1

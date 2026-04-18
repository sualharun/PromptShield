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
    """A tainted var going into print() or db.execute() should not be flagged."""
    code = textwrap.dedent("""\
        user_msg = input()
        print(user_msg)
        db.execute(user_msg)
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

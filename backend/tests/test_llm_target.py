from llm_target import detect_llm_targets, primary_target


def test_detects_openai():
    text = "import openai\nclient = OpenAI()\nclient.chat.completions.create(model='gpt-4o')"
    assert detect_llm_targets(text) == ["openai"]
    assert primary_target(text) == "openai"


def test_detects_anthropic():
    text = "from anthropic import Anthropic\nclient.messages.create(model='claude-sonnet-4-20250514')"
    assert detect_llm_targets(text) == ["anthropic"]


def test_detects_multiple_providers():
    text = """
    import openai
    from anthropic import Anthropic
    from google.generativeai import GenerativeModel
    """
    assert detect_llm_targets(text) == ["anthropic", "gemini", "openai"]


def test_detects_huggingface_and_llama():
    text = "from transformers import AutoModelForCausalLM\nimport ollama"
    assert "huggingface" in detect_llm_targets(text)
    assert "llama" in detect_llm_targets(text)


def test_returns_empty_when_no_provider():
    assert detect_llm_targets("def foo(): pass") == []
    assert primary_target("") == "none"

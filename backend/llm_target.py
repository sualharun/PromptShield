"""Detect which LLM provider a scanned text targets.

Heuristic: look for imports and client constructors. We return *all* matches,
not a single one, because one file can legitimately call multiple providers
(router pattern). Callers typically just care about presence.
"""

import re
from typing import Dict, List, Set


# pattern => target key
_TARGET_PATTERNS: Dict[str, List[str]] = {
    "openai": [
        r"\bimport openai\b",
        r"\bfrom openai\b",
        r"\bOpenAI\s*\(",
        r"openai\.chat\.completions\b",
        r"openai\.ChatCompletion\b",
        r"openai\.responses\.create\b",
        r"api\.openai\.com",
        r"\bgpt-4\b",
        r"\bgpt-3\.5\b",
    ],
    "anthropic": [
        r"\bimport anthropic\b",
        r"\bfrom anthropic\b",
        r"\bAnthropic\s*\(",
        r"client\.messages\.create\b",
        r"api\.anthropic\.com",
        r"\bclaude-(?:sonnet|opus|haiku|[0-9])",
    ],
    "gemini": [
        r"\bimport google\.generativeai\b",
        r"\bfrom google\.generativeai\b",
        r"\bGenerativeModel\s*\(",
        r"generativelanguage\.googleapis\.com",
        r"\bgemini-(?:pro|flash|[0-9])",
    ],
    "llama": [
        r"\bollama\b",
        r"\bllama_index\b",
        r"\bllamaapi\b",
        r"\bllama-?\d",
    ],
    "huggingface": [
        r"\bfrom transformers\b",
        r"\bimport transformers\b",
        r"huggingface\.co/",
        r"\bAutoModelForCausalLM\b",
    ],
}

_COMPILED = {
    target: [re.compile(p, re.IGNORECASE) for p in patterns]
    for target, patterns in _TARGET_PATTERNS.items()
}


def detect_llm_targets(text: str) -> List[str]:
    """Return a sorted list of detected targets ('openai', 'anthropic', ...).
    Empty list when no provider is identifiable — caller should treat as 'none'.
    """
    if not text:
        return []
    hits: Set[str] = set()
    for target, patterns in _COMPILED.items():
        for rx in patterns:
            if rx.search(text):
                hits.add(target)
                break
    return sorted(hits)


def primary_target(text: str) -> str:
    """Convenience for single-label filtering. Returns 'none' when ambiguous/absent."""
    hits = detect_llm_targets(text)
    return hits[0] if hits else "none"

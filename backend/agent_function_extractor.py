"""Identify functions/tools exposed to LLMs.

Detects `@tool` decorators, `Tool(...)` constructors, LangChain `Tool.from_function`,
`openai.ChatCompletion.create(functions=...)`, and JS/TS tool-object registrations.
"""
import ast
import re
from typing import List, Optional
from dataclasses import dataclass


_TOOL_DECORATOR_HINTS = ("tool", "function", "anthropic", "langchain")
_TOOL_NAME_HINTS = ("tool", "action", "handle_", "execute_", "run_", "call_")


@dataclass
class ExtractedFunction:
    name: str
    language: str
    line: int
    end_line: Optional[int]
    decorator: Optional[str]
    is_registered: bool
    description: Optional[str]
    parameters: List[dict]
    return_type: Optional[str]
    docstring: Optional[str]
    registration_context: Optional[str]


class AgentFunctionExtractor:
    def extract_from_python(self, code: str) -> List[ExtractedFunction]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        functions: List[ExtractedFunction] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                decorators = [self._get_decorator_name(d) for d in node.decorator_list]
                tool_decorator = next(
                    (d for d in decorators if any(x in d.lower() for x in _TOOL_DECORATOR_HINTS)),
                    None,
                )
                if tool_decorator or self._looks_like_tool_function(node.name):
                    functions.append(ExtractedFunction(
                        name=node.name,
                        language="python",
                        line=node.lineno,
                        end_line=node.end_lineno,
                        decorator=tool_decorator,
                        is_registered=False,
                        description=None,
                        parameters=self._extract_function_params(node),
                        return_type=self._extract_return_annotation(node),
                        docstring=ast.get_docstring(node),
                        registration_context=None,
                    ))

        def _mark_registered(func_name: str, context: str) -> None:
            for f in functions:
                if f.name == func_name:
                    f.is_registered = True
                    f.registration_context = context
                    return

        for match in re.finditer(r'Tool\s*\(\s*name\s*=\s*["\'](\w+)["\']', code):
            line_num = code[:match.start()].count("\n") + 1
            _mark_registered(match.group(1), f"Tool(...) at line {line_num}")

        for match in re.finditer(r"Tool\.from_function\s*\(\s*(\w+)", code):
            _mark_registered(match.group(1), "langchain Tool.from_function()")

        for match in re.finditer(
            r"openai\.ChatCompletion\.create\s*\([^)]*functions\s*=\s*(\[.*?\])",
            code,
            re.DOTALL,
        ):
            for name_match in re.finditer(r'"name"\s*:\s*"(\w+)"', match.group(1)):
                _mark_registered(
                    name_match.group(1),
                    "openai.ChatCompletion.create(functions=...)",
                )

        return functions

    def extract_from_javascript(self, code: str) -> List[ExtractedFunction]:
        functions: List[ExtractedFunction] = []

        tool_pattern = r'const\s+(\w+)\s*=\s*(?:new\s+)?[Tt]ool\s*\(\s*\{[^}]*name\s*:\s*["\']?(\w+)["\']?'
        for match in re.finditer(tool_pattern, code):
            var_name = match.group(1)
            func_name = match.group(2)
            line_num = code[:match.start()].count("\n") + 1
            doc = self._extract_js_comment_before(code, match.start())

            functions.append(ExtractedFunction(
                name=func_name or var_name,
                language="javascript",
                line=line_num,
                end_line=None,
                decorator=None,
                is_registered=True,
                description=doc,
                parameters=[],
                return_type=None,
                docstring=doc,
                registration_context="tool({ ... })",
            ))

        anthropic_pattern = r"const\s+(\w+)\s*=\s*\{\s*(?:name|description|func)\s*:"
        for match in re.finditer(anthropic_pattern, code):
            line_num = code[:match.start()].count("\n") + 1
            block_start = match.start()
            name_match = re.search(
                r'name\s*:\s*["\'](\w+)["\']',
                code[block_start:block_start + 200],
            )
            if name_match:
                functions.append(ExtractedFunction(
                    name=name_match.group(1),
                    language="javascript",
                    line=line_num,
                    end_line=None,
                    decorator=None,
                    is_registered=True,
                    parameters=[],
                    return_type=None,
                    docstring=None,
                    registration_context="anthropic tool object",
                    description=None,
                ))

        return functions

    @staticmethod
    def _get_decorator_name(node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id
            if isinstance(node.func, ast.Attribute):
                return node.func.attr
        return ""

    @staticmethod
    def _looks_like_tool_function(name: str) -> bool:
        return any(kw in name.lower() for kw in _TOOL_NAME_HINTS)

    @staticmethod
    def _extract_function_params(node: ast.FunctionDef) -> List[dict]:
        params: List[dict] = []
        for arg in node.args.args:
            param: dict = {"name": arg.arg}
            if arg.annotation:
                param["type"] = ast.unparse(arg.annotation)
            params.append(param)
        return params

    @staticmethod
    def _extract_return_annotation(node: ast.FunctionDef) -> Optional[str]:
        if node.returns:
            return ast.unparse(node.returns)
        return None

    @staticmethod
    def _extract_js_comment_before(code: str, pos: int) -> Optional[str]:
        preceding = code[:pos].rstrip()
        if preceding.endswith("*/"):
            start = preceding.rfind("/**")
            if start != -1:
                return preceding[start:].strip()
        return None


def extract_agent_functions(code: str, language: str) -> List[ExtractedFunction]:
    extractor = AgentFunctionExtractor()
    lang = language.lower()
    if lang in ("python", "py"):
        return extractor.extract_from_python(code)
    if lang in ("javascript", "typescript", "js", "ts"):
        return extractor.extract_from_javascript(code)
    return []

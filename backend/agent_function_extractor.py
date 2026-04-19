"""
Agent Function Extractor – Identify functions/tools exposed to LLMs.

Detects:
- @tool decorators (LangChain, Anthropic)
- Tool(...) constructor calls
- openai.ChatCompletion functions= parameter
- Function registrations in agent frameworks
"""
import ast
import re
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class ExtractedFunction:
    """Represents a function potentially exposed to an LLM."""
    name: str
    language: str
    line: int
    end_line: Optional[int]
    decorator: Optional[str]  # e.g., "@tool", "@anthropic.tool"
    is_registered: bool
    description: Optional[str]
    parameters: List[dict]  # [{"name": "path", "type": "str"}]
    return_type: Optional[str]
    docstring: Optional[str]
    registration_context: Optional[str]  # where it's registered as a tool


class AgentFunctionExtractor:
    """Extract function/tool definitions from code that may be exposed to LLMs."""

    def __init__(self):
        self.functions = []

    def extract_from_python(self, code: str) -> List[ExtractedFunction]:
        """Extract tool definitions from Python code."""
        functions = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        # Find functions with @tool or similar decorators
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                decorators = [self._get_decorator_name(d) for d in node.decorator_list]
                
                # Check if function has tool-like decorator
                tool_decorator = None
                for dec in decorators:
                    if any(x in dec.lower() for x in ['tool', 'function', 'anthropic', 'langchain']):
                        tool_decorator = dec
                        break

                if tool_decorator or self._looks_like_tool_function(node.name):
                    func = ExtractedFunction(
                        name=node.name,
                        language="python",
                        line=node.lineno,
                        end_line=node.end_lineno,
                        decorator=tool_decorator,
                        is_registered=False,  # Will be set when we find registration
                        description=None,
                        parameters=self._extract_function_params(node),
                        return_type=self._extract_return_annotation(node),
                        docstring=ast.get_docstring(node),
                        registration_context=None,
                    )
                    functions.append(func)

        # Find Tool(...) registrations and matches
        tool_pattern = r'Tool\s*\(\s*name\s*=\s*["\'](\w+)["\']'
        for match in re.finditer(tool_pattern, code):
            func_name = match.group(1)
            line_num = code[:match.start()].count('\n') + 1
            
            # Mark matching function as registered
            for func in functions:
                if func.name == func_name:
                    func.is_registered = True
                    func.registration_context = f"Tool(...) at line {line_num}"
                    break

        # Find langchain Tool registration patterns
        langchain_pattern = r'Tool\.from_function\s*\(\s*(\w+)'
        for match in re.finditer(langchain_pattern, code):
            func_name = match.group(1)
            for func in functions:
                if func.name == func_name:
                    func.is_registered = True
                    func.registration_context = "langchain Tool.from_function()"
                    break

        # Find openai functions parameter
        openai_pattern = r'openai\.ChatCompletion\.create\s*\([^)]*functions\s*=\s*(\[.*?\])'
        for match in re.finditer(openai_pattern, code, re.DOTALL):
            func_data = match.group(1)
            for name_match in re.finditer(r'"name"\s*:\s*"(\w+)"', func_data):
                func_name = name_match.group(1)
                for func in functions:
                    if func.name == func_name:
                        func.is_registered = True
                        func.registration_context = "openai.ChatCompletion.create(functions=...)"
                        break

        return functions

    def extract_from_javascript(self, code: str) -> List[ExtractedFunction]:
        """Extract tool definitions from JavaScript/TypeScript code."""
        functions = []

        # Find tool definitions: const toolName = tool({ ... })
        tool_pattern = r'const\s+(\w+)\s*=\s*(?:new\s+)?[Tt]ool\s*\(\s*\{[^}]*name\s*:\s*["\']?(\w+)["\']?'
        for match in re.finditer(tool_pattern, code):
            var_name = match.group(1)
            func_name = match.group(2)
            line_num = code[:match.start()].count('\n') + 1
            
            # Extract docstring/description from surrounding context
            doc = self._extract_js_comment_before(code, match.start())
            
            functions.append(ExtractedFunction(
                name=func_name or var_name,
                language="javascript",
                line=line_num,
                end_line=None,
                decorator=None,
                is_registered=True,
                description=doc,
                parameters=self._extract_js_function_params(code, match.start()),
                return_type=None,
                docstring=doc,
                registration_context="tool({ ... })",
            ))

        # Find anthropic tool declarations
        anthropic_pattern = r'const\s+(\w+)\s*=\s*\{\s*(?:name|description|func)\s*:'
        for match in re.finditer(anthropic_pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            # Extract name from the block
            block_start = match.start()
            # Simple extraction - look for name field
            name_match = re.search(r'name\s*:\s*["\'](\w+)["\']', code[block_start:block_start+200])
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
        """Extract decorator name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id
            elif isinstance(node.func, ast.Attribute):
                return node.func.attr
        return ""

    @staticmethod
    def _looks_like_tool_function(name: str) -> bool:
        """Heuristic: does function name suggest it's a tool?"""
        tool_keywords = ['tool', 'action', 'handle_', 'execute_', 'run_', 'call_']
        return any(kw in name.lower() for kw in tool_keywords)

    @staticmethod
    def _extract_function_params(node: ast.FunctionDef) -> List[dict]:
        """Extract function parameters with type annotations."""
        params = []
        for arg in node.args.args:
            param = {"name": arg.arg}
            if arg.annotation:
                param["type"] = ast.unparse(arg.annotation)
            params.append(param)
        return params

    @staticmethod
    def _extract_return_annotation(node: ast.FunctionDef) -> Optional[str]:
        """Extract return type annotation."""
        if node.returns:
            return ast.unparse(node.returns)
        return None

    @staticmethod
    def _extract_js_comment_before(code: str, pos: int) -> Optional[str]:
        """Extract preceding comment (JSDoc style)."""
        # Look back for /** ... */ or // comments
        preceding = code[:pos].rstrip()
        if preceding.endswith('*/'):
            start = preceding.rfind('/**')
            if start != -1:
                return preceding[start:].strip()
        return None

    @staticmethod
    def _extract_js_function_params(code: str, match_pos: int) -> List[dict]:
        """Extract parameters from JS function context."""
        # Simple extraction - look for params field in tool definition
        context = code[match_pos:match_pos+500]
        params = []
        # This is simplified; full implementation would parse the tool schema
        return params


def extract_agent_functions(code: str, language: str) -> List[ExtractedFunction]:
    """Convenience function to extract agent functions."""
    extractor = AgentFunctionExtractor()
    
    if language.lower() in ["python", "py"]:
        return extractor.extract_from_python(code)
    elif language.lower() in ["javascript", "typescript", "js", "ts"]:
        return extractor.extract_from_javascript(code)
    
    return []

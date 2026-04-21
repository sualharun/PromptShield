"""Integrated agent-security scanner.

Combines (1) extraction of LLM-exposed functions, (2) dangerous-sink detection,
and (3) connection analysis that flags exposed functions calling dangerous sinks.
"""
import re
from typing import List, Optional
from dataclasses import dataclass

from agent_function_extractor import extract_agent_functions, ExtractedFunction
from agent_sink_analyzer import analyze_sinks, DangerousSink


@dataclass
class AgentSecurityFinding:
    type: str
    language: str
    severity: str
    title: str
    description: str
    line: int
    evidence: str
    function_name: Optional[str]
    sink_name: Optional[str]
    cwe: Optional[str]
    owasp_llm: List[str]
    remediation: str
    code_snippet: Optional[str]


class AgentSecurityScanner:
    def scan(self, code: str, language: str) -> List[AgentSecurityFinding]:
        findings: List[AgentSecurityFinding] = []
        extracted_functions = extract_agent_functions(code, language)
        findings.extend(self._findings_from_extracted_functions(extracted_functions, code))

        dangerous_sinks = analyze_sinks(code, language)
        findings.extend(self._findings_from_sinks(dangerous_sinks, code))

        findings.extend(self._findings_from_connections(extracted_functions, dangerous_sinks, code, language))
        return findings

    def _findings_from_extracted_functions(self, functions: List[ExtractedFunction], code: str) -> List[AgentSecurityFinding]:
        findings: List[AgentSecurityFinding] = []
        for func in functions:
            if func.is_registered:
                has_validation = self._check_validation(func, code, func.language)
                func_code = self._extract_function_code(code, func.line, func.end_line)
                severity = "high" if not has_validation else "medium"
                
                finding = AgentSecurityFinding(
                    type="AGENT_FUNCTION_EXPOSURE",
                    language=func.language,
                    severity=severity,
                    title=f"Function '{func.name}' is exposed to AI agents",
                    description=f"The function '{func.name}' is registered as a tool available to LLMs.\n"
                                f"Risk: LLMs could call this function with harmful inputs if not properly validated.\n"
                                f"Context: {func.registration_context}",
                    line=func.line,
                    evidence=f"def {func.name}(...) registered as tool at line {func.line}",
                    function_name=func.name,
                    sink_name=None,
                    cwe="CWE-94",
                    owasp_llm=["LLM02", "LLM07"],
                    remediation=f"1. Validate all parameters to '{func.name}' against strict types\n"
                                f"2. Use allowlists for sensitive inputs (file paths, SQL, etc.)\n"
                                f"3. Add rate limiting to prevent abuse\n"
                                f"4. {'' if has_validation else 'Add input validation'}",
                    code_snippet=func_code[:200] if func_code else None,
                )
                findings.append(finding)
        
        return findings

    def _findings_from_sinks(self, sinks: List[tuple[int, DangerousSink]], code: str) -> List[AgentSecurityFinding]:
        findings: List[AgentSecurityFinding] = []
        for line_no, sink in sinks:
            finding = AgentSecurityFinding(
                type="DANGEROUS_SINK",
                language=sink.language,
                severity=sink.severity,
                title=f"Dangerous operation: {sink.name}",
                description=sink.description,
                line=line_no,
                evidence=self._get_line_content(code, line_no),
                function_name=self._find_containing_function(code, line_no),
                sink_name=sink.name,
                cwe=sink.cwe,
                owasp_llm=sink.owasp_llm,
                remediation="\n".join(f"• {m}" for m in sink.mitigations),
                code_snippet=self._get_line_content(code, line_no),
            )
            findings.append(finding)
        return findings

    def _findings_from_connections(
        self,
        functions: List[ExtractedFunction],
        sinks: List[tuple[int, DangerousSink]],
        code: str,
        language: str,
    ) -> List[AgentSecurityFinding]:
        findings: List[AgentSecurityFinding] = []
        for func in functions:
            if not func.is_registered:
                continue
            func_code = self._extract_function_code(code, func.line, func.end_line)
            if not func_code:
                continue
            for sink_line, sink in sinks:
                if sink_line >= func.line and (func.end_line is None or sink_line <= func.end_line):
                    finding = AgentSecurityFinding(
                        type="UNVALIDATED_FUNCTION_PARAM_TO_SINK",
                        language=language,
                        severity="critical",
                        title=f"AI-exposed function '{func.name}' calls dangerous operation: {sink.name}",
                        description=f"Function '{func.name}' is exposed as a tool to LLMs.\n"
                                   f"However, it calls {sink.name} which is dangerous.\n"
                                   f"If the function accepts LLM-controlled parameters without validation,\n"
                                   f"an attacker can exploit it via prompt injection.",
                        line=func.line,
                        evidence=f"Function {func.name} (line {func.line}) → {sink.name} (line {sink_line})",
                        function_name=func.name,
                        sink_name=sink.name,
                        cwe=sink.cwe,
                        owasp_llm=["LLM02", "LLM07"],
                        remediation=f"1. Wrap '{func.name}' to validate all inputs before calling {sink.name}\n"
                                   f"2. {sink.mitigations[0] if sink.mitigations else ''}\n"
                                   f"3. Consider wrapping {sink.name} in a safer abstraction",
                        code_snippet=func_code[:300],
                    )
                    findings.append(finding)
        return findings

    _VALIDATION_PATTERNS = (
        re.compile(r"\b(assert|if|raise|ValidationError)\b", re.IGNORECASE),
        re.compile(r"(allowlist|whitelist|validate|check|guard)", re.IGNORECASE),
    )

    @classmethod
    def _check_validation(cls, func: ExtractedFunction, code: str, language: str) -> bool:
        func_code = cls._extract_function_code(code, func.line, func.end_line)
        if not func_code:
            return False
        return any(p.search(func_code) for p in cls._VALIDATION_PATTERNS)

    @staticmethod
    def _extract_function_code(code: str, start_line: int, end_line: Optional[int]) -> Optional[str]:
        lines = code.split("\n")
        if start_line < 1 or start_line > len(lines):
            return None
        end = end_line if end_line and end_line <= len(lines) else min(start_line + 20, len(lines))
        return "\n".join(lines[start_line - 1:end])

    @staticmethod
    def _get_line_content(code: str, line_no: int) -> str:
        lines = code.split("\n")
        if line_no < 1 or line_no > len(lines):
            return ""
        return lines[line_no - 1].strip()

    @staticmethod
    def _find_containing_function(code: str, line_no: int) -> Optional[str]:
        lines = code.split("\n")
        for i in range(line_no - 1, -1, -1):
            func_match = re.match(r"^\s*(?:def|function|async\s+function)\s+(\w+)", lines[i])
            if func_match:
                return func_match.group(1)
        return None


def scan_agent_security(code: str, language: str) -> List[AgentSecurityFinding]:
    return AgentSecurityScanner().scan(code, language)

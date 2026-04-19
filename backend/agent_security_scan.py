"""
Agent Security Scanner – Integrated analysis of AI function safety.

Combines:
1. Function extraction (what functions are exposed to AI)
2. Dangerous operation detection (what sinks exist)
3. Connection analysis (which functions call dangerous sinks)
"""
import re
from typing import List, Optional
from dataclasses import dataclass, asdict

from agent_function_extractor import extract_agent_functions, ExtractedFunction
from agent_sink_analyzer import analyze_sinks, DangerousSink, SinkCategory

@dataclass
class AgentSecurityFinding:
    """A security finding related to AI function safety."""
    type: str  # AGENT_FUNCTION_EXPOSURE, DANGEROUS_SINK, UNVALIDATED_FUNCTION_PARAM
    language: str
    severity: str  # critical, high, medium, low
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
    """Scan code for AI agent security issues."""

    def __init__(self):
        pass

    def scan(self, code: str, language: str) -> List[AgentSecurityFinding]:
        """Run full agent security analysis."""
        findings = []
        
        # Step 1: Extract functions exposed to LLMs
        extracted_functions = extract_agent_functions(code, language)
        findings.extend(self._findings_from_extracted_functions(extracted_functions, code))
        
        # Step 2: Find dangerous sinks
        dangerous_sinks = analyze_sinks(code, language)
        findings.extend(self._findings_from_sinks(dangerous_sinks, code))
        
        # Step 3: Connect functions to sinks (which functions call dangerous sinks?)
        findings.extend(self._findings_from_connections(extracted_functions, dangerous_sinks, code, language))
        
        return findings

    def _findings_from_extracted_functions(self, functions: List[ExtractedFunction], code: str) -> List[AgentSecurityFinding]:
        """Generate findings for exposed functions."""
        findings = []
        
        for func in functions:
            if func.is_registered:
                # This function is explicitly registered as a tool
                has_validation = self._check_validation(func, code, func.language)
                
                # Get the function code
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
        """Generate findings for dangerous sinks."""
        findings = []
        
        for line_no, sink in sinks:
            # Check if sink is in a function that's exposed to AI
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
        language: str
    ) -> List[AgentSecurityFinding]:
        """Generate findings for dangerous connections: exposed function calls dangerous sink."""
        findings = []
        
        for func in functions:
            if not func.is_registered:
                continue
            
            func_code = self._extract_function_code(code, func.line, func.end_line)
            if not func_code:
                continue
            
            # Check if this function's code calls any dangerous sinks
            for sink_line, sink in sinks:
                if sink_line >= func.line and (func.end_line is None or sink_line <= func.end_line):
                    # This sink is within the function
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

    @staticmethod
    def _check_validation(func: ExtractedFunction, code: str, language: str) -> bool:
        """Simple heuristic: does function validate its inputs?"""
        func_code = AgentSecurityScanner._extract_function_code(code, func.line, func.end_line)
        if not func_code:
            return False
        
        # Look for validation patterns
        validation_patterns = [
            r'\b(assert|if|raise|ValidationError)\b',
            r'(allowlist|whitelist|validate|check|guard)',
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, func_code, re.IGNORECASE):
                return True
        
        return False

    @staticmethod
    def _extract_function_code(code: str, start_line: int, end_line: Optional[int]) -> Optional[str]:
        """Extract function body from code."""
        lines = code.split('\n')
        if start_line < 1 or start_line > len(lines):
            return None
        
        end = end_line if end_line and end_line <= len(lines) else min(start_line + 20, len(lines))
        return '\n'.join(lines[start_line - 1:end])

    @staticmethod
    def _get_line_content(code: str, line_no: int) -> str:
        """Get content of a specific line."""
        lines = code.split('\n')
        if line_no < 1 or line_no > len(lines):
            return ""
        return lines[line_no - 1].strip()

    @staticmethod
    def _find_containing_function(code: str, line_no: int) -> Optional[str]:
        """Find which function contains a given line."""
        lines = code.split('\n')
        
        # Search backwards from line_no
        for i in range(line_no - 1, -1, -1):
            line = lines[i]
            func_match = re.match(r'^\s*(?:def|function|async\s+function)\s+(\w+)', line)
            if func_match:
                return func_match.group(1)
        
        return None


def scan_agent_security(code: str, language: str) -> List[AgentSecurityFinding]:
    """Convenience function."""
    scanner = AgentSecurityScanner()
    return scanner.scan(code, language)


def findings_to_dicts(findings: List[AgentSecurityFinding]) -> List[dict]:
    """Convert findings to dictionaries for JSON serialization."""
    return [asdict(f) for f in findings]

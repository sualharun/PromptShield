"""
Agent Sink Analyzer – Detect dangerous operations that can be abused by LLMs.

Maps dangerous operations (sinks) to:
- CWE IDs
- OWASP LLM risks
- Severity
- Required mitigations
"""
import re
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum

class SinkCategory(Enum):
    """Categories of dangerous operations."""
    CODE_EXECUTION = "code_execution"
    COMMAND_INJECTION = "command_injection"
    FILE_OPERATIONS = "file_operations"
    SQL_INJECTION = "sql_injection"
    NETWORK_ACCESS = "network_access"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"

@dataclass
class DangerousSink:
    """Represents a dangerous operation (sink) that can harm the system."""
    name: str
    category: SinkCategory
    language: str
    line: int
    severity: str  # critical, high, medium, low
    cwe: str  # e.g., "CWE-78"
    owasp_llm: List[str]  # e.g., ["LLM02", "LLM07"]
    description: str
    pattern: str  # regex that matches this sink
    mitigations: List[str]
    example_attack: Optional[str]


class AgentSinkAnalyzer:
    """Detect dangerous operations in code."""

    # Define dangerous patterns for Python
    PYTHON_SINKS = [
        # Code Execution
        DangerousSink(
            name="eval()",
            category=SinkCategory.CODE_EXECUTION,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-95",
            owasp_llm=["LLM02"],
            description="eval() executes arbitrary Python code provided by LLM",
            pattern=r'\beval\s*\(',
            mitigations=[
                "Never use eval() with untrusted input",
                "Use ast.literal_eval() for safe data parsing",
                "Whitelist allowed operations"
            ],
            example_attack='LLM prompted to: "Execute: eval(\'__import__(\"os\").system(\"rm -rf /\")\')"'
        ),
        DangerousSink(
            name="exec()",
            category=SinkCategory.CODE_EXECUTION,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-95",
            owasp_llm=["LLM02"],
            description="exec() executes arbitrary Python code",
            pattern=r'\bexec\s*\(',
            mitigations=["Never use exec() with untrusted input", "Use restricted execution environments"],
            example_attack='LLM executes: exec("import os; os.system(...)")'
        ),

        # Command Injection
        DangerousSink(
            name="subprocess.run() with shell=True",
            category=SinkCategory.COMMAND_INJECTION,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-78",
            owasp_llm=["LLM02", "LLM07"],
            description="Shell command execution vulnerable to injection",
            pattern=r'subprocess\.run\s*\([^)]*shell\s*=\s*True',
            mitigations=[
                "Use shell=False (default)",
                "Use list args: subprocess.run(['cmd', 'arg'])",
                "Use shlex.quote() to escape arguments"
            ],
            example_attack='LLM inputs: "file.txt; rm -rf /" → command executed'
        ),
        DangerousSink(
            name="os.system()",
            category=SinkCategory.COMMAND_INJECTION,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-78",
            owasp_llm=["LLM02"],
            description="Direct shell command execution",
            pattern=r'\bos\.system\s*\(',
            mitigations=["Use subprocess.run() with list args", "Avoid shell=True"],
            example_attack='LLM input flows into os.system(user_input)'
        ),

        # File Operations
        DangerousSink(
            name="open() for write",
            category=SinkCategory.FILE_OPERATIONS,
            language="python",
            line=0,
            severity="high",
            cwe="CWE-434",
            owasp_llm=["LLM07"],
            description="File write without validated path",
            pattern=r'open\s*\([^)]*["\']?[wa]["\']?\s*\)',
            mitigations=[
                "Validate file path against allowlist",
                "Use os.path.normpath() and check prefix",
                "Restrict to specific directory"
            ],
            example_attack='LLM inputs path: "../../../etc/passwd" → file overwritten'
        ),
        DangerousSink(
            name="os.remove() / shutil.rmtree()",
            category=SinkCategory.FILE_OPERATIONS,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-426",
            owasp_llm=["LLM07"],
            description="File/directory deletion without validation",
            pattern=r'(os\.remove|shutil\.rmtree)\s*\(',
            mitigations=[
                "Validate path is within allowed directory",
                "Require explicit confirmation for deletions",
                "Use filesystem immutability where possible"
            ],
            example_attack='LLM: "delete_file(\'/etc/important\')" → critical files deleted'
        ),

        # SQL Injection
        DangerousSink(
            name="SQL string concatenation",
            category=SinkCategory.SQL_INJECTION,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-89",
            owasp_llm=["LLM02"],
            description="SQL query built with string interpolation",
            pattern=r'(execute|query)\s*\(\s*["\'].*%s.*["\']|f["\'].*\{.*\}.*["\']',
            mitigations=[
                "Use parameterized queries: cursor.execute('... WHERE id = ?', [user_id])",
                "Use ORMs with parameterized APIs",
                "Never concatenate user input into SQL"
            ],
            example_attack='LLM input: "1 OR 1=1 --" → SQL injection'
        ),

        # Network Access
        DangerousSink(
            name="requests/urllib with LLM-controlled URL",
            category=SinkCategory.NETWORK_ACCESS,
            language="python",
            line=0,
            severity="high",
            cwe="CWE-601",
            owasp_llm=["LLM02"],
            description="Network request with untrusted URL",
            pattern=r'(requests\.(get|post)|urllib\.request\.urlopen)\s*\(',
            mitigations=[
                "Validate URL scheme and hostname",
                "Use allowlist of safe domains",
                "Disable redirects or limit hops"
            ],
            example_attack='LLM outputs: "https://attacker.com?steal_data=yes" → SSRF'
        ),
    ]

    # JavaScript sinks
    JAVASCRIPT_SINKS = [
        DangerousSink(
            name="eval()",
            category=SinkCategory.CODE_EXECUTION,
            language="javascript",
            line=0,
            severity="critical",
            cwe="CWE-95",
            owasp_llm=["LLM02"],
            description="eval() executes arbitrary JavaScript",
            pattern=r'\beval\s*\(',
            mitigations=["Never use eval()", "Use Function() with care", "Use vm module with restrictions"],
            example_attack='eval(llmOutput) executes attacker code'
        ),
        DangerousSink(
            name="child_process.exec() with shell",
            category=SinkCategory.COMMAND_INJECTION,
            language="javascript",
            line=0,
            severity="critical",
            cwe="CWE-78",
            owasp_llm=["LLM02"],
            description="Shell command execution",
            pattern=r'child_process\.exec\s*\(',
            mitigations=["Use execFile() or spawn() with array args", "Never user shell=true"],
            example_attack='exec(`command ${llmInput}`) → command injection'
        ),
        DangerousSink(
            name="fs.writeFileSync() without validation",
            category=SinkCategory.FILE_OPERATIONS,
            language="javascript",
            line=0,
            severity="high",
            cwe="CWE-434",
            owasp_llm=["LLM07"],
            description="File write without path validation",
            pattern=r'fs\.write\w+\s*\(',
            mitigations=["Validate filepath against allowlist", "Use path.resolve() and check"],
            example_attack='writeFile(llmPath, data) → arbitrary file written'
        ),
    ]

    def __init__(self):
        self.sinks = self.PYTHON_SINKS + self.JAVASCRIPT_SINKS

    def find_sinks_in_python(self, code: str) -> List[tuple[int, DangerousSink]]:
        """Find dangerous sinks in Python code.
        
        Returns: [(line_number, sink_def), ...]
        """
        results = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            for sink in [s for s in self.PYTHON_SINKS]:
                if re.search(sink.pattern, line):
                    sink_copy = DangerousSink(
                        name=sink.name,
                        category=sink.category,
                        language=sink.language,
                        line=i + 1,  # 1-indexed
                        severity=sink.severity,
                        cwe=sink.cwe,
                        owasp_llm=sink.owasp_llm,
                        description=sink.description,
                        pattern=sink.pattern,
                        mitigations=sink.mitigations,
                        example_attack=sink.example_attack,
                    )
                    results.append((i + 1, sink_copy))
        
        return results

    def find_sinks_in_javascript(self, code: str) -> List[tuple[int, DangerousSink]]:
        """Find dangerous sinks in JavaScript code."""
        results = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            for sink in [s for s in self.JAVASCRIPT_SINKS]:
                if re.search(sink.pattern, line):
                    sink_copy = DangerousSink(
                        name=sink.name,
                        category=sink.category,
                        language=sink.language,
                        line=i + 1,
                        severity=sink.severity,
                        cwe=sink.cwe,
                        owasp_llm=sink.owasp_llm,
                        description=sink.description,
                        pattern=sink.pattern,
                        mitigations=sink.mitigations,
                        example_attack=sink.example_attack,
                    )
                    results.append((i + 1, sink_copy))
        
        return results

    def find_sinks(self, code: str, language: str) -> List[tuple[int, DangerousSink]]:
        """Find dangerous sinks in code."""
        if language.lower() in ["python", "py"]:
            return self.find_sinks_in_python(code)
        elif language.lower() in ["javascript", "typescript", "js", "ts"]:
            return self.find_sinks_in_javascript(code)
        return []


def analyze_sinks(code: str, language: str) -> List[tuple[int, DangerousSink]]:
    """Convenience function."""
    analyzer = AgentSinkAnalyzer()
    return analyzer.find_sinks(code, language)

"""Detect dangerous operations (sinks) that can be abused by LLMs.

Each sink maps to a CWE, one or more OWASP-LLM risks, severity, and mitigations.
"""
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import List, Optional


class SinkCategory(Enum):
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
    name: str
    category: SinkCategory
    language: str
    line: int
    severity: str
    cwe: str
    owasp_llm: List[str]
    description: str
    pattern: str
    mitigations: List[str]
    example_attack: Optional[str]


class AgentSinkAnalyzer:
    PYTHON_SINKS: List[DangerousSink] = [
        DangerousSink(
            name="eval()",
            category=SinkCategory.CODE_EXECUTION,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-95",
            owasp_llm=["LLM02"],
            description="eval() executes arbitrary Python code provided by LLM",
            pattern=r"\beval\s*\(",
            mitigations=[
                "Never use eval() with untrusted input",
                "Use ast.literal_eval() for safe data parsing",
                "Whitelist allowed operations",
            ],
            example_attack='LLM prompted to: "Execute: eval(\'__import__(\"os\").system(\"rm -rf /\")\')"',
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
            pattern=r"\bexec\s*\(",
            mitigations=["Never use exec() with untrusted input", "Use restricted execution environments"],
            example_attack='LLM executes: exec("import os; os.system(...)")',
        ),
        DangerousSink(
            name="subprocess.run() with shell=True",
            category=SinkCategory.COMMAND_INJECTION,
            language="python",
            line=0,
            severity="critical",
            cwe="CWE-78",
            owasp_llm=["LLM02", "LLM07"],
            description="Shell command execution vulnerable to injection",
            pattern=r"subprocess\.run\s*\([^)]*shell\s*=\s*True",
            mitigations=[
                "Use shell=False (default)",
                "Use list args: subprocess.run(['cmd', 'arg'])",
                "Use shlex.quote() to escape arguments",
            ],
            example_attack='LLM inputs: "file.txt; rm -rf /" → command executed',
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
            pattern=r"\bos\.system\s*\(",
            mitigations=["Use subprocess.run() with list args", "Avoid shell=True"],
            example_attack="LLM input flows into os.system(user_input)",
        ),
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
                "Restrict to specific directory",
            ],
            example_attack='LLM inputs path: "../../../etc/passwd" → file overwritten',
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
            pattern=r"(os\.remove|shutil\.rmtree)\s*\(",
            mitigations=[
                "Validate path is within allowed directory",
                "Require explicit confirmation for deletions",
                "Use filesystem immutability where possible",
            ],
            example_attack='LLM: "delete_file(\'/etc/important\')" → critical files deleted',
        ),
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
                "Never concatenate user input into SQL",
            ],
            example_attack='LLM input: "1 OR 1=1 --" → SQL injection',
        ),
        DangerousSink(
            name="requests/urllib with LLM-controlled URL",
            category=SinkCategory.NETWORK_ACCESS,
            language="python",
            line=0,
            severity="high",
            cwe="CWE-601",
            owasp_llm=["LLM02"],
            description="Network request with untrusted URL",
            pattern=r"(requests\.(get|post)|urllib\.request\.urlopen)\s*\(",
            mitigations=[
                "Validate URL scheme and hostname",
                "Use allowlist of safe domains",
                "Disable redirects or limit hops",
            ],
            example_attack='LLM outputs: "https://attacker.com?steal_data=yes" → SSRF',
        ),
    ]

    JAVASCRIPT_SINKS: List[DangerousSink] = [
        DangerousSink(
            name="eval()",
            category=SinkCategory.CODE_EXECUTION,
            language="javascript",
            line=0,
            severity="critical",
            cwe="CWE-95",
            owasp_llm=["LLM02"],
            description="eval() executes arbitrary JavaScript",
            pattern=r"\beval\s*\(",
            mitigations=["Never use eval()", "Use Function() with care", "Use vm module with restrictions"],
            example_attack="eval(llmOutput) executes attacker code",
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
            pattern=r"child_process\.exec\s*\(",
            mitigations=["Use execFile() or spawn() with array args", "Never user shell=true"],
            example_attack="exec(`command ${llmInput}`) → command injection",
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
            pattern=r"fs\.write\w+\s*\(",
            mitigations=["Validate filepath against allowlist", "Use path.resolve() and check"],
            example_attack="writeFile(llmPath, data) → arbitrary file written",
        ),
    ]

    _PY_COMPILED = [(re.compile(s.pattern), s) for s in PYTHON_SINKS]
    _JS_COMPILED = [(re.compile(s.pattern), s) for s in JAVASCRIPT_SINKS]

    def _scan(self, code: str, compiled: List[tuple]) -> List[tuple[int, DangerousSink]]:
        results: List[tuple[int, DangerousSink]] = []
        for i, line in enumerate(code.split("\n"), start=1):
            for rx, sink in compiled:
                if rx.search(line):
                    results.append((i, replace(sink, line=i)))
        return results

    def find_sinks(self, code: str, language: str) -> List[tuple[int, DangerousSink]]:
        lang = language.lower()
        if lang in ("python", "py"):
            return self._scan(code, self._PY_COMPILED)
        if lang in ("javascript", "typescript", "js", "ts"):
            return self._scan(code, self._JS_COMPILED)
        return []


def analyze_sinks(code: str, language: str) -> List[tuple[int, DangerousSink]]:
    return AgentSinkAnalyzer().find_sinks(code, language)

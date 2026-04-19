"""Vulnerable AI Agent — Tool definitions with dangerous capabilities.

This agent exposes tools to an LLM that can execute shell commands, delete
files, run arbitrary SQL, and read any file on the filesystem. None of the
tools validate their inputs or restrict scope.

PromptShield should flag every @tool function in this file.
"""

from langchain.tools import tool
import subprocess
import os
import sqlite3


@tool
def run_shell(command: str) -> str:
    """Execute a shell command and return its output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@tool
def delete_file(path: str) -> str:
    """Delete a file from the filesystem."""
    os.remove(path)
    return f"Deleted {path}"


@tool
def run_query(query: str) -> str:
    """Run a SQL query against the application database."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return str(results)


@tool
def read_file(path: str) -> str:
    """Read the contents of any file on the system."""
    with open(path) as f:
        return f.read()


@tool
def list_directory(directory: str) -> str:
    """List all files in a directory."""
    entries = os.listdir(directory)
    return "\n".join(entries)


# Wire the tools into an agent
from langchain.agents import initialize_agent, AgentType
from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(model="gpt-4", temperature=0)
agent = initialize_agent(
    tools=[run_shell, delete_file, run_query, read_file, list_directory],
    llm=llm,
    agent=AgentType.OPENAI_FUNCTIONS,
    verbose=True,
)

# In production this would receive user messages — any of which could
# contain prompt injection that tricks the agent into calling tools
# with malicious arguments.
user_message = input("Ask the agent: ")
agent.run(user_message)

"""Unsafe LLM Output Handling — Executing AI-generated content.

This code takes raw LLM output and passes it to eval(), exec(),
subprocess.run(), and cursor.execute() without any validation.

PromptShield should flag every dangerous sink that consumes LLM output.
"""

from anthropic import Anthropic
import subprocess
import sqlite3

client = Anthropic()

# --- Example 1: Arbitrary code execution via exec() ---

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=2048,
    messages=[{"role": "user", "content": "Write Python code to process the CSV"}],
)

generated_code = response.content[0].text
exec(generated_code)  # CRITICAL: Arbitrary code execution from LLM output


# --- Example 2: eval() on LLM output ---

response2 = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=256,
    messages=[{"role": "user", "content": "Return a Python expression for the discount"}],
)

discount = eval(response2.content[0].text)  # CRITICAL: eval() on untrusted LLM output


# --- Example 3: Shell command from LLM ---

response3 = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=256,
    messages=[{"role": "user", "content": "What command lists running processes?"}],
)

shell_cmd = response3.content[0].text
result = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True)  # CRITICAL


# --- Example 4: Raw SQL from LLM ---

response4 = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=512,
    messages=[{"role": "user", "content": "Write a SQL query to find inactive users"}],
)

query = response4.content[0].text
conn = sqlite3.connect("app.db")
cursor = conn.cursor()
cursor.execute(query)  # CRITICAL: SQL injection via LLM output
results = cursor.fetchall()
conn.close()


# --- Example 5: LLM output as HTML (XSS) ---
# In a web context:
# element.innerHTML = response.content[0].text  # Would be XSS

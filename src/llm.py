"""LLM client for explaining audit findings."""

import json
import urllib.request
import urllib.error
import os


SYSTEM_PROMPT = """You are an expert Kubernetes security engineer explaining audit findings.

Given a namespace audit with security issues, explain them and provide fixes.

Rules:
- Explain each issue in simple terms
- Provide specific kubectl commands to fix issues
- Prioritize by severity (critical first)
- Include YAML snippets for fixes
- Use markdown formatting
- Be actionable — developers should know exactly what to do

Output in markdown format with:
1. Summary
2. Critical Issues (must fix)
3. Important Issues (should fix)
4. Recommendations"""


def explain_audit(
    audit_prompt: str,
    ollama_url: str = "http://localhost:11434",
    model: str = "llama3.2",
) -> str:
    """Generate audit explanation."""
    user_prompt = f"""Explain these security audit findings and suggest fixes:

{audit_prompt}"""

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.3},
    }

    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            return result["message"]["content"].strip()
    except urllib.error.URLError:
        openai_key = os.environ.get("OPENAI_API_KEY")
        if openai_key:
            return _explain_openai(audit_prompt, openai_key)
        raise ConnectionError(
            f"Cannot connect to Ollama at {ollama_url}. "
            "Start Ollama: ollama serve"
        )


def _explain_openai(audit_prompt: str, api_key: str) -> str:
    """Fallback to OpenAI."""
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Explain these audit findings:\n\n{audit_prompt}"},
        ],
        "temperature": 0.3,
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"].strip()


def check_ollama(ollama_url: str = "http://localhost:11434") -> bool:
    """Check if Ollama is running."""
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False

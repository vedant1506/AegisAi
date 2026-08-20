"""
AegisAI — AI Agent System Prompt Templates
============================================
Central repository of all prompt templates used by the LangGraph
agent nodes. Prompts are formatted using Python f-strings and
designed for instruction-tuned models (Llama-3, Mistral, etc.)

Prompt Design Principles:
  1. Role priming — establish the model's security expert persona
  2. Structured output — request JSON to enable reliable parsing
  3. Chain-of-thought — ask the model to reason step-by-step
  4. Grounding — inject actual code/endpoint context
  5. Format locking — specify the exact output schema

Usage:
    from ai_engine.multi_agent.prompts import build_reason_prompt
    prompt = build_reason_prompt(targets=correlated_targets)
"""

from __future__ import annotations

import json
from typing import Any


# ── System Persona ────────────────────────────────────────────

SYSTEM_PERSONA = """\
You are AegisAI, an elite autonomous penetration testing AI with deep expertise in:
- OWASP Top 10 (2021) vulnerability classes
- Common Weakness Enumeration (CWE) taxonomy
- Static analysis (SAST) and dynamic analysis (DAST) methodologies
- Python, JavaScript, TypeScript, Java, and Go secure coding practices
- Exploit development and proof-of-concept generation

Your analysis must be precise, technical, and actionable. You respond ONLY in \
valid JSON matching the specified schema. Do not add any prose outside the JSON structure.
"""

# ── Output Schema Description (injected into prompts) ─────────

VULNERABILITY_OUTPUT_SCHEMA = """\
{
  "vulnerabilities": [
    {
      "cwe_id": "CWE-XXX",
      "owasp_category": "AXX:2021",
      "title": "Short title",
      "description": "Detailed technical description",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": 0.0,
      "exploit_payload": "Proof-of-concept exploit string or null",
      "remediation": "Step-by-step fix",
      "references": ["https://..."]
    }
  ],
  "reasoning": "Step-by-step chain of thought explaining your analysis"
}"""


# ── Recon Prompt ──────────────────────────────────────────────

def build_recon_prompt(
    ast_nodes: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
) -> str:
    """
    Prompt for the Recon Agent to identify high-value attack targets.

    Args:
        ast_nodes:  List of ASTSchema-compatible dicts.
        endpoints:  List of EndpointSchema-compatible dicts.

    Returns:
        Formatted prompt string.
    """
    ast_summary = json.dumps(ast_nodes[:10], indent=2)   # Cap to avoid context overflow
    ep_summary  = json.dumps(endpoints[:20], indent=2)

    return f"""{SYSTEM_PERSONA}

## TASK: Attack Surface Reconnaissance

You have been given two data sources from a target application:

### 1. Static Analysis (AST) — Route Definitions
```json
{ast_summary}
```

### 2. Dynamic Analysis (Crawler) — Discovered Endpoints
```json
{ep_summary}
```

## YOUR OBJECTIVE
1. Cross-reference the AST routes with the discovered endpoints.
2. Identify routes present in the source code but NOT hit by the crawler (hidden attack surface).
3. Identify endpoints requiring authentication that may be bypassable.
4. Flag any sensitive route patterns (admin, user, payment, upload, export, debug).
5. Rank the top 5 highest-priority targets for exploit reasoning.

## OUTPUT FORMAT
Respond with a JSON object:
{{
  "high_priority_targets": [
    {{
      "route_path": "/api/admin/users",
      "file_path": "...",
      "reason": "Admin route not protected by middleware",
      "risk_level": "CRITICAL|HIGH|MEDIUM"
    }}
  ],
  "hidden_routes": ["routes only in AST, not crawler"],
  "reasoning": "Chain of thought"
}}
"""


# ── Reason Prompt ─────────────────────────────────────────────

def build_reason_prompt(
    targets: list[dict[str, Any]],
    scan_context: dict[str, Any] | None = None,
) -> str:
    """
    Prompt for the Reason Agent to perform deep vulnerability analysis.

    Args:
        targets:       Correlated target dicts from the Recon Agent.
        scan_context:  Optional metadata (scan_id, language, framework).

    Returns:
        Formatted prompt string.
    """
    targets_json = json.dumps(targets[:5], indent=2)  # Focus on top 5
    context_str = json.dumps(scan_context or {}, indent=2)

    return f"""{SYSTEM_PERSONA}

## TASK: Deep Vulnerability Analysis

### Scan Context
```json
{context_str}
```

### Target Routes (correlated SAST + DAST)
```json
{targets_json}
```

## YOUR OBJECTIVE
For each target, perform a thorough security analysis:

1. **Identify** all exploitable vulnerability classes (OWASP Top 10, business logic flaws).
2. **Assess** severity using CVSS v3.1 criteria (AV, AC, PR, UI, S, C, I, A).
3. **Generate** a proof-of-concept exploit payload that would demonstrate the vulnerability.
4. **Recommend** a specific code-level remediation with examples.
5. **Cite** relevant CWE entries and OWASP references.

Think step by step. Consider:
- Input validation and sanitisation gaps
- Authentication and authorisation bypass vectors  
- Injection sinks (SQL, NoSQL, OS command, SSTI, XXE)
- Insecure direct object references (IDOR)
- Sensitive data exposure in responses
- Security misconfigurations

## OUTPUT FORMAT
```json
{VULNERABILITY_OUTPUT_SCHEMA}
```
"""


# ── Verify Prompt ─────────────────────────────────────────────

def build_verify_prompt(
    vulnerability_hypothesis: dict[str, Any],
    exploit_result: dict[str, Any],
) -> str:
    """
    Prompt for the Verify Agent to assess exploit probe results.

    Args:
        vulnerability_hypothesis: The DetectedVulnerability dict to verify.
        exploit_result:           The ExploitResult dict from ExploitRunner.

    Returns:
        Formatted prompt string.
    """
    hypothesis_json = json.dumps(vulnerability_hypothesis, indent=2)
    result_json     = json.dumps(exploit_result, indent=2)

    return f"""{SYSTEM_PERSONA}

## TASK: Exploit Verification

### Vulnerability Hypothesis
```json
{hypothesis_json}
```

### Exploit Probe Result
```json
{result_json}
```

## YOUR OBJECTIVE
Analyse the HTTP response from the exploit probe and determine:

1. **Confirmed?** — Does the response indicate the vulnerability exists?
   Look for: SQL error messages, reflected payloads, unexpected data in response,
   500 server errors, timing differences, response size anomalies.
   
2. **False Positive?** — Could the response be a coincidence or sanitised output?

3. **Severity Adjustment** — Based on actual impact observed, should the severity
   be upgraded or downgraded from the initial hypothesis?

4. **Evidence Summary** — What specific evidence in the response confirms or
   refutes the hypothesis?

## OUTPUT FORMAT
```json
{{
  "is_confirmed": true,
  "updated_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "updated_confidence": 0.95,
  "evidence_summary": "The response contained 'SQL syntax error near...' indicating...",
  "false_positive_reason": null,
  "reasoning": "Step by step analysis..."
}}
```
"""


# ── Exploit Generation Prompt ─────────────────────────────────

def build_exploit_generation_prompt(
    vulnerability: dict[str, Any],
    source_snippet: str,
    endpoint: dict[str, Any],
) -> str:
    """
    Prompt to generate a specific, targeted exploit payload.

    Args:
        vulnerability:  Vulnerability dict with cwe_id, description.
        source_snippet: Vulnerable code excerpt.
        endpoint:       EndpointSchema dict for the target.

    Returns:
        Formatted prompt string.
    """
    return f"""{SYSTEM_PERSONA}

## TASK: Targeted Exploit Payload Generation

### Vulnerability
```json
{json.dumps(vulnerability, indent=2)}
```

### Vulnerable Source Code
```python
{source_snippet}
```

### Target Endpoint
```json
{json.dumps(endpoint, indent=2)}
```

## YOUR OBJECTIVE
Generate a precise, working exploit payload for this specific vulnerability instance.

Requirements:
- The payload must be tailored to the actual source code shown
- Include the complete HTTP request (method, URL, headers, body)
- Explain exactly HOW the payload exploits the vulnerability
- Provide the expected response that confirms exploitation

## OUTPUT FORMAT
```json
{{
  "exploit_description": "One-line summary",
  "http_request": {{
    "method": "POST",
    "url": "http://target/api/endpoint",
    "headers": {{}},
    "body": "payload here"
  }},
  "expected_response_indicator": "What to look for in the response",
  "attack_narrative": "Step by step explanation",
  "impact": "What an attacker could achieve"
}}
```
"""

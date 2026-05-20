import json


# -----------------------------------------
# SAFE SERIALIZER
# -----------------------------------------

def safe_format(data):
    """
    Safely convert Python objects to readable JSON string
    for LLM prompts.
    """
    try:
        return json.dumps(data, indent=2, default=str)
    except Exception:
        return str(data)


# -----------------------------------------
# MAIN SECURITY ANALYSIS PROMPT
# -----------------------------------------

def build_security_prompt(features, attacks, recommendations):
    """
    Builds a structured prompt for LLM security analysis.
    """

    features_str = safe_format(features)
    attacks_str = safe_format(attacks)
    recommendations_str = safe_format(recommendations)

    prompt = f"""
You are an expert Quantum Cybersecurity Analyst working in a Security Operations Center (SOC).

Your task is to analyze TLS cryptographic configurations and assess their security against classical and quantum attacks.

----------------------------------------
SYSTEM DATA
----------------------------------------

🔹 TLS & Crypto Features:
{features_str}

🔹 Simulated Attacks:
{attacks_str}

🔹 Recommended Fixes:
{recommendations_str}

----------------------------------------
ANALYSIS TASKS
----------------------------------------

1. Identify all major security risks in the system
2. Determine which attack is the most critical and why
3. Explain the impact of quantum computing on this system
4. Evaluate whether the system is future-proof (PQC readiness)
5. Suggest prioritized mitigation steps
6. Give a final security verdict (SAFE / MODERATE / HIGH RISK / CRITICAL)

----------------------------------------
RESPONSE FORMAT
----------------------------------------

Provide your answer in this structure:

Security Summary:
- ...

Critical Risk:
- ...

Quantum Threat Analysis:
- ...

Recommended Actions:
- ...

Final Verdict:
- ...

----------------------------------------

Be concise, professional, and technical.
Avoid unnecessary explanations.
"""

    return prompt


# -----------------------------------------
# ATTACK REASONING PROMPT
# -----------------------------------------

def build_attack_reasoning_prompt(features):
    """
    Used to let AI decide which attacks are possible.
    """

    features_str = safe_format(features)

    return f"""
You are a cybersecurity attack simulation engine.

Given the TLS configuration below, determine possible attack vectors.

Features:
{features_str}

Tasks:
1. Identify applicable attacks (Shor, Grover, TLS Downgrade, MITM, HNDL)
2. Rank attacks by severity
3. Return structured list

Output format:
[
  {{
    "attack": "...",
    "severity": "...",
    "reason": "..."
  }}
]
"""


# -----------------------------------------
# PQC MIGRATION PROMPT
# -----------------------------------------

def build_pqc_prompt(features):
    """
    Generates prompt for PQC migration strategy.
    """

    features_str = safe_format(features)

    return f"""
You are a Post-Quantum Cryptography expert.

Analyze the following cryptographic configuration and recommend a migration plan.

Features:
{features_str}

Tasks:
1. Identify quantum-vulnerable components
2. Suggest PQC replacements (Kyber, Dilithium, Falcon)
3. Suggest hybrid deployment strategy
4. Provide step-by-step migration plan

Be practical and implementation-focused.
"""


# -----------------------------------------
# REPORT GENERATION PROMPT
# -----------------------------------------

def build_report_prompt(asset, analysis):
    """
    Generate final human-readable report.
    """

    analysis_str = safe_format(analysis)

    return f"""
Generate a professional cybersecurity report.

Asset:
{asset}

Analysis:
{analysis_str}

Include:
1. Overview
2. Risk Summary
3. Attack Simulation Results
4. Quantum Risk Assessment
5. Recommendations

Make it suitable for enterprise reporting.
"""
# -----------------------------------------
# AI CHAT ACTION PROMPT
# -----------------------------------------

def build_chat_system_prompt():

    return """
You are QuantumSentinel AI Security Assistant.

Your responsibilities:
- Help users with cybersecurity analysis
- Explain vulnerabilities
- Assist with PQC readiness
- Trigger scans when user asks

IMPORTANT:

If user asks to scan a domain,
respond ONLY in this JSON format:

{
  "action": "start_scan",
  "domain": "example.com"
}

Examples:
User: scan google.com
Response:
{
  "action": "start_scan",
  "domain": "google.com"
}

User: analyze microsoft.com
Response:
{
  "action": "start_scan",
  "domain": "microsoft.com"
}

For normal cybersecurity questions,
respond normally in professional format.

Never explain JSON.
Never add markdown.
"""
import anthropic
import json
import os
import re
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── CVSS Rubric ───────────────────────────────────────────────────────────────
CVSS_RUBRIC = """
CVSS v3.1 Base Score Metrics:

Attack Vector (AV):
  Network(N) = exploitable remotely over internet
  Adjacent(A) = requires local network access
  Local(L) = requires local system access
  Physical(P) = requires physical access

Attack Complexity (AC):
  Low(L) = no special conditions required
  High(H) = requires specific circumstances

Privileges Required (PR):
  None(N) = no authentication needed
  Low(L) = basic user privileges
  High(H) = admin privileges required

User Interaction (UI):
  None(N) = no victim action needed
  Required(R) = victim must take action

Scope (S):
  Unchanged(U) = impact limited to vulnerable component
  Changed(C) = impact spreads beyond vulnerable component

Confidentiality (C): None(N) Low(L) High(H)
Integrity (I):       None(N) Low(L) High(H)
Availability (A):    None(N) Low(L) High(H)

Score ranges:
  0.0       = None
  0.1-3.9   = Low
  4.0-6.9   = Medium
  7.0-8.9   = High
  9.0-10.0  = Critical
"""

# ── System Prompt ─────────────────────────────────────────────────────────────
SCORER_SYSTEM = f"""You are a CVSS 3.1 certified security analyst.
Score security threats with precise CVSS 3.1 base scores.

{CVSS_RUBRIC}

RULES:
- Output ONLY valid JSON array. No markdown, no explanation.
- Be calibrated: most threats score 4.0-8.9.
- Reserve 9.0+ for truly catastrophic threats only.
- CVSS vector string must be syntactically valid.
- Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- Do NOT include newline characters inside JSON string values.
- Return ALL fields from the input threat plus the new scoring fields.
- NEVER drop the threat_title, threat_source, or threat_category fields.
"""

# ── Scoring Prompt ────────────────────────────────────────────────────────────
SCORER_PROMPT = """Score each threat with CVSS 3.1 base scores.

Threats to score:
{threats_json}

Return a JSON array. Each object MUST include ALL original fields from the
input PLUS these new scoring fields:

{{
  ... all original threat fields preserved exactly ...
  "cvss_vector": "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X",
  "cvss_base_score": 7.5,
  "cvss_severity": "Critical or High or Medium or Low or Informational",
  "priority": 1,
  "risk_statement": "IF this threat occurs THEN this impact affects this asset",
  "remediation_effort": "Low or Medium or High",
  "remediation_timeline": "Immediate (24h) or Short-term (1 week) or Medium-term (1 month) or Long-term (quarter)"
}}

Sort by cvss_base_score descending. Assign priority 1 = highest risk.
IMPORTANT: Preserve ALL input fields. Do not drop any field."""


# ── JSON Repair ───────────────────────────────────────────────────────────────
def fix_json(raw: str) -> str:
    """Fix truncated or malformed JSON."""
    raw = raw.strip()

    # Remove invalid control characters
    raw = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', raw)

    # Replace literal newlines inside JSON strings with space
    def clean_strings(text):
        result = []
        in_string = False
        escape_next = False
        for char in text:
            if escape_next:
                result.append(char)
                escape_next = False
            elif char == '\\' and in_string:
                result.append(char)
                escape_next = True
            elif char == '"':
                result.append(char)
                in_string = not in_string
            elif char == '\n' and in_string:
                result.append(' ')
            else:
                result.append(char)
        return ''.join(result)

    raw = clean_strings(raw)

    # Fix truncated JSON
    if not raw.endswith("]"):
        last_brace = raw.rfind("}")
        if last_brace != -1:
            raw = raw[:last_brace + 1] + "\n]"

    return raw


# ── Main Scoring Function ─────────────────────────────────────────────────────
def score_threats(threats: list) -> list:
    """
    Add CVSS 3.1 scores and priority rankings to threat list.
    Processes in batches of 15 to stay within token limits.

    Returns:
        scored (list): Threats sorted by CVSS score with priority rankings
    """
    BATCH_SIZE = 15
    scored = []

    for i in range(0, len(threats), BATCH_SIZE):
        batch = threats[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (len(threats) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"   Scoring batch {batch_num}/{total_batches} "
              f"({len(batch)} threats)...")

        threats_json = json.dumps(batch, indent=2)
        prompt = SCORER_PROMPT.replace("{threats_json}", threats_json)

        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            system=SCORER_SYSTEM,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        raw = fix_json(raw)

        try:
            batch_scored = json.loads(raw.strip())

            # Merge original fields back in case Claude dropped any
            for scored_t in batch_scored:
                original = next(
                    (t for t in batch
                     if t.get("threat_id") == scored_t.get("threat_id")),
                    None
                )
                if original:
                    for key, value in original.items():
                        if key not in scored_t:
                            scored_t[key] = value

            scored.extend(batch_scored)

        except json.JSONDecodeError as e:
            print(f"   ⚠️  Batch {batch_num} parse error — using defaults: {e}")
            for t in batch:
                t.update({
                    "cvss_vector": "N/A",
                    "cvss_base_score": 0.0,
                    "cvss_severity": "Unknown",
                    "priority": 99,
                    "risk_statement": "Unable to score — review manually",
                    "remediation_effort": "Unknown",
                    "remediation_timeline": "Unknown"
                })
                scored.append(t)

    # Sort globally by CVSS score and re-assign priority
    scored.sort(key=lambda x: x.get("cvss_base_score", 0), reverse=True)
    for i, t in enumerate(scored):
        t["priority"] = i + 1

    return scored


def get_severity_summary(scored_threats: list) -> dict:
    """Return count breakdown by severity for executive summary."""
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
        "Unknown": 0
    }
    for t in scored_threats:
        sev = t.get("cvss_severity", "Unknown")
        summary[sev] = summary.get(sev, 0) + 1
    return summary


# ── Test Runner ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🧪 Testing scorer with sample threats...\n")

    sample_threats = [
        {
            "threat_id": "T001",
            "target_id": "comp_2",
            "target_name": "Node.js API",
            "target_type": "component",
            "threat_source": "STRIDE",
            "threat_category": "I",
            "threat_category_name": "Information Disclosure",
            "threat_title": "JWT Secret Exposure via Verbose Error Messages",
            "threat_description": "API returns stack traces in production exposing JWT secrets",
            "attack_scenario": "Step 1: Attacker triggers error. Step 2: Stack trace reveals JWT secret. Step 3: Attacker forges tokens.",
            "attack_vector": "Network",
            "attacker_profile": "External Attacker",
            "prerequisites": "Application running in debug mode",
            "impact": "Full authentication bypass — attacker forges any JWT token",
            "likelihood": "Medium",
            "cwe_id": "CWE-209",
            "cwe_name": "Generation of Error Message Containing Sensitive Information",
            "owasp_category": "A09:2021 Security Logging and Monitoring Failures",
            "mitigation": "Disable debug mode in production. Use generic error responses.",
            "mitigation_type": "Preventive"
        },
        {
            "threat_id": "T002",
            "target_id": "comp_3",
            "target_name": "Scanner Agent",
            "target_type": "component",
            "threat_source": "SINGLE-AGENT",
            "threat_category": "SA01",
            "threat_category_name": "SA01: Prompt Injection",
            "threat_title": "Prompt Injection via Malicious Code Comment",
            "threat_description": "Attacker embeds override instructions in code comments",
            "attack_scenario": "Step 1: Attacker submits PR with malicious comment. Step 2: Agent reads code including comment. Step 3: Agent follows injected instructions.",
            "attack_vector": "Prompt",
            "attacker_profile": "External Attacker",
            "prerequisites": "Ability to submit a pull request",
            "impact": "Agent performs unauthorized actions bypassing security controls",
            "likelihood": "High",
            "cwe_id": "N/A",
            "cwe_name": "N/A",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "mitigation": "Sanitize all code content before including in agent context window.",
            "mitigation_type": "Preventive"
        },
        {
            "threat_id": "T003",
            "target_id": "comp_2",
            "target_name": "LangGraph Orchestrator",
            "target_type": "component",
            "threat_source": "MULTI-AGENT",
            "threat_category": "MA09",
            "threat_category_name": "MA09: Compromised Orchestrator",
            "threat_title": "Orchestrator Hijacked to Redirect All Worker Agents",
            "threat_description": "Compromised orchestrator redirects all agents to serve attacker",
            "attack_scenario": "Step 1: Attacker compromises orchestrator via prompt injection. Step 2: Orchestrator sends malicious tasks to all agents. Step 3: All agents perform attacker-controlled actions.",
            "attack_vector": "Inter-Agent",
            "attacker_profile": "Compromised Agent",
            "prerequisites": "Initial access to orchestrator input",
            "impact": "Full pipeline compromise — all agent actions controlled by attacker",
            "likelihood": "High",
            "cwe_id": "N/A",
            "cwe_name": "N/A",
            "owasp_category": "N/A",
            "mitigation": "Implement orchestrator integrity monitoring and human-in-the-loop approval for all irreversible actions.",
            "mitigation_type": "Preventive"
        },
        {
            "threat_id": "T004",
            "target_id": "comp_3",
            "target_name": "PostgreSQL Database",
            "target_type": "component",
            "threat_source": "STRIDE",
            "threat_category": "E",
            "threat_category_name": "Elevation of Privilege",
            "threat_title": "SQL Injection via Unsanitized API Input",
            "threat_description": "Unsanitized user input passed to SQL queries allows privilege escalation",
            "attack_scenario": "Step 1: Attacker sends crafted SQL payload in API request. Step 2: Payload executes with database privileges. Step 3: Attacker reads or modifies all data.",
            "attack_vector": "Network",
            "attacker_profile": "External Attacker",
            "prerequisites": "Access to any API endpoint that queries the database",
            "impact": "Full database compromise — all customer PII exposed or modified",
            "likelihood": "Medium",
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "owasp_category": "A03:2021 Injection",
            "mitigation": "Use parameterized queries and ORM. Never concatenate user input into SQL.",
            "mitigation_type": "Preventive"
        }
    ]

    scored = score_threats(sample_threats)
    summary = get_severity_summary(scored)

    print(f"\n✅ Scoring complete!")
    print(f"\nSeverity Summary:")

    icons = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢",
        "Informational": "⚪",
        "Unknown": "⚫"
    }

    for sev, count in summary.items():
        if count > 0:
            print(f"   {icons.get(sev, '⚫')} {sev}: {count}")

    print(f"\nTop threats by CVSS score:")
    for t in scored:
        title = t.get("threat_title", t.get("threat_id", "Unknown"))
        source = t.get("threat_source", "?")
        category = t.get("threat_category", "?")
        severity = t.get("cvss_severity", "?")
        score = t.get("cvss_base_score", "?")
        priority = t.get("priority", "?")
        vector = t.get("cvss_vector", "N/A")
        timeline = t.get("remediation_timeline", "N/A")
        risk = t.get("risk_statement", "N/A")

        print(f"   [{severity:12}] Score: {score} | "
              f"Priority: #{priority} | [{source}][{category}]")
        print(f"   Title    : {title[:60]}...")
        print(f"   Vector   : {vector}")
        print(f"   Timeline : {timeline}")
        print(f"   Risk     : {risk[:80]}...")
        print()
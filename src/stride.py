import anthropic
import json
import os
import re
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── STRIDE Definitions ────────────────────────────────────────────────────────
STRIDE_DEFINITIONS = """
STRIDE Threat Categories:
- S (Spoofing): Attacker impersonates a user, service, or component
- T (Tampering): Unauthorized modification of data in transit or at rest
- R (Repudiation): Deny performing an action — lack of audit trail
- I (Information Disclosure): Unauthorized access to sensitive data
- D (Denial of Service): Making a service unavailable to legitimate users
- E (Elevation of Privilege): Gaining more access than authorized
"""

# ── Agentic AI Threat Definitions ─────────────────────────────────────────────
AGENTIC_THREAT_DEFINITIONS = """
Single-Agent Threat Categories (SA):
- SA01: Prompt Injection — attacker overrides agent system prompt via crafted input
- SA02: Unsafe Tool Execution — agent calls dangerous tools without input validation
- SA03: Insecure Output Handling — agent output rendered or executed without sanitization
- SA04: Excessive Agency — agent takes actions beyond its intended scope
- SA05: Credential Theft via Tools — agent leaks API keys or secrets through tool responses
- SA06: Memory Manipulation — agent context window poisoned via malicious observations
- SA07: Goal Hijacking — attacker redirects agent objective via environment observations
- SA08: Agent Denial of Service — resource exhaustion via expensive or looping agent tasks

Multi-Agent Threat Categories (MA):
- MA01: Agent Impersonation — malicious agent masquerades as trusted agent in pipeline
- MA02: Insecure Inter-Agent Communication — agents blindly trust each other without verification
- MA03: Indirect Prompt Injection via Environment — malicious content in observations hijacks agent
- MA04: Uncontrolled Agent Recursion — orchestrator spawns infinite sub-agents or loops
- MA05: Shared Memory Poisoning — corrupting shared agent memory or LangGraph checkpointer state
- MA06: Privilege Escalation via Tool Chaining — agent chain accumulates elevated access across hops
- MA07: Excessive Autonomous Action — irreversible real-world actions without human approval gate
- MA08: Goal Hijacking across Agents — compromised upstream agent redirects downstream agents
- MA09: Compromised Orchestrator — orchestrator hijacked to redirect all worker agents maliciously
- MA10: MCP Tool Abuse — malicious or misconfigured MCP server exposes dangerous tools to agents
"""

# ── Keywords ──────────────────────────────────────────────────────────────────
AGENTIC_KEYWORDS = [
    "agent", "agentic", "langgraph", "langchain", "autogen", "crewai",
    "orchestrat", "supervisor", "worker agent", "sub-agent", "multi-agent",
    "tool use", "tool-use", "tool call", "function call", "mcp",
    "model context protocol", "react agent", "autonomous", "memory",
    "long-term memory", "pipeline agent", "claude", "gpt", "llm",
    "openai", "anthropic", "gemini", "llama", "ai", "embedding",
    "vector", "rag", "chatbot", "copilot", "assistant"
]

MULTI_AGENT_KEYWORDS = [
    "orchestrat", "supervisor", "worker agent", "sub-agent",
    "multi-agent", "langgraph", "autogen", "crewai", "agent team",
    "scanner agent", "triage agent", "fixer agent", "planner agent"
]

# ── System Prompt ─────────────────────────────────────────────────────────────
STRIDE_SYSTEM = f"""You are a world-class AppSec engineer and AI security researcher
specializing in threat modeling for traditional applications and agentic AI systems.

You apply two threat frameworks simultaneously:
1. STRIDE — for all traditional application components
2. Agentic AI Threats — for single-agent and multi-agent AI systems

{STRIDE_DEFINITIONS}

{AGENTIC_THREAT_DEFINITIONS}

CRITICAL OUTPUT RULES — FOLLOW EXACTLY:
- Output ONLY a valid JSON array. No markdown fences, no explanation, no preamble.
- Traditional app threats: threat_source MUST be exactly the string "STRIDE"
- Single agent threats: threat_source MUST be exactly the string "SINGLE-AGENT"
- Multi-agent threats: threat_source MUST be exactly the string "MULTI-AGENT"
- NEVER label agentic threats as STRIDE — completely different frameworks
- NEVER label multi-agent threats as SINGLE-AGENT
- When multi-agent system detected you MUST output these exact threats:
    * One threat with threat_category "MA01" and threat_source "MULTI-AGENT"
    * One threat with threat_category "MA02" and threat_source "MULTI-AGENT"
    * One threat with threat_category "MA03" and threat_source "MULTI-AGENT"
    * One threat with threat_category "MA04" and threat_source "MULTI-AGENT"
    * One threat with threat_category "MA07" and threat_source "MULTI-AGENT"
    * One threat with threat_category "MA09" and threat_source "MULTI-AGENT"
    * One threat with threat_category "MA10" and threat_source "MULTI-AGENT"
- In JSON strings use a space instead of newline characters
- Do NOT include newline characters inside any JSON string value
- Every threat needs a specific actionable mitigation
"""

# ── Analysis Prompt ───────────────────────────────────────────────────────────
STRIDE_PROMPT = """Perform a two-layer threat analysis on this architecture.

Architecture:
{architecture_json}

Agent Components Detected: {agent_components}
Multi-Agent System: {is_multi_agent}

LAYER 1 — STRIDE ANALYSIS (all components):
Analyze every component for all 6 STRIDE categories.
Analyze every data flow crossing a trust boundary.
Focus on: internet-facing components, auth flows, databases, third-party services.

LAYER 2 — AGENTIC AI THREAT ANALYSIS (agent components only):
For SINGLE-AGENT systems: generate SA01 to SA08 threats
For MULTI-AGENT systems: generate SA01 to SA08 AND MA01 to MA10 threats

Focus on:
- Tool execution boundaries: what tools can each agent call?
- Inter-agent trust: do agents verify each other before acting?
- Memory and state: can agent memory be poisoned?
- Human-in-the-loop: what actions happen without human approval?
- MCP servers: are tool schemas validated before execution?
- Code in context: can code comments inject malicious instructions?

REMEMBER: Use threat_source = "SINGLE-AGENT" for SA threats
and threat_source = "MULTI-AGENT" for MA threats.
Never use threat_source = "STRIDE" for agentic threats.

Output a JSON array. Each object MUST follow this EXACT schema:
[
  {{
    "threat_id": "T001",
    "target_id": "comp_id or flow_id",
    "target_name": "component or flow name",
    "target_type": "component or data_flow",
    "threat_source": "STRIDE or SINGLE-AGENT or MULTI-AGENT",
    "threat_category": "S or T or R or I or D or E or SA01-SA08 or MA01-MA10",
    "threat_category_name": "full category name",
    "threat_title": "concise descriptive title",
    "threat_description": "detailed explanation of the vulnerability",
    "attack_scenario": "Step 1: attacker does X. Step 2: this causes Y. Step 3: impact is Z.",
    "attack_vector": "Network or Adjacent or Local or Physical or Prompt or Inter-Agent",
    "attacker_profile": "External Attacker or Authenticated User or Insider or Malicious Prompt or Compromised Agent",
    "prerequisites": "what the attacker needs",
    "impact": "specific business and technical impact",
    "likelihood": "High or Medium or Low",
    "cwe_id": "CWE-xxx or N/A",
    "cwe_name": "full CWE name or N/A",
    "owasp_category": "OWASP reference or N/A",
    "mitigation": "specific technical control",
    "mitigation_type": "Preventive or Detective or Corrective"
  }}
]"""


# ── Detection Functions ───────────────────────────────────────────────────────
def detect_agent_components(architecture: dict) -> list:
    """Detect agent and AI components in the architecture."""
    agent_components = []
    for comp in architecture.get("components", []):
        comp_text = (
            comp.get("name", "") + " " +
            comp.get("description", "") + " " +
            " ".join(comp.get("tech_stack", []))
        ).lower()
        if any(kw in comp_text for kw in AGENTIC_KEYWORDS):
            agent_components.append(comp["name"])
    return agent_components


def detect_multi_agent(architecture: dict) -> bool:
    """Determine if architecture is a multi-agent system."""
    agent_count = 0
    for comp in architecture.get("components", []):
        comp_text = (
            comp.get("name", "") + " " +
            comp.get("description", "") + " " +
            " ".join(comp.get("tech_stack", []))
        ).lower()
        if any(kw in comp_text for kw in MULTI_AGENT_KEYWORDS):
            return True
        if any(kw in comp_text for kw in ["agent", "llm", "claude", "gpt"]):
            agent_count += 1
    return agent_count > 1


# ── JSON Repair Functions ─────────────────────────────────────────────────────
def fix_truncated_json(raw: str) -> str:
    """Fix JSON that was cut off or has control characters."""
    raw = raw.strip()

    # Remove invalid control characters except tab, newline, carriage return
    raw = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', raw)

    # Replace literal newlines inside JSON strings with a space
    def replace_newlines_in_strings(text):
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

    raw = replace_newlines_in_strings(raw)

    # Fix truncated JSON
    if not raw.endswith("]"):
        last_brace = raw.rfind("}")
        if last_brace != -1:
            raw = raw[:last_brace + 1] + "\n]"

    return raw


# ── Main Analysis Function ────────────────────────────────────────────────────
def analyze_stride(architecture: dict) -> tuple:
    """
    Run STRIDE + Agentic AI threat analysis.

    Returns:
        threats (list): All generated threats
        agent_components (list): Detected agent component names
        multi_agent (bool): Whether multi-agent system was detected
    """
    agent_components = detect_agent_components(architecture)
    multi_agent = detect_multi_agent(architecture)

    # Report detection
    if multi_agent:
        print(f"   🤖 Multi-agent system detected")
        print(f"   → Applying STRIDE + Single-Agent (SA) + Multi-Agent (MA) threats")
    elif agent_components:
        print(f"   🧠 Single-agent: {', '.join(agent_components[:3])}")
        print(f"   → Applying STRIDE + Single-Agent (SA) threats")
    else:
        print(f"   → Traditional application — applying STRIDE only")

    arch_json = json.dumps(architecture, indent=2)

    # ── Call 1: STRIDE + Single-Agent threats ────────────────────────────────
    prompt = STRIDE_PROMPT.replace(
        "{architecture_json}", arch_json
    ).replace(
        "{agent_components}",
        ", ".join(agent_components) if agent_components else "None detected"
    ).replace(
        "{is_multi_agent}",
        "YES — MUST generate MA01-MA10 with threat_source MULTI-AGENT"
        if multi_agent else
        "NO — generate SA01-SA08 with threat_source SINGLE-AGENT only"
    )

    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=8192,
        system=STRIDE_SYSTEM,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]

    raw = fix_truncated_json(raw)

    try:
        threats = json.loads(raw.strip())
    except json.JSONDecodeError:
        try:
            raw = re.sub(r'\n\s*', ' ', raw)
            threats = json.loads(raw.strip())
        except json.JSONDecodeError:
            threats = []
            pattern = re.compile(r'\{[^{}]*\}', re.DOTALL)
            for match in pattern.finditer(raw):
                try:
                    obj = json.loads(match.group())
                    if "threat_title" in obj:
                        threats.append(obj)
                except json.JSONDecodeError:
                    continue
            print(f"   ⚠️  Recovered {len(threats)} threats after repair")

    # ── Call 2: Force MA threats for multi-agent systems ─────────────────────
    if multi_agent:
        print(f"   → Generating Multi-Agent threats (MA01-MA10)...")

        ma_prompt = f"""You are an AI security expert. Generate EXACTLY 7 multi-agent 
security threats for this architecture. Output ONLY a valid JSON array.

Architecture:
{arch_json}

You MUST generate one threat for each of these categories:
MA01, MA02, MA03, MA04, MA07, MA09, MA10

Every threat MUST have:
- threat_source = "MULTI-AGENT"
- threat_category = one of MA01 MA02 MA03 MA04 MA07 MA09 MA10
- All other fields filled in

Output JSON array with this schema:
[
  {{
    "threat_id": "MA001",
    "target_id": "comp_id",
    "target_name": "component name",
    "target_type": "component",
    "threat_source": "MULTI-AGENT",
    "threat_category": "MA01",
    "threat_category_name": "Agent Impersonation",
    "threat_title": "concise title",
    "threat_description": "detailed description",
    "attack_scenario": "Step 1: X happens. Step 2: Y occurs. Step 3: Z is the impact.",
    "attack_vector": "Inter-Agent",
    "attacker_profile": "Compromised Agent",
    "prerequisites": "what attacker needs",
    "impact": "business and technical impact",
    "likelihood": "High or Medium or Low",
    "cwe_id": "CWE-xxx or N/A",
    "cwe_name": "CWE name or N/A",
    "owasp_category": "OWASP reference or N/A",
    "mitigation": "specific technical control",
    "mitigation_type": "Preventive or Detective or Corrective"
  }}
]"""

        ma_response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            messages=[{"role": "user", "content": ma_prompt}]
        )

        ma_raw = ma_response.content[0].text.strip()
        if ma_raw.startswith("```"):
            ma_raw = ma_raw.split("```")[1]
            if ma_raw.startswith("json"):
                ma_raw = ma_raw[4:]

        ma_raw = fix_truncated_json(ma_raw)

        try:
            ma_threats = json.loads(ma_raw.strip())
            # Force correct labels on every MA threat
            for t in ma_threats:
                t["threat_source"] = "MULTI-AGENT"
            threats.extend(ma_threats)
            print(f"   ✓ Added {len(ma_threats)} Multi-Agent threats")
        except json.JSONDecodeError:
            print(f"   ⚠️  Could not parse MA threats")

    # ── Re-number all threats sequentially ───────────────────────────────────
    for i, threat in enumerate(threats):
        threat["threat_id"] = f"T{str(i+1).zfill(3)}"

    return threats, agent_components, multi_agent


# ── Test Runner ───────────────────────────────────────────────────────────────
if __name__ == "__main__":

    # ── TEST 1: Traditional Web Application ──────────────────────────────────
    print("\n" + "="*60)
    print("TEST 1: Traditional Web Application (STRIDE Only)")
    print("="*60)

    traditional_arch = {
        "system_name": "E-Commerce Web App",
        "components": [
            {
                "id": "comp_1",
                "name": "React Frontend",
                "type": "WebApp",
                "tech_stack": ["React", "TypeScript"],
                "trust_level": "INTERNET",
                "description": "Customer-facing storefront"
            },
            {
                "id": "comp_2",
                "name": "Node.js API",
                "type": "API",
                "tech_stack": ["Node.js", "Express", "JWT"],
                "trust_level": "DMZ",
                "description": "REST API handling orders and authentication"
            },
            {
                "id": "comp_3",
                "name": "PostgreSQL Database",
                "type": "Database",
                "tech_stack": ["PostgreSQL"],
                "trust_level": "PRIVILEGED",
                "description": "Database storing orders and customer PII"
            }
        ],
        "data_flows": [
            {
                "id": "flow_1",
                "from": "comp_1",
                "to": "comp_2",
                "data_type": "User credentials and order data",
                "protocol": "HTTPS",
                "encrypted": True,
                "authenticated": False,
                "crosses_trust_boundary": True
            },
            {
                "id": "flow_2",
                "from": "comp_2",
                "to": "comp_3",
                "data_type": "SQL queries with customer PII",
                "protocol": "SQL",
                "encrypted": True,
                "authenticated": True,
                "crosses_trust_boundary": True
            }
        ],
        "trust_boundaries": [],
        "tech_stack_summary": ["React", "Node.js", "PostgreSQL", "JWT"],
        "parser_notes": "Standard e-commerce application"
    }

    print("\n🔍 Analyzing...\n")
    threats1, agents1, multi1 = analyze_stride(traditional_arch)
    stride_only = [t for t in threats1 if t.get("threat_source") == "STRIDE"]

    print(f"\n✅ Results:")
    print(f"   Total  : {len(threats1)}")
    print(f"   STRIDE : {len(stride_only)}")
    print(f"\n   Sample threats:")
    for t in threats1[:3]:
        print(f"   [{t['threat_category']}] {t['threat_title']}")
        print(f"         CWE: {t['cwe_id']} | {t['likelihood']} likelihood")

    # ── TEST 2: Multi-Agent DevSecOps Pipeline ────────────────────────────────
    print("\n" + "="*60)
    print("TEST 2: Multi-Agent DevSecOps Pipeline")
    print("="*60)

    agentic_arch = {
        "system_name": "Multi-Agent DevSecOps Security Pipeline",
        "components": [
            {
                "id": "comp_1",
                "name": "GitHub Repository",
                "type": "other",
                "tech_stack": ["GitHub", "Git"],
                "trust_level": "INTERNET",
                "description": "Source code repo — triggers pipeline on every PR"
            },
            {
                "id": "comp_2",
                "name": "LangGraph Orchestrator",
                "type": "AI",
                "tech_stack": ["LangGraph", "Python", "Agent Orchestrator"],
                "trust_level": "INTERNAL",
                "description": "Multi-agent supervisor managing Scanner, Triage, Fixer agents"
            },
            {
                "id": "comp_3",
                "name": "Scanner Agent",
                "type": "AI",
                "tech_stack": ["Claude", "Semgrep", "Agent", "LLM"],
                "trust_level": "INTERNAL",
                "description": "AI agent running SAST scans and interpreting findings"
            },
            {
                "id": "comp_4",
                "name": "Triage Agent",
                "type": "AI",
                "tech_stack": ["Claude", "Agent", "LLM", "CVSS"],
                "trust_level": "INTERNAL",
                "description": "AI agent scoring findings with CVSS and filtering false positives"
            },
            {
                "id": "comp_5",
                "name": "Fixer Agent",
                "type": "AI",
                "tech_stack": ["Claude Code", "Agent", "LLM", "GitHub API"],
                "trust_level": "INTERNAL",
                "description": "AI agent generating remediation PRs via GitHub API"
            },
            {
                "id": "comp_6",
                "name": "MCP Tool Server",
                "type": "other",
                "tech_stack": ["MCP", "Model Context Protocol", "Tool Server"],
                "trust_level": "INTERNAL",
                "description": "MCP server exposing Semgrep, GitHub, and AWS tools to agents"
            },
            {
                "id": "comp_7",
                "name": "PostgreSQL State DB",
                "type": "Database",
                "tech_stack": ["PostgreSQL", "LangGraph Checkpointer"],
                "trust_level": "PRIVILEGED",
                "description": "Stores agent state, memory, and pipeline execution history"
            }
        ],
        "data_flows": [
            {
                "id": "flow_1",
                "from": "comp_1",
                "to": "comp_2",
                "data_type": "PR webhook with code diff and metadata",
                "protocol": "HTTPS",
                "encrypted": True,
                "authenticated": True,
                "crosses_trust_boundary": True
            },
            {
                "id": "flow_2",
                "from": "comp_2",
                "to": "comp_3",
                "data_type": "Agent task instructions and code to scan",
                "protocol": "internal",
                "encrypted": False,
                "authenticated": False,
                "crosses_trust_boundary": False
            },
            {
                "id": "flow_3",
                "from": "comp_3",
                "to": "comp_4",
                "data_type": "Raw scan findings including code context",
                "protocol": "internal",
                "encrypted": False,
                "authenticated": False,
                "crosses_trust_boundary": False
            },
            {
                "id": "flow_4",
                "from": "comp_4",
                "to": "comp_5",
                "data_type": "Triaged findings with CVSS scores",
                "protocol": "internal",
                "encrypted": False,
                "authenticated": False,
                "crosses_trust_boundary": False
            },
            {
                "id": "flow_5",
                "from": "comp_3",
                "to": "comp_6",
                "data_type": "Tool calls to run Semgrep on repository code",
                "protocol": "MCP",
                "encrypted": False,
                "authenticated": False,
                "crosses_trust_boundary": False
            },
            {
                "id": "flow_6",
                "from": "comp_5",
                "to": "comp_1",
                "data_type": "Remediation PR with fixed code",
                "protocol": "HTTPS",
                "encrypted": True,
                "authenticated": True,
                "crosses_trust_boundary": True
            },
            {
                "id": "flow_7",
                "from": "comp_2",
                "to": "comp_7",
                "data_type": "Agent state checkpoints and execution history",
                "protocol": "SQL",
                "encrypted": True,
                "authenticated": True,
                "crosses_trust_boundary": True
            }
        ],
        "trust_boundaries": [],
        "tech_stack_summary": [
            "LangGraph", "Claude", "Claude Code",
            "Semgrep", "MCP", "GitHub", "PostgreSQL", "Python"
        ],
        "parser_notes": "Multi-agent agentic DevSecOps security pipeline"
    }

    print("\n🔍 Analyzing...\n")
    threats2, agents2, multi2 = analyze_stride(agentic_arch)

    stride_t  = [t for t in threats2 if t.get("threat_source") == "STRIDE"]
    single_t  = [t for t in threats2 if t.get("threat_source") == "SINGLE-AGENT"]
    multi_t   = [t for t in threats2 if t.get("threat_source") == "MULTI-AGENT"]

    print(f"\n✅ Results:")
    print(f"   Total        : {len(threats2)}")
    print(f"   STRIDE       : {len(stride_t)}")
    print(f"   Single-Agent : {len(single_t)}")
    print(f"   Multi-Agent  : {len(multi_t)}")

    if multi_t:
        print(f"\n   🤖 Multi-Agent Threats:")
        for t in multi_t[:4]:
            print(f"   [{t['threat_category']}] {t['threat_title']}")
            print(f"         Attack : {t['attack_scenario'][:100]}...")
            print(f"         Fix    : {t['mitigation'][:80]}...")
            print()

    if single_t:
        print(f"   🧠 Single-Agent Threats:")
        for t in single_t[:2]:
            print(f"   [{t['threat_category']}] {t['threat_title']}")
            print(f"         Fix: {t['mitigation'][:80]}...")
            print()
import anthropic
import json
import os
import re
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

ATLAS_TACTICS = """
MITRE ATLAS Tactics and Techniques:

AML.TA0001 - Reconnaissance:
  AML.T0000: ML Model Reconnaissance
  AML.T0001: Discover ML Model Ontology

AML.TA0004 - Initial Access:
  AML.T0010: ML Supply Chain Compromise
  AML.T0012: Valid Accounts

AML.TA0005 - Execution:
  AML.T0017: Exploit Public-Facing Application
  AML.T0018: Backdoor ML Model

AML.TA0006 - Persistence:
  AML.T0019: Backdoor ML Model
  AML.T0020: Poison Training Data

AML.TA0008 - Defense Evasion:
  AML.T0030: Adversarial Examples
  AML.T0031: Bypass AI Safety Guardrails

AML.TA0009 - Collection:
  AML.T0035: Mirror Model
  AML.T0037: Data from Information Repositories

AML.TA0010 - Exfiltration:
  AML.T0040: Exfiltrate via API
  AML.T0041: Model Inversion

AML.TA0040 - Impact:
  AML.T0046: Denial of ML Service
  AML.T0047: Erode ML Model Integrity
  AML.T0048: Compromise Model Predictions

AML.TA0043 - ML Attack Staging:
  AML.T0051: LLM Prompt Injection
  AML.T0052: Backdoor Model through Fine-tuning
  AML.T0054: Craft Adversarial Data
"""

AI_ML_KEYWORDS = [
    "llm", "gpt", "claude", "openai", "anthropic", "gemini", "llama",
    "ml", "model", "ai", "embedding", "vector", "rag", "chatbot",
    "tensorflow", "pytorch", "huggingface", "langchain", "agent",
    "inference", "prediction", "classifier", "nlp", "diffusion",
    "copilot", "assistant", "generative", "foundation model",
    "fine-tun", "training", "dataset", "neural", "deep learning",
    "transformer", "langgraph", "autogen", "crewai", "mcp",
    "model context protocol"
]

ATLAS_SYSTEM = f"""You are an AI/ML security expert specializing in MITRE ATLAS
adversarial threat modeling for AI and ML systems.

{ATLAS_TACTICS}

CRITICAL RULES:
- Output ONLY a valid JSON array. No markdown, no preamble, no explanation.
- Only generate threats relevant to the AI/ML components present.
- Reference real ATLAS tactic and technique IDs in every threat.
- Be specific to THIS architecture.
- Do NOT include newline characters inside any JSON string value.
- Every threat needs a concrete attack scenario and actionable mitigation.
"""

ATLAS_PROMPT = """Perform a MITRE ATLAS adversarial threat analysis on the
AI/ML components in this architecture.

Architecture:
{architecture_json}

AI/ML Components Detected: {ai_components}

Generate ATLAS threats for each AI/ML component focusing on:
1. LLM components: prompt injection (AML.T0051), model extraction, jailbreaking
2. Agent systems: tool misuse, goal hijacking, unsafe autonomous actions
3. RAG pipelines: knowledge base poisoning, retrieval manipulation
4. MCP servers: malicious tool exposure, credential theft via tool calls

Output a JSON array with EXACTLY this schema:
[
  {{
    "atlas_id": "AT001",
    "target_id": "comp_id",
    "target_name": "component name",
    "target_type": "component",
    "threat_source": "MITRE-ATLAS",
    "atlas_tactic_id": "AML.TA0001",
    "atlas_tactic_name": "tactic name",
    "atlas_technique_id": "AML.T0051",
    "atlas_technique_name": "technique name",
    "threat_title": "concise descriptive title",
    "threat_description": "detailed explanation of the AI/ML vulnerability",
    "attack_scenario": "Step 1: X. Step 2: Y. Step 3: Z impact.",
    "attacker_capability": "Script Kiddie or Researcher or Nation State or Insider",
    "prerequisites": "what attacker needs",
    "impact": "specific impact on AI system and downstream business",
    "likelihood": "High or Medium or Low",
    "detection_method": "how to detect this attack",
    "mitigation": "specific ML security control to prevent this threat",
    "atlas_url": "https://atlas.mitre.org/techniques/AML.T0051"
  }}
]"""


def detect_ai_components(architecture: dict) -> list:
    """Identify AI/ML components in the parsed architecture."""
    ai_components = []
    for comp in architecture.get("components", []):
        comp_text = (
            comp.get("name", "") + " " +
            comp.get("description", "") + " " +
            " ".join(comp.get("tech_stack", []))
        ).lower()
        if any(kw in comp_text for kw in AI_ML_KEYWORDS):
            ai_components.append({
                "id": comp.get("id"),
                "name": comp.get("name"),
                "type": comp.get("type"),
                "tech_stack": comp.get("tech_stack", []),
                "description": comp.get("description", "")
            })
    return ai_components


def fix_json(raw: str) -> str:
    """Fix truncated or malformed JSON."""
    raw = raw.strip()
    raw = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', raw)

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

    if not raw.endswith("]"):
        last_brace = raw.rfind("}")
        if last_brace != -1:
            raw = raw[:last_brace + 1] + "\n]"

    return raw


def analyze_atlas(architecture: dict) -> tuple:
    """
    Run MITRE ATLAS analysis on AI/ML components.

    Returns:
        atlas_threats (list): ATLAS threats generated
        ai_components (list): Detected AI/ML components
    """
    ai_components = detect_ai_components(architecture)

    if not ai_components:
        print(f"   No AI/ML components detected — ATLAS skipped")
        return [], []

    ai_names = [c["name"] for c in ai_components]
    print(f"   AI/ML components: {', '.join(ai_names[:4])}")
    print(f"   Running MITRE ATLAS adversarial analysis...")

    arch_json = json.dumps(architecture, indent=2)
    ai_components_str = json.dumps(
        [c["name"] for c in ai_components], indent=2
    )

    prompt = ATLAS_PROMPT.replace(
        "{architecture_json}", arch_json
    ).replace(
        "{ai_components}", ai_components_str
    )

    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=4096,
        system=ATLAS_SYSTEM,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]

    raw = fix_json(raw)

    try:
        atlas_threats = json.loads(raw.strip())
    except json.JSONDecodeError as e:
        print(f"   JSON parse error — attempting recovery: {e}")
        try:
            raw = re.sub(r'\n\s*', ' ', raw)
            atlas_threats = json.loads(raw.strip())
        except json.JSONDecodeError:
            atlas_threats = []
            pattern = re.compile(r'\{[^{}]*\}', re.DOTALL)
            for match in pattern.finditer(raw):
                try:
                    obj = json.loads(match.group())
                    if "threat_title" in obj:
                        atlas_threats.append(obj)
                except json.JSONDecodeError:
                    continue
            print(f"   Recovered {len(atlas_threats)} threats")

    for i, t in enumerate(atlas_threats):
        t["threat_source"] = "MITRE-ATLAS"
        t["atlas_id"] = f"AT{str(i+1).zfill(3)}"

    print(f"   Generated {len(atlas_threats)} ATLAS threats")

    return atlas_threats, ai_components


if __name__ == "__main__":
    print("\nTesting MITRE ATLAS...\n")

    test_arch = {
        "system_name": "AI Chatbot",
        "components": [
            {
                "id": "comp_1",
                "name": "Claude LLM Agent",
                "type": "AI",
                "tech_stack": ["Claude", "Anthropic API", "LLM", "Agent"],
                "trust_level": "INTERNAL",
                "description": "LLM agent powering chatbot responses"
            },
            {
                "id": "comp_2",
                "name": "RAG Knowledge Base",
                "type": "Database",
                "tech_stack": ["Pinecone", "Vector DB", "Embeddings", "RAG"],
                "trust_level": "INTERNAL",
                "description": "Vector database storing knowledge embeddings"
            },
            {
                "id": "comp_3",
                "name": "MCP Tool Server",
                "type": "other",
                "tech_stack": ["MCP", "Model Context Protocol"],
                "trust_level": "INTERNAL",
                "description": "MCP server exposing tools to agents"
            }
        ],
        "data_flows": [],
        "trust_boundaries": [],
        "tech_stack_summary": ["Claude", "Pinecone", "MCP"],
        "parser_notes": "Test AI architecture"
    }

    threats, comps = analyze_atlas(test_arch)
    print(f"\nResults:")
    print(f"   AI components : {len(comps)}")
    print(f"   ATLAS threats : {len(threats)}")

    for t in threats[:3]:
        print(f"\n   [{t['atlas_technique_id']}] {t['threat_title']}")
        print(f"   Tactic : {t['atlas_tactic_name']}")
        print(f"   Fix    : {t['mitigation'][:80]}...")
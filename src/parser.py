import anthropic
import base64
import json
import os
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

PARSER_SYSTEM = """You are a senior security architect specializing in threat modeling.
Your job is to analyze architecture descriptions or diagrams and extract a precise,
structured inventory of components, data flows, and trust boundaries.

CRITICAL RULES:
- Output ONLY valid JSON. No markdown, no explanation, no preamble.
- Be exhaustive — capture every component and every data flow you can identify.
- Assign trust levels: INTERNET, DMZ, INTERNAL, PRIVILEGED.
- For data flows, always specify: what data moves, what protocol, and whether encrypted.
- Do NOT include newline characters inside any JSON string value.
- Keep descriptions concise — maximum 100 characters per description field.
"""

PARSER_PROMPT = """Analyze this architecture and output JSON in EXACTLY this schema:

{
  "system_name": "inferred name of the system",
  "components": [
    {
      "id": "comp_1",
      "name": "string",
      "type": "WebApp|API|Database|Queue|Cache|AuthService|CDN|ThirdParty|User|AI|other",
      "tech_stack": ["string"],
      "trust_level": "INTERNET|DMZ|INTERNAL|PRIVILEGED",
      "description": "what this component does in under 100 characters"
    }
  ],
  "data_flows": [
    {
      "id": "flow_1",
      "from": "comp_id",
      "to": "comp_id",
      "data_type": "what data is transferred",
      "protocol": "HTTPS|HTTP|gRPC|TCP|SQL|MCP|internal|other",
      "encrypted": true,
      "authenticated": true,
      "crosses_trust_boundary": true
    }
  ],
  "trust_boundaries": [
    {
      "id": "tb_1",
      "name": "string",
      "description": "string",
      "components_inside": ["comp_id"]
    }
  ],
  "tech_stack_summary": ["all unique technologies"],
  "parser_notes": "anything ambiguous or assumed in under 200 characters"
}

Architecture to analyze:
{input}"""


def fix_json(raw: str) -> str:
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

    if not raw.endswith("}"):
        open_arrays = raw.count('[') - raw.count(']')
        for _ in range(max(0, open_arrays)):
            raw += ']'
        open_objects = raw.count('{') - raw.count('}')
        for _ in range(max(0, open_objects)):
            raw += '}'

    return raw


def parse_from_text(description: str) -> dict:
    prompt = PARSER_PROMPT.replace("{input}", description)
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=8192,
        system=PARSER_SYSTEM,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = fix_json(raw.strip())
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"   Parser JSON error — attempting recovery: {e}")
        try:
            raw = re.sub(r'\n\s*', ' ', raw)
            return json.loads(raw)
        except json.JSONDecodeError:
            print("   Parser truncated — returning partial structure")
            return {
                "system_name": "Parsed Architecture",
                "components": [],
                "data_flows": [],
                "trust_boundaries": [],
                "tech_stack_summary": [],
                "parser_notes": "Architecture too complex — truncated."
            }


def parse_from_image(image_path: str) -> dict:
    path = Path(image_path)
    ext = path.suffix.lower()
    media_types = {
        ".png":  "image/png",
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif":  "image/gif",
        ".webp": "image/webp"
    }
    media_type = media_types.get(ext, "image/png")
    with open(image_path, "rb") as f:
        image_data = base64.standard_b64encode(f.read()).decode("utf-8")
    prompt = PARSER_PROMPT.replace(
        "{input}",
        "The architecture diagram is provided as an image above. "
        "Extract all visible components, connections, labels, and annotations."
    )
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=8192,
        system=PARSER_SYSTEM,
        messages=[{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": image_data,
                    }
                },
                {"type": "text", "text": prompt}
            ]
        }]
    )
    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = fix_json(raw.strip())
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        print("   Image parser truncated — returning partial structure")
        return {
            "system_name": "Parsed Architecture",
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
            "tech_stack_summary": [],
            "parser_notes": "Image too complex — truncated."
        }


if __name__ == "__main__":
    print("\nTesting parser...\n")
    test_arch = """
    A React SPA talks to a Node.js REST API over HTTPS.
    The API authenticates users via JWT and reads from PostgreSQL.
    Redis is used for session caching. Runs on AWS behind an ALB.
    """
    result = parse_from_text(test_arch)
    print(f"System    : {result.get('system_name')}")
    print(f"Components: {len(result.get('components', []))}")
    print(f"Data flows: {len(result.get('data_flows', []))}")

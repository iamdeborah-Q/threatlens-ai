"""ThreatLens AI Pipeline"""
from src.parser import parse_from_text, parse_from_image
from src.stride import analyze_stride
from src.atlas import analyze_atlas
from src.scorer import score_threats, get_severity_summary
from src.reporter import generate_report


def run(description=None, image_path=None):
    print("\n" + "="*60)
    print("   ThreatLens AI - Full Pipeline")
    print("="*60)

    print("\n Step 1/5 - Parsing architecture...")
    if image_path:
        architecture = parse_from_image(image_path)
    else:
        architecture = parse_from_text(description)
    print(f"   OK System    : {architecture.get('system_name')}")
    print(f"   OK Components: {len(architecture.get('components', []))}")
    print(f"   OK Data flows: {len(architecture.get('data_flows', []))}")

    print("\n Step 2/5 - Running STRIDE + Agentic analysis...")
    threats, agent_components, multi_agent = analyze_stride(architecture)
    stride_t = [t for t in threats if t.get("threat_source") == "STRIDE"]
    single_t = [t for t in threats if t.get("threat_source") == "SINGLE-AGENT"]
    multi_t  = [t for t in threats if t.get("threat_source") == "MULTI-AGENT"]
    print(f"   OK Total     : {len(threats)}")
    print(f"   STRIDE       : {len(stride_t)}")
    print(f"   Single-Agent : {len(single_t)}")
    print(f"   Multi-Agent  : {len(multi_t)}")

    print("\n Step 3/5 - Running MITRE ATLAS analysis...")
    atlas_threats, ai_components = analyze_atlas(architecture)
    if atlas_threats:
        print(f"   OK ATLAS threats: {len(atlas_threats)}")
        threats.extend(atlas_threats)
    else:
        print("   No AI/ML components - ATLAS skipped")
    print(f"   OK Total after ATLAS: {len(threats)}")

    print("\n Step 4/5 - Scoring all threats (CVSS 3.1)...")
    scored = score_threats(threats)
    summary = get_severity_summary(scored)
    print(f"   Critical : {summary['Critical']}")
    print(f"   High     : {summary['High']}")
    print(f"   Medium   : {summary['Medium']}")
    print(f"   Low      : {summary['Low']}")

    print("\n Step 5/5 - Generating report...")
    report_path, report_content = generate_report(
        architecture, scored, summary
    )
    print(f"   OK Report saved -> {report_path}")

    print("\n" + "="*60)
    print("   Pipeline Complete!")
    print("="*60)
    print(f"\n   System       : {architecture.get('system_name')}")
    print(f"   Total threats: {len(scored)}")
    print(f"   STRIDE       : {len([t for t in scored if t.get('threat_source') == 'STRIDE'])}")
    print(f"   Single-Agent : {len([t for t in scored if t.get('threat_source') == 'SINGLE-AGENT'])}")
    print(f"   Multi-Agent  : {len([t for t in scored if t.get('threat_source') == 'MULTI-AGENT'])}")
    print(f"   MITRE ATLAS  : {len([t for t in scored if t.get('threat_source') == 'MITRE-ATLAS'])}")
    print(f"   Report       : {report_path}")

    print("\n Top 5 Priority Threats:")
    for t in scored[:5]:
        sev      = t.get("cvss_severity", "?")
        score    = t.get("cvss_base_score", "?")
        title    = t.get("threat_title", "Unknown")
        source   = t.get("threat_source", "?")
        category = t.get("threat_category", t.get("atlas_technique_id", "?"))
        print(f"   [{sev:12}] CVSS {score} | [{source}][{category}]")
        print(f"               {title[:55]}...")

    return {
        "architecture": architecture,
        "threats": scored,
        "severity_summary": summary,
        "report_path": report_path,
        "report_content": report_content
    }


if __name__ == "__main__":
    architecture_input = """
    A healthcare patient portal for viewing lab results and booking appointments.
    Components:
    - React frontend on AWS CloudFront CDN
    - Python FastAPI backend on EC2 behind Application Load Balancer
    - PostgreSQL RDS storing PHI patient health information
    - Redis ElastiCache for session token storage
    - Auth0 for patient authentication using OAuth 2.0 and OIDC
    - Twilio for SMS appointment reminders with patient name and time
    - Vue.js admin panel for clinic staff with elevated permissions
    - S3 bucket storing PDF lab reports with pre-signed URLs 1 hour expiry
    - LangGraph multi-agent AI assistant answering patient questions
    - Scanner Agent using Claude to analyze patient symptoms
    - Fixer Agent using Claude Code to update patient records via API
    - MCP server exposing patient database tools to agents
    No input sanitization on patient messages before sent to Claude agents.
    JWT tokens RS256 signed. Staff tokens have elevated privileges.
    """
    result = run(description=architecture_input)
    print(f"\n Open report: {result['report_path']}")

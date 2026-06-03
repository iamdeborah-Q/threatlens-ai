import streamlit as st
from src.parser import parse_from_text, parse_from_image
from src.stride import analyze_stride
from src.atlas import analyze_atlas
from src.scorer import score_threats, get_severity_summary
from src.reporter import generate_report
import tempfile
from pathlib import Path

st.set_page_config(
    page_title="ThreatLens AI",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
* { font-family: 'Inter', sans-serif; }
.stApp { background: #07070F; color: #E0E0F0; }

.hero {
    background: #0D0D2B;
    border: 1px solid #2a2a5a;
    border-radius: 16px;
    padding: 36px;
    text-align: center;
    margin-bottom: 28px;
}
.hero-title {
    font-size: 2.6rem;
    font-weight: 700;
    color: #60A5FA;
    margin: 0 0 6px;
}
.hero-subtitle {
    color: #9CA3AF;
    font-size: 0.95rem;
    margin: 0 0 16px;
}
.badge-row {
    display: flex;
    gap: 8px;
    justify-content: center;
    flex-wrap: wrap;
}
.badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.badge-blue   { background:#1E3A5F; color:#60A5FA; border:1px solid #2563EB44; }
.badge-purple { background:#2D1B69; color:#A78BFA; border:1px solid #7C3AED44; }
.badge-green  { background:#064E3B; color:#34D399; border:1px solid #10B98144; }
.badge-orange { background:#431407; color:#FB923C; border:1px solid #EA580C44; }

.metric-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
    margin-bottom: 20px;
}
.metric-card {
    background: #0D0D1A;
    border-radius: 10px;
    padding: 14px;
    text-align: center;
    border: 1px solid #1a1a2e;
}
.metric-value { font-size: 1.9rem; font-weight: 700; line-height: 1; margin-bottom: 4px; }
.metric-label { font-size: 10px; color: #6B7280; text-transform: uppercase; letter-spacing: 0.08em; }
.critical-card { border-color:#EF444433; }
.critical-card .metric-value { color:#EF4444; }
.high-card     { border-color:#F9731633; }
.high-card     .metric-value { color:#F97316; }
.medium-card   { border-color:#EAB30833; }
.medium-card   .metric-value { color:#EAB308; }
.low-card      { border-color:#22C55E33; }
.low-card      .metric-value { color:#22C55E; }
.total-card    { border-color:#3B82F633; }
.total-card    .metric-value { color:#3B82F6; }

.fw-row { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:20px; }
.fw-badge { padding:5px 14px; border-radius:20px; font-size:11px; font-weight:600; }
.fw-stride  { background:#1E3A5F22; color:#60A5FA; border:1px solid #3B82F644; }
.fw-single  { background:#2D1B6922; color:#A78BFA; border:1px solid #7C3AED44; }
.fw-multi   { background:#06402022; color:#34D399; border:1px solid #10B98144; }
.fw-atlas   { background:#43140722; color:#FB923C; border:1px solid #EA580C44; }

.threat-card {
    background: #0D0D1A;
    border: 1px solid #1a1a2e;
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 10px;
    transition: border-color 0.2s, transform 0.2s;
}
.threat-card:hover { border-color:#2a2a4e; transform:translateX(3px); }
.threat-header { display:flex; align-items:flex-start; gap:10px; margin-bottom:10px; }
.sev-dot {
    width: 9px; height: 9px; border-radius: 50%;
    margin-top: 5px; flex-shrink: 0;
}
.dot-critical { background:#EF4444; box-shadow:0 0 7px #EF444466; }
.dot-high     { background:#F97316; box-shadow:0 0 7px #F9731666; }
.dot-medium   { background:#EAB308; box-shadow:0 0 7px #EAB30866; }
.dot-low      { background:#22C55E; box-shadow:0 0 7px #22C55E66; }

.threat-title { font-size:13px; font-weight:600; color:#E5E7EB; flex:1; }
.tag-row { display:flex; gap:5px; flex-wrap:wrap; margin-top:4px; }
.tag {
    font-size: 9px; padding: 2px 7px; border-radius: 10px;
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
}
.tag-critical { background:#EF444422; color:#FCA5A5; border:1px solid #EF444433; }
.tag-high     { background:#F9731622; color:#FDBA74; border:1px solid #F9731633; }
.tag-medium   { background:#EAB30822; color:#FDE047; border:1px solid #EAB30833; }
.tag-low      { background:#22C55E22; color:#86EFAC; border:1px solid #22C55E33; }
.tag-stride   { background:#3B82F622; color:#93C5FD; border:1px solid #3B82F633; }
.tag-single   { background:#7C3AED22; color:#C4B5FD; border:1px solid #7C3AED33; }
.tag-multi    { background:#10B98122; color:#6EE7B7; border:1px solid #10B98133; }
.tag-atlas    { background:#EA580C22; color:#FDBA74; border:1px solid #EA580C33; }
.tag-gray     { background:#1F2937; color:#9CA3AF; border:1px solid #374151; }

.t-section { margin-top:10px; padding-top:10px; border-top:1px solid #1a1a2e; }
.t-label {
    font-size: 9px; color: #6B7280; text-transform: uppercase;
    letter-spacing: 0.1em; font-weight: 700; margin-bottom: 3px;
}
.t-text { font-size:12px; color:#9CA3AF; line-height:1.6; }

.attack-box {
    background:#43140722; border:1px solid #EA580C33;
    border-radius:8px; padding:10px; margin-top:8px;
}
.attack-label {
    font-size:9px; color:#FB923C; text-transform:uppercase;
    letter-spacing:0.1em; font-weight:700; margin-bottom:3px;
}
.attack-text { font-size:12px; color:#FED7AA; line-height:1.6; }

.mitig-box {
    background:#064E3B22; border:1px solid #10B98133;
    border-radius:8px; padding:10px; margin-top:8px;
}
.mitig-label {
    font-size:9px; color:#34D399; text-transform:uppercase;
    letter-spacing:0.1em; font-weight:700; margin-bottom:3px;
}
.mitig-text { font-size:12px; color:#6EE7B7; line-height:1.6; }

.road-section {
    border-radius:10px; padding:14px; margin-bottom:10px;
}
.road-critical { background:#EF444411; border:1px solid #EF444433; }
.road-high     { background:#F9731611; border:1px solid #F9731633; }
.road-medium   { background:#EAB30811; border:1px solid #EAB30833; }
.road-low      { background:#22C55E11; border:1px solid #22C55E33; }
.road-title { font-size:12px; font-weight:700; margin-bottom:8px; }
.road-item {
    display:flex; gap:8px; padding:5px 0;
    font-size:11px; border-top:1px solid;
}
.road-critical .road-title { color:#EF4444; }
.road-critical .road-item  { border-color:#EF444422; }
.road-critical .road-id    { color:#EF4444; font-weight:700; flex-shrink:0; }
.road-critical .road-name  { color:#FCA5A5; }
.road-high    .road-title  { color:#F97316; }
.road-high    .road-item   { border-color:#F9731622; }
.road-high    .road-id     { color:#F97316; font-weight:700; flex-shrink:0; }
.road-high    .road-name   { color:#FDBA74; }
.road-medium  .road-title  { color:#EAB308; }
.road-medium  .road-item   { border-color:#EAB30822; }
.road-medium  .road-id     { color:#EAB308; font-weight:700; flex-shrink:0; }
.road-medium  .road-name   { color:#FDE047; }
.road-low     .road-title  { color:#22C55E; }
.road-low     .road-item   { border-color:#22C55E22; }
.road-low     .road-id     { color:#22C55E; font-weight:700; flex-shrink:0; }
.road-low     .road-name   { color:#86EFAC; }

.input-card {
    background:#0D0D1A; border:1px solid #1a1a2e;
    border-radius:16px; padding:22px;
}
.sec-title {
    font-size:16px; font-weight:600; color:#E5E7EB; margin-bottom:14px;
}
.tip-text {
    text-align:center; color:#4B5563;
    font-size:11px; margin-top:10px;
}

.stTextArea textarea {
    background:#111128 !important;
    border:1px solid #2a2a4e !important;
    border-radius:10px !important;
    color:#E5E7EB !important;
    font-size:13px !important;
}
div[data-testid="stButton"] button {
    background: #1D4ED8 !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    transition: all 0.2s !important;
}
div[data-testid="stButton"] button:hover {
    background: #2563EB !important;
    transform: translateY(-2px) !important;
}
.stTabs [data-baseweb="tab-list"] {
    background:#0D0D1A !important;
    border-radius:10px !important;
    padding:3px !important;
    gap:3px !important;
}
.stTabs [data-baseweb="tab"] {
    background:transparent !important;
    border-radius:8px !important;
    color:#6B7280 !important;
    font-weight:500 !important;
}
.stTabs [aria-selected="true"] {
    background:#1a1a3e !important;
    color:#60A5FA !important;
}
.stProgress > div > div {
    background: #3B82F6 !important;
    border-radius: 4px !important;
}
hr { border-color:#1a1a2e !important; }
</style>
""", unsafe_allow_html=True)


def sev_dot(sev):
    s = (sev or "low").lower()
    return f'<div class="sev-dot dot-{s}"></div>'


def sev_tag(sev):
    s = (sev or "low").lower()
    return f'<span class="tag tag-{s}">{sev}</span>'


def src_tag(src):
    m = {
        "STRIDE": "stride",
        "SINGLE-AGENT": "single",
        "MULTI-AGENT": "multi",
        "MITRE-ATLAS": "atlas"
    }
    k = m.get(src, "gray")
    return f'<span class="tag tag-{k}">{src}</span>'


def threat_card(t):
    sev      = t.get("cvss_severity", "Low")
    score    = t.get("cvss_base_score", "?")
    title    = t.get("threat_title", "Unknown threat")
    source   = t.get("threat_source", "STRIDE")
    cat      = t.get("threat_category", t.get("atlas_technique_id", "?"))
    desc     = t.get("threat_description", "")
    attack   = t.get("attack_scenario", "")
    mitig    = t.get("mitigation", "")
    impact   = t.get("impact", "")
    cwe      = t.get("cwe_id", "N/A")
    timeline = t.get("remediation_timeline", "")
    tid      = t.get("threat_id", "")

    timeline_html = ""
    if timeline:
        timeline_html = f"""
        <div class="t-section">
          <div class="t-label">Remediation Timeline</div>
          <div class="t-text">{timeline}</div>
        </div>"""

    return f"""
<div class="threat-card">
  <div class="threat-header">
    {sev_dot(sev)}
    <div style="flex:1">
      <div class="threat-title">{tid} — {title}</div>
      <div class="tag-row">
        {sev_tag(sev)}
        {src_tag(source)}
        <span class="tag tag-gray">CVSS {score}</span>
        <span class="tag tag-gray">{cat}</span>
        <span class="tag tag-gray">{cwe}</span>
      </div>
    </div>
  </div>
  <div class="t-section">
    <div class="t-label">Description</div>
    <div class="t-text">{desc}</div>
  </div>
  <div class="attack-box">
    <div class="attack-label">Attack Scenario</div>
    <div class="attack-text">{attack}</div>
  </div>
  <div class="t-section">
    <div class="t-label">Impact</div>
    <div class="t-text">{impact}</div>
  </div>
  <div class="mitig-box">
    <div class="mitig-label">Mitigation</div>
    <div class="mitig-text">{mitig}</div>
  </div>
  {timeline_html}
</div>"""


def road_section(threats, sev, color_class, label):
    items = [t for t in threats if t.get("cvss_severity") == sev]
    if not items:
        return ""
    rows = "".join(
        f'<div class="road-item">'
        f'<span class="road-id">{t.get("threat_id","")}</span>'
        f'<span class="road-name">{t.get("threat_title","")}</span>'
        f'</div>'
        for t in items
    )
    return f"""
<div class="road-section road-{color_class}">
  <div class="road-title">{label}</div>
  {rows}
</div>"""


# ── Hero ──────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
  <div class="hero-title">🛡 ThreatLens AI</div>
  <div class="hero-subtitle">
    AI-Powered Threat Modeling · STRIDE · Single &amp; Multi-Agent · MITRE ATLAS · CVSS 3.1
  </div>
  <div class="badge-row">
    <span class="badge badge-blue">Powered by Claude</span>
    <span class="badge badge-purple">Agentic AI Threats</span>
    <span class="badge badge-green">MITRE ATLAS</span>
    <span class="badge badge-orange">CVSS 3.1 Scoring</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_input, tab_results, tab_report = st.tabs([
    "📋  Input Architecture",
    "📊  Threat Analysis",
    "📄  Report"
])

# ── Input Tab ─────────────────────────────────────────────────────────────────
with tab_input:
    st.markdown('<div class="input-card">', unsafe_allow_html=True)
    st.markdown('<div class="sec-title">🏗 Describe Your Architecture</div>',
                unsafe_allow_html=True)

    input_mode = st.radio(
        "Input type",
        ["📝 Text Description", "🖼 Architecture Diagram (Image)"],
        horizontal=True,
        label_visibility="collapsed"
    )

    arch_text  = None
    image_path = None

    if "Text" in input_mode:
        arch_text = st.text_area(
            "Architecture",
            height=260,
            placeholder="""Describe your system. Example:

A healthcare patient portal for viewing lab results.
Components:
- React frontend on AWS CloudFront
- Python FastAPI backend behind ALB
- PostgreSQL RDS storing PHI data
- Auth0 for OAuth 2.0 authentication
- LangGraph multi-agent AI assistant
- Scanner Agent using Claude to analyze symptoms
- MCP server exposing database tools to agents

Include tech stack, auth method, cloud platform,
and any AI/agent components for best results.""",
            label_visibility="collapsed"
        )
    else:
        uploaded = st.file_uploader(
            "Upload diagram",
            type=["png", "jpg", "jpeg", "webp"],
            label_visibility="collapsed"
        )
        if uploaded:
            st.image(uploaded, caption="Architecture diagram",
                     use_column_width=True)
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=Path(uploaded.name).suffix
            ) as tmp:
                tmp.write(uploaded.read())
                image_path = tmp.name

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        run_btn = st.button(
            "🔍  Analyze Threats",
            use_container_width=True,
            disabled=not (arch_text or image_path)
        )

    st.markdown(
        '<p class="tip-text">Tip: More detail = more accurate threats. '
        'Include tech stack, auth method, data sensitivity, '
        'cloud provider, and any AI/agent components.</p>',
        unsafe_allow_html=True
    )

# ── Pipeline ──────────────────────────────────────────────────────────────────
if run_btn:
    st.session_state.results = None

    with tab_results:
        progress = st.progress(0)
        status   = st.empty()

        try:
            status.info("🔍 Step 1/5 — Parsing architecture...")
            progress.progress(10)
            if image_path:
                architecture = parse_from_image(image_path)
            else:
                architecture = parse_from_text(arch_text)
            progress.progress(20)

            status.info("⚡ Step 2/5 — Running STRIDE + Agentic analysis...")
            progress.progress(25)
            threats, agent_components, multi_agent = analyze_stride(architecture)
            progress.progress(50)

            status.info("🎯 Step 3/5 — Running MITRE ATLAS analysis...")
            progress.progress(55)
            atlas_threats, ai_components = analyze_atlas(architecture)
            if atlas_threats:
                threats.extend(atlas_threats)
            progress.progress(65)

            status.info("📊 Step 4/5 — Scoring all threats (CVSS 3.1)...")
            progress.progress(70)
            scored  = score_threats(threats)
            summary = get_severity_summary(scored)
            progress.progress(85)

            status.info("📄 Step 5/5 — Generating report...")
            report_path, report_content = generate_report(
                architecture, scored, summary
            )
            progress.progress(100)
            status.success("✅ Analysis complete!")

            st.session_state.results = {
                "architecture":   architecture,
                "threats":        scored,
                "summary":        summary,
                "report_content": report_content
            }

        except Exception as e:
            status.error(f"❌ Error: {str(e)}")
            st.exception(e)

# ── Results Tab ───────────────────────────────────────────────────────────────
with tab_results:
    if "results" in st.session_state and st.session_state.results:
        r       = st.session_state.results
        summary = r["summary"]
        threats = r["threats"]
        arch    = r["architecture"]

        st.markdown(
            f'<h2 style="font-size:20px;font-weight:700;color:#E5E7EB;margin:0 0 18px;">'
            f'🎯 {arch.get("system_name","System")} — {len(threats)} Threats Found</h2>',
            unsafe_allow_html=True
        )

        st.markdown(f"""
<div class="metric-grid">
  <div class="metric-card critical-card">
    <div class="metric-value">{summary['Critical']}</div>
    <div class="metric-label">Critical</div>
  </div>
  <div class="metric-card high-card">
    <div class="metric-value">{summary['High']}</div>
    <div class="metric-label">High</div>
  </div>
  <div class="metric-card medium-card">
    <div class="metric-value">{summary['Medium']}</div>
    <div class="metric-label">Medium</div>
  </div>
  <div class="metric-card low-card">
    <div class="metric-value">{summary['Low']}</div>
    <div class="metric-label">Low</div>
  </div>
  <div class="metric-card total-card">
    <div class="metric-value">{len(threats)}</div>
    <div class="metric-label">Total</div>
  </div>
</div>
""", unsafe_allow_html=True)

        stride_c = len([t for t in threats if t.get("threat_source") == "STRIDE"])
        single_c = len([t for t in threats if t.get("threat_source") == "SINGLE-AGENT"])
        multi_c  = len([t for t in threats if t.get("threat_source") == "MULTI-AGENT"])
        atlas_c  = len([t for t in threats if t.get("threat_source") == "MITRE-ATLAS"])

        st.markdown(f"""
<div class="fw-row">
  <span class="fw-badge fw-stride">📋 STRIDE: {stride_c}</span>
  <span class="fw-badge fw-single">🧠 Single-Agent: {single_c}</span>
  <span class="fw-badge fw-multi">🤖 Multi-Agent: {multi_c}</span>
  <span class="fw-badge fw-atlas">🎯 MITRE ATLAS: {atlas_c}</span>
</div>
""", unsafe_allow_html=True)

        st.markdown('<hr>', unsafe_allow_html=True)

        col_f1, col_f2 = st.columns(2)
        with col_f1:
            sev_filter = st.multiselect(
                "Filter by severity",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        with col_f2:
            src_filter = st.multiselect(
                "Filter by framework",
                ["STRIDE", "SINGLE-AGENT", "MULTI-AGENT", "MITRE-ATLAS"],
                default=["STRIDE", "SINGLE-AGENT", "MULTI-AGENT", "MITRE-ATLAS"]
            )

        filtered = [
            t for t in threats
            if t.get("cvss_severity") in sev_filter
            and t.get("threat_source") in src_filter
        ]

        st.markdown(
            f'<p style="color:#6B7280;font-size:12px;margin-bottom:14px;">'
            f'Showing {len(filtered)} of {len(threats)} threats</p>',
            unsafe_allow_html=True
        )

        for t in filtered:
            st.markdown(threat_card(t), unsafe_allow_html=True)

# ── Report Tab ────────────────────────────────────────────────────────────────
with tab_report:
    if "results" in st.session_state and st.session_state.results:
        r            = st.session_state.results
        report_md    = r["report_content"]
        arch_name    = r["architecture"].get("system_name", "report")
        summary      = r["summary"]
        threats      = r["threats"]

        st.markdown(
            f'<h2 style="font-size:20px;font-weight:700;color:#E5E7EB;margin:0 0 18px;">'
            f'📄 {arch_name} — Threat Model Report</h2>',
            unsafe_allow_html=True
        )

        st.markdown(f"""
<div class="metric-grid">
  <div class="metric-card critical-card">
    <div class="metric-value">{summary['Critical']}</div>
    <div class="metric-label">Critical</div>
  </div>
  <div class="metric-card high-card">
    <div class="metric-value">{summary['High']}</div>
    <div class="metric-label">High</div>
  </div>
  <div class="metric-card medium-card">
    <div class="metric-value">{summary['Medium']}</div>
    <div class="metric-label">Medium</div>
  </div>
  <div class="metric-card low-card">
    <div class="metric-value">{summary['Low']}</div>
    <div class="metric-label">Low</div>
  </div>
  <div class="metric-card total-card">
    <div class="metric-value">{len(threats)}</div>
    <div class="metric-label">Total</div>
  </div>
</div>
""", unsafe_allow_html=True)

        st.markdown(
            road_section(threats, "Critical", "critical",
                         "🔴 Immediate Action — Critical (within 24 hours)"),
            unsafe_allow_html=True
        )
        st.markdown(
            road_section(threats, "High", "high",
                         "🟠 Short-term — High (within 1 week)"),
            unsafe_allow_html=True
        )
        st.markdown(
            road_section(threats, "Medium", "medium",
                         "🟡 Medium-term — Medium (within 1 month)"),
            unsafe_allow_html=True
        )
        st.markdown(
            road_section(threats, "Low", "low",
                         "🟢 Long-term — Low (this quarter)"),
            unsafe_allow_html=True
        )

        st.markdown("<br>", unsafe_allow_html=True)

        st.download_button(
            label="⬇️  Download Full Threat Model Report",
            data=report_md,
            file_name=f"threatlens_{arch_name.lower().replace(' ','_')}.md",
            mime="text/markdown",
            use_container_width=True
        )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(report_md)

    else:
        st.markdown("""
<div style="text-align:center; padding:60px 0; color:#4B5563;">
  <div style="font-size:44px; margin-bottom:14px;">📄</div>
  <div style="font-size:15px; font-weight:500; color:#6B7280;">
    Run analysis to generate your report
  </div>
  <div style="font-size:12px; margin-top:8px; color:#4B5563;">
    Your threat model report will appear here after analysis
  </div>
</div>
""", unsafe_allow_html=True)
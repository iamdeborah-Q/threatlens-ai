import streamlit as st
from src.parser import parse_from_text, parse_from_image
from src.stride import analyze_stride
from src.atlas import analyze_atlas
from src.scorer import score_threats, get_severity_summary
from src.reporter import generate_report
import tempfile
from pathlib import Path

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatLens AI",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background: #07070F; color: #DDD; }
    .metric-card {
        background: #0D0D1A;
        border: 1px solid #1a1a2e;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## 🛡 ThreatLens AI")
st.caption(
    "Automated Threat Modeling · "
    "STRIDE + Single/Multi-Agent + MITRE ATLAS + CVSS 3.1 · "
    "Powered by Claude"
)
st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_input, tab_results, tab_report = st.tabs([
    "📋 Input Architecture",
    "📊 Threat Analysis",
    "📄 Report"
])

# ── Input Tab ─────────────────────────────────────────────────────────────────
with tab_input:
    st.subheader("Describe Your Architecture")

    input_mode = st.radio(
        "Input type:",
        ["Text Description", "Architecture Diagram (Image)"],
        horizontal=True
    )

    arch_text = None
    image_path = None

    if input_mode == "Text Description":
        arch_text = st.text_area(
            "Architecture Description",
            height=300,
            placeholder="""Example:
A React SPA connects to a Node.js REST API over HTTPS.
The API uses JWT authentication and reads/writes to PostgreSQL.
An admin dashboard with elevated privileges connects to the same API.
Redis handles session caching. Deployed on AWS behind an ALB.
SendGrid handles transactional email.

For AI systems add:
- LangGraph orchestrator managing Scanner and Fixer agents
- Scanner Agent using Claude for analysis
- MCP server exposing tools to agents""",
            help="Be specific: list components, technologies, data flows, and who has access to what."
        )

    else:
        uploaded = st.file_uploader(
            "Upload architecture diagram",
            type=["png", "jpg", "jpeg", "webp"],
            help="PNG or JPG of your architecture diagram."
        )
        if uploaded:
            st.image(uploaded, caption="Uploaded diagram", use_column_width=True)
            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=Path(uploaded.name).suffix
            ) as tmp:
                tmp.write(uploaded.read())
                image_path = tmp.name

    st.divider()

    col1, col2 = st.columns([3, 1])
    with col1:
        st.caption(
            "Tip: More detail = more accurate threats. "
            "Include tech stack, auth method, data sensitivity, and trust boundaries."
        )
    with col2:
        run_btn = st.button(
            "🔍 Analyze Threats",
            type="primary",
            use_container_width=True,
            disabled=not (arch_text or image_path)
        )

# ── Run Pipeline ──────────────────────────────────────────────────────────────
if run_btn:
    st.session_state.results = None

    with tab_results:
        progress = st.progress(0, text="Starting analysis...")
        status = st.empty()

        try:
            # Step 1: Parse
            status.info("🔍 **Step 1/5** — Parsing architecture...")
            progress.progress(10)
            if image_path:
                architecture = parse_from_image(image_path)
            else:
                architecture = parse_from_text(arch_text)
            progress.progress(20)
            status.success(
                f"✓ Parsed: **{len(architecture['components'])} components**, "
                f"**{len(architecture['data_flows'])} data flows**"
            )

            # Step 2: STRIDE
            status.info("⚡ **Step 2/5** — Running STRIDE + Agentic analysis...")
            progress.progress(25)
            threats, agent_components, multi_agent = analyze_stride(architecture)
            stride_t = [t for t in threats if t.get("threat_source") == "STRIDE"]
            single_t = [t for t in threats if t.get("threat_source") == "SINGLE-AGENT"]
            multi_t  = [t for t in threats if t.get("threat_source") == "MULTI-AGENT"]
            progress.progress(45)
            status.success(
                f"✓ Threats: STRIDE={len(stride_t)} | "
                f"Single-Agent={len(single_t)} | "
                f"Multi-Agent={len(multi_t)}"
            )

            # Step 3: ATLAS
            status.info("🎯 **Step 3/5** — Running MITRE ATLAS analysis...")
            progress.progress(50)
            atlas_threats, ai_components = analyze_atlas(architecture)
            if atlas_threats:
                threats.extend(atlas_threats)
            progress.progress(60)
            if atlas_threats:
                status.success(f"✓ ATLAS: {len(atlas_threats)} adversarial threats")
            else:
                status.info("ℹ️ No AI/ML components — ATLAS skipped")

            # Step 4: Score
            status.info("📊 **Step 4/5** — Scoring threats (CVSS 3.1)...")
            progress.progress(65)
            scored = score_threats(threats)
            summary = get_severity_summary(scored)
            progress.progress(85)
            status.success(
                f"✓ Scored: Critical={summary['Critical']} | "
                f"High={summary['High']} | "
                f"Medium={summary['Medium']} | "
                f"Low={summary['Low']}"
            )

            # Step 5: Report
            status.info("📄 **Step 5/5** — Generating report...")
            report_path, report_content = generate_report(
                architecture, scored, summary
            )
            progress.progress(100)
            status.success("✅ Analysis complete!")

            st.session_state.results = {
                "architecture": architecture,
                "threats": scored,
                "summary": summary,
                "report_content": report_content
            }

        except Exception as e:
            status.error(f"❌ Pipeline error: {str(e)}")
            st.exception(e)

# ── Results Tab ───────────────────────────────────────────────────────────────
with tab_results:
    if "results" in st.session_state and st.session_state.results:
        r = st.session_state.results
        summary = r["summary"]
        threats = r["threats"]
        arch = r["architecture"]

        # Header
        st.subheader(
            f"🎯 {arch['system_name']} — {len(threats)} Threats Found"
        )

        # Severity metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("🔴 Critical", summary["Critical"])
        col2.metric("🟠 High",     summary["High"])
        col3.metric("🟡 Medium",   summary["Medium"])
        col4.metric("🟢 Low",      summary["Low"])
        col5.metric("Total",       len(threats))

        # Framework breakdown
        stride_t = [t for t in threats if t.get("threat_source") == "STRIDE"]
        single_t = [t for t in threats if t.get("threat_source") == "SINGLE-AGENT"]
        multi_t  = [t for t in threats if t.get("threat_source") == "MULTI-AGENT"]
        atlas_t  = [t for t in threats if t.get("threat_source") == "MITRE-ATLAS"]

        st.caption(
            f"📋 STRIDE: {len(stride_t)} | "
            f"🧠 Single-Agent: {len(single_t)} | "
            f"🤖 Multi-Agent: {len(multi_t)} | "
            f"🎯 MITRE ATLAS: {len(atlas_t)}"
        )

        st.divider()

        # Filters
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            sev_filter = st.multiselect(
                "Filter by severity:",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        with col_f2:
            source_filter = st.multiselect(
                "Filter by framework:",
                ["STRIDE", "SINGLE-AGENT", "MULTI-AGENT", "MITRE-ATLAS"],
                default=["STRIDE", "SINGLE-AGENT", "MULTI-AGENT", "MITRE-ATLAS"]
            )

        filtered = [
            t for t in threats
            if t.get("cvss_severity") in sev_filter
            and t.get("threat_source") in source_filter
        ]

        st.caption(f"Showing {len(filtered)} of {len(threats)} threats")
        st.divider()

        # Threat cards
        icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }

        for t in filtered:
            sev  = t.get("cvss_severity", "Low")
            icon = icons.get(sev, "⚪")
            src  = t.get("threat_source", "?")
            cat  = t.get(
                "threat_category",
                t.get("atlas_technique_id", "?")
            )

            with st.expander(
                f"{icon} **{t.get('threat_id','?')}** — "
                f"{t.get('threat_title','Unknown')} | "
                f"{t.get('target_name','?')} | "
                f"CVSS {t.get('cvss_base_score','?')} | "
                f"[{src}][{cat}]"
            ):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Framework:** {src}")
                    st.markdown(f"**Category:** {cat}")
                    st.markdown(
                        f"**CWE:** {t.get('cwe_id','N/A')} — "
                        f"{t.get('cwe_name','N/A')}"
                    )
                    st.markdown(
                        f"**OWASP:** {t.get('owasp_category','N/A')}"
                    )
                    if t.get("atlas_technique_id"):
                        st.markdown(
                            f"**ATLAS:** [{t['atlas_technique_id']}]"
                            f"(https://atlas.mitre.org/techniques/"
                            f"{t['atlas_technique_id']})"
                        )
                with c2:
                    st.markdown(
                        f"**CVSS Vector:** `{t.get('cvss_vector','N/A')}`"
                    )
                    st.markdown(
                        f"**Likelihood:** {t.get('likelihood','?')}"
                    )
                    st.markdown(
                        f"**Effort:** {t.get('remediation_effort','?')}"
                    )
                    st.markdown(
                        f"**Timeline:** "
                        f"{t.get('remediation_timeline','?')}"
                    )

                st.markdown("**Description**")
                st.info(t.get("threat_description", ""))

                st.markdown("**Attack Scenario**")
                st.warning(t.get("attack_scenario", ""))

                st.markdown("**Impact**")
                st.error(t.get("impact", ""))

                st.markdown("**Mitigation**")
                st.success(t.get("mitigation", ""))

# ── Report Tab ────────────────────────────────────────────────────────────────
with tab_report:
    if "results" in st.session_state and st.session_state.results:
        report_md = st.session_state.results["report_content"]
        arch_name = st.session_state.results["architecture"].get(
            "system_name", "report"
        )

        st.download_button(
            label="⬇️ Download Markdown Report",
            data=report_md,
            file_name=f"threat_model_{arch_name.lower().replace(' ','_')}.md",
            mime="text/markdown",
            type="primary"
        )

        st.divider()
        st.markdown(report_md)

    else:
        st.info(
            "Run the analysis in the Input tab to generate a report."
        )
        
        
# ThreatLens AI

AI-powered threat modeling tool that automatically generates STRIDE, Single-Agent, Multi-Agent, and MITRE ATLAS threat models with CVSS 3.1 scoring from architecture descriptions or diagram images.

## Live Demo
https://threatlens-ai-62t6l9bh6picz9dq4scqrb.streamlit.app

## What it does
- Accepts architecture description (text) or diagram (image)
- Runs Claude through a 5-stage pipeline: Parse → STRIDE → ATLAS → Score → Report
- Outputs prioritized threat register with CWE mappings and remediation roadmap
- Covers traditional app threats, single-agent AI, multi-agent AI, and MITRE ATLAS

## Tech Stack
Python · Anthropic Claude · Streamlit · Jinja2

## Run locally
pip install anthropic streamlit jinja2 python-dotenv Pillow
echo "ANTHROPIC_API_KEY=your-key" > .env
streamlit run app.py

## Frameworks covered
- STRIDE (traditional app threats)
- Single-Agent AI threats (SA01-SA08)
- Multi-Agent AI threats (MA01-MA10)
- MITRE ATLAS adversarial ML threats
- CVSS 3.1 scoring

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent / "agents"))
from orchestrator import scan

st.set_page_config(page_title="Phishing Detection Platform", page_icon="🛡️", layout="centered")

st.title("🛡️ Agentic AI Phishing Detection Platform")
st.caption("URL Analysis + Domain/WHOIS + Threat Intel agents, with an Orchestrator and a Decision Agent")

url = st.text_input("Paste a URL", placeholder="http://example.com/login")

if st.button("SCAN", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        with st.spinner("Agents are analyzing the URL..."):
            r = scan(url.strip())

        score = r["final_score"]
        if r["verdict"] == "PHISHING":
            st.error(f"🚨 PHISHING  |  Risk: {score}/100")
        elif r["verdict"] == "SUSPICIOUS":
            st.warning(f"⚠️ SUSPICIOUS  |  Risk: {score}/100")
        else:
            st.success(f"✅ SAFE  |  Risk: {score}/100")

        st.progress(score / 100)
        st.write("**Action:**", r["action"])

        st.subheader("What the agents did")
        for i, s in enumerate(r["steps"], 1):
            st.write(f"{i}. {s}")

        st.subheader("Explanation")
        for reason in r["reasons"]:
            st.write("•", reason)
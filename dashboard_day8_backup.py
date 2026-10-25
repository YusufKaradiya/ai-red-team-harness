
import streamlit as st
import requests

st.set_page_config(
    page_title="MAI-24 | Red-Team Harness",
    page_icon="🛡️",
    layout="wide",
)

API_URL = st.text_input(
    "Backend API URL",
    value="http://127.0.0.1:8000",
)

st.title("🛡️ MAI-24 | Agentic AI Red-Team Harness")

st.caption(
    "Prompt Injection | Tool Abuse | Data Exfiltration"
)

st.info("Day 1: Environment and backend connectivity")

if st.button("Check Backend Connection"):
    try:
        response = requests.get(
            f"{API_URL.rstrip('/')}/health",
            timeout=5,
        )
        response.raise_for_status()
        result = response.json()

        st.success("Backend connection successful")
        st.json(result)

    except requests.RequestException as exc:
        st.error(f"Backend connection failed: {exc}")

st.divider()

col1, col2, col3 = st.columns(3)

col1.metric("Project", "MAI-24")
col2.metric("Frontend", "Streamlit")
col3.metric("Backend", "FastAPI")

st.caption("Security testing functionality will be added in later milestones.")

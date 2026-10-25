
import os
import json
from io import StringIO

import requests
import pandas as pd
import streamlit as st


# ---------------- CONFIG ----------------

API_BASE_URL = os.getenv(
    "REDTEAM_API_URL",
    "http://127.0.0.1:8000"
).rstrip("/")

TIMEOUT = 20
MAX_SCENARIOS = 100

st.set_page_config(
    page_title="MAI-24 Red-Team Harness",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------- API HELPERS ----------------

def api_get(path):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def api_post(path, payload):
    response = requests.post(
        f"{API_BASE_URL}{path}",
        json=payload,
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def normalize_scenarios(data):
    """
    Accept common response formats:
    - list of scenarios
    - {"scenarios": [...]}
    - {"items": [...]}
    """
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get(
            "scenarios",
            data.get("items", []),
        )
    else:
        raise ValueError("Invalid scenarios response")

    if not isinstance(items, list):
        raise ValueError("Scenario collection must be a list")

    normalized = []

    for item in items:
        if not isinstance(item, dict):
            continue

        scenario_id = item.get("id")

        if not isinstance(scenario_id, str):
            continue

        normalized.append({
            **item,
            "id": scenario_id,
            "name": item.get("name", scenario_id),
            "category": item.get("category", "unknown"),
            "severity": item.get("severity", "unknown"),
            "enabled": item.get("enabled", True),
        })

    return normalized


def safe_trials(result):
    trials = result.get("trials", [])

    if not isinstance(trials, list):
        return []

    return [
        trial for trial in trials
        if isinstance(trial, dict)
    ]


def make_trials_dataframe(trials):
    if not trials:
        return pd.DataFrame()

    rows = []

    for trial in trials:
        expected = trial.get("expected", {})
        observed = trial.get("observed", {})

        if not isinstance(expected, dict):
            expected = {}

        if not isinstance(observed, dict):
            observed = {}

        rows.append({
            "Scenario": trial.get("scenario_id", "Unknown"),
            "Mode": trial.get("mode", "Unknown"),
            "Status": trial.get("status", "Unknown"),
            "Reason": trial.get("reason_code", "Unknown"),
            "Expected Authorization": expected.get(
                "authorization", "Unknown"
            ),
            "Observed Authorization": observed.get(
                "authorization", "Unknown"
            ),
            "Secret Exposure": observed.get(
                "secret_exposure", "Unknown"
            ),
            "Pass": trial.get("pass", "Unknown"),
            "Latency (ms)": trial.get("latency_ms", None),
        })

    return pd.DataFrame(rows)


# ---------------- HEADER ----------------

st.title("🛡️ MAI-24 | Agentic AI Red-Team Harness")

st.caption(
    "Prompt Injection • Tool Abuse • Synthetic Data Exfiltration"
)

with st.sidebar:
    st.header("Control Panel")
    st.caption("Local security testing environment")

    st.code(API_BASE_URL)

    if st.button("Check Backend", use_container_width=True):
        try:
            health = api_get("/health")
            st.success("Backend responded")
            st.json(health)
        except requests.RequestException as exc:
            st.error(f"Backend unavailable: {type(exc).__name__}")

    st.divider()
    st.info(
        "Use only the authorized local simulator and "
        "synthetic test data."
    )


# ---------------- SESSION STATE ----------------

if "campaign_result" not in st.session_state:
    st.session_state.campaign_result = None

if "campaign_error" not in st.session_state:
    st.session_state.campaign_error = None


# ---------------- LOAD SCENARIOS ----------------

st.header("1. Scenario Explorer")

try:
    scenario_data = api_get("/scenarios")
    scenarios = normalize_scenarios(scenario_data)

    scenarios = [
        s for s in scenarios
        if s.get("enabled") is True
    ]

except (requests.RequestException, ValueError) as exc:
    st.error(
        "Could not load scenarios. Check backend and API format."
    )
    st.caption(type(exc).__name__)
    st.stop()


if not scenarios:
    st.warning("No enabled scenarios available.")
    st.stop()


col_a, col_b, col_c = st.columns(3)

col_a.metric("Enabled Scenarios", len(scenarios))

col_b.metric(
    "Categories",
    len(set(s["category"] for s in scenarios)),
)

col_c.metric(
    "Severity Levels",
    len(set(s["severity"] for s in scenarios)),
)


filter_col1, filter_col2 = st.columns(2)

categories = sorted(
    set(s["category"] for s in scenarios)
)

severities = sorted(
    set(s["severity"] for s in scenarios)
)

with filter_col1:
    category_filter = st.multiselect(
        "Filter by Category",
        categories,
        default=categories,
    )

with filter_col2:
    severity_filter = st.multiselect(
        "Filter by Severity",
        severities,
        default=severities,
    )


filtered = [
    s for s in scenarios
    if s["category"] in category_filter
    and s["severity"] in severity_filter
]

scenario_df = pd.DataFrame([
    {
        "ID": s["id"],
        "Name": s["name"],
        "Category": s["category"],
        "Severity": s["severity"],
    }
    for s in filtered
])

st.dataframe(
    scenario_df,
    use_container_width=True,
    hide_index=True,
)

# ---------------- CAMPAIGN RUNNER ----------------

st.divider()
st.header("2. Campaign Runner")

mode = st.radio(
    "Select Campaign Mode",
    ["defended", "baseline"],
    horizontal=True,
    help="Baseline and defended campaigns use different execution paths.",
)

available_ids = [s["id"] for s in filtered]

selected_ids = st.multiselect(
    "Select scenarios",
    options=available_ids,
    default=available_ids[:min(3, len(available_ids))],
    max_selections=MAX_SCENARIOS,
)

if mode == "defended":
    st.info(
        "Defended mode uses the configured security controls."
    )
else:
    st.warning(
        "Baseline mode is a comparison condition, not a "
        "security-approved operating mode."
    )

if st.button(
    "▶ Run Campaign",
    type="primary",
    use_container_width=True,
):
    if not selected_ids:
        st.warning("Select at least one scenario.")

    elif len(selected_ids) > MAX_SCENARIOS:
        st.error("Campaign exceeds scenario limit.")

    else:
        st.session_state.campaign_result = None
        st.session_state.campaign_error = None

        payload = {
            "mode": mode,
            "selected_ids": selected_ids,
            "defense_overrides": {},
        }

        try:
            with st.spinner("Executing campaign..."):
                result = api_post(
                    "/campaigns/run",
                    payload,
                )

            if not isinstance(result, dict):
                raise ValueError("Invalid campaign response")

            st.session_state.campaign_result = result
            st.success("Campaign response received.")

        except requests.RequestException as exc:
            st.session_state.campaign_error = (
                f"API request failed: {type(exc).__name__}"
            )

        except ValueError as exc:
            st.session_state.campaign_error = str(exc)


if st.session_state.campaign_error:
    st.error(st.session_state.campaign_error)


# ---------------- CAMPAIGN RESULTS ----------------

result = st.session_state.campaign_result

if result:
    st.divider()
    st.header("3. Campaign Results")

    campaign_id = result.get("campaign_id", "Unknown")

    st.caption(f"Campaign ID: {campaign_id}")

    total = result.get("scenario_count", 0)
    completed = result.get("completed_count", 0)
    errors = result.get("error_count", 0)
    passed = result.get("pass_count", 0)

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Selected Trials", total)
    c2.metric("Completed", completed)
    c3.metric("Errors", errors)
    c4.metric("Matched Expected", passed)

    trials = safe_trials(result)

    df = make_trials_dataframe(trials)

    if not df.empty:
        st.subheader("Trial-Level Results")

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

        # Export current campaign results.
        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇ Download Trial Results CSV",
            data=csv_data,
            file_name=f"campaign_{campaign_id}.csv",
            mime="text/csv",
        )

        # Show execution statuses.
        st.subheader("Execution Status Distribution")

        status_counts = (
            df["Status"]
            .fillna("Unknown")
            .value_counts()
        )

        st.bar_chart(status_counts)

        # Latency visualization.
        latency_df = df[
            ["Scenario", "Latency (ms)"]
        ].dropna()

        if not latency_df.empty:
            st.subheader("Trial Latency")

            st.bar_chart(
                latency_df.set_index("Scenario")
            )

        # Trial inspection.
        st.subheader("Trial Inspection")

        chosen = st.selectbox(
            "Choose scenario result",
            df["Scenario"].tolist(),
        )

        matching = next(
            (
                trial for trial in trials
                if trial.get("scenario_id") == chosen
            ),
            None,
        )

        if matching:
            st.json(matching)

        # Raw trial CSV only; don't export sensitive audit logs.
        st.caption(
            "CSV contains displayed trial fields only. "
            "Inspect the data before sharing."
        )

    else:
        st.warning(
            "Campaign summary received, but trial details "
            "were not included in the response."
        )

    st.subheader("Campaign Summary")

    st.json({
        "campaign_id": campaign_id,
        "mode": result.get("mode"),
        "scenario_count": total,
        "completed_count": completed,
        "error_count": errors,
        "pass_count": passed,
        "execution_pass_rate": result.get(
            "execution_pass_rate"
        ),
        "result_match_rate": result.get(
            "result_match_rate"
        ),
    })


# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "MAI-24 | Research prototype | "
    "Results are limited to the configured test environment."
)





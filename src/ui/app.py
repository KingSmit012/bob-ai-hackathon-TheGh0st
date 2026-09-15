"""
ui/app.py — Streamlit web dashboard for the Threat Intel Correlation Assistant.

A lightweight UI with three main views:
  1. Alert Feed       — raw alert table, filterable by source/severity
  2. Correlated Incidents — grouped view showing which alerts form each incident
  3. BLUF Reports     — ranked summaries with colour-coded priority

Run with:
    streamlit run ui/app.py

DESIGN: Minimal and functional. Uses Streamlit's built-in components
(tables, expanders, metrics, columns) rather than custom HTML/CSS.
"""

import streamlit as st
import pandas as pd
import json
import os
import sys
from datetime import datetime

# Add src/ to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SYNTHETIC_ALERTS_FILE, CORRELATION_TIME_WINDOW_MINUTES
from ingestion.ingest import load_alerts_from_json, Alert
from correlation.correlator import correlate_alerts, Incident


# ─── PAGE CONFIG ─────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Threat Intel Correlation Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better visuals
st.markdown("""
<style>
    .stMetric {
        background-color: #1e1e2e;
        padding: 15px;
        border-radius: 10px;
    }
    .genuine-threat {
        background-color: #ff4b4b20;
        border-left: 4px solid #ff4b4b;
        padding: 10px;
        margin: 5px 0;
        border-radius: 5px;
    }
    .false-positive {
        background-color: #00cc6620;
        border-left: 4px solid #00cc66;
        padding: 10px;
        margin: 5px 0;
        border-radius: 5px;
    }
    .bluf-box {
        background-color: #1a1a2e;
        border: 1px solid #444;
        padding: 15px;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
    }
</style>
""", unsafe_allow_html=True)


# ─── SIDEBAR ─────────────────────────────────────────────────────────────

st.sidebar.title("🛡️ Threat Intel Assistant")
st.sidebar.markdown("---")

# File upload or use default
upload_mode = st.sidebar.radio(
    "Alert Source",
    ["Use Sample Data", "Upload JSON File"],
)

alert_file = None
if upload_mode == "Upload JSON File":
    uploaded = st.sidebar.file_uploader("Upload alert JSON", type=["json"])
    if uploaded:
        # Save to temp location
        temp_path = os.path.join(os.path.dirname(__file__), "_uploaded_alerts.json")
        with open(temp_path, "wb") as f:
            f.write(uploaded.getvalue())
        alert_file = temp_path
else:
    alert_file = SYNTHETIC_ALERTS_FILE

# Correlation settings
st.sidebar.markdown("---")
st.sidebar.subheader("Correlation Settings")
time_window = st.sidebar.slider(
    "Time Window (minutes)",
    min_value=5,
    max_value=120,
    value=CORRELATION_TIME_WINDOW_MINUTES,
    step=5,
    help="Alerts within this time window are grouped into the same incident."
)

# Analysis trigger
st.sidebar.markdown("---")
run_llm = st.sidebar.checkbox(
    "Run LLM Analysis",
    value=False,
    help="Enable to classify incidents, map MITRE ATT&CK, and generate BLUF summaries. "
         "Requires LLM API key in .env file."
)

analyse_button = st.sidebar.button(
    "🔍 Analyse Alerts",
    type="primary",
    use_container_width=True,
)


# ─── HELPER FUNCTIONS ───────────────────────────────────────────────────

@st.cache_data
def load_and_correlate(file_path: str, time_window_min: int):
    """Load alerts and correlate them. Cached to avoid re-running."""
    alerts = load_alerts_from_json(file_path)
    incidents = correlate_alerts(alerts, time_window_min)
    return alerts, incidents


def severity_color(severity: str) -> str:
    """Return a colour for a severity level."""
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }.get(severity, "⚪")


def alerts_to_dataframe(alerts) -> pd.DataFrame:
    """Convert a list of Alert objects to a Pandas DataFrame."""
    rows = []
    for a in alerts:
        rows.append({
            "ID": a.alert_id,
            "Time": a.timestamp.strftime("%H:%M:%S"),
            "Source": a.source,
            "Severity": f"{severity_color(a.severity_reported)} {a.severity_reported.upper()}",
            "Type": a.alert_type,
            "Source IP": a.source_ip,
            "Dest IP": a.dest_ip,
            "Port": a.dest_port,
            "Asset": a.asset_name,
            "Message": a.raw_message[:120] + "..." if len(a.raw_message) > 120 else a.raw_message,
        })
    return pd.DataFrame(rows)


# ─── MAIN CONTENT ────────────────────────────────────────────────────────

st.title("🛡️ Threat Intel Correlation & Alert Prioritisation")
st.markdown("*Defence analysts' assistant: Ingest → Correlate → Classify → Prioritise → BLUF*")

if alert_file is None or not os.path.exists(alert_file):
    st.warning("Please upload an alert JSON file or use the sample data.")
    st.stop()

# Load and correlate
alerts, incidents = load_and_correlate(alert_file, time_window)

# ── Tab Layout ──
tab1, tab2, tab3 = st.tabs([
    "📋 Alert Feed",
    "🔗 Correlated Incidents",
    "📊 BLUF Reports"
])


# ─── TAB 1: ALERT FEED ──────────────────────────────────────────────────

with tab1:
    st.header("Raw Alert Feed")

    # Metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Alerts", len(alerts))
    with col2:
        critical = sum(1 for a in alerts if a.severity_reported == "critical")
        st.metric("Critical", critical)
    with col3:
        high = sum(1 for a in alerts if a.severity_reported == "high")
        st.metric("High", high)
    with col4:
        medium = sum(1 for a in alerts if a.severity_reported == "medium")
        st.metric("Medium", medium)
    with col5:
        low = sum(1 for a in alerts if a.severity_reported == "low")
        st.metric("Low", low)

    st.markdown("---")

    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        sources = sorted({a.source for a in alerts})
        source_filter = st.multiselect("Filter by Source", sources, default=sources)
    with col_f2:
        severities = ["critical", "high", "medium", "low"]
        sev_filter = st.multiselect("Filter by Severity", severities, default=severities)
    with col_f3:
        alert_types = sorted({a.alert_type for a in alerts})
        type_filter = st.multiselect("Filter by Alert Type", alert_types, default=alert_types)

    # Apply filters
    filtered = [
        a for a in alerts
        if a.source in source_filter
        and a.severity_reported in sev_filter
        and a.alert_type in type_filter
    ]

    st.dataframe(
        alerts_to_dataframe(filtered),
        use_container_width=True,
        height=500,
    )
    st.caption(f"Showing {len(filtered)} of {len(alerts)} alerts")


# ─── TAB 2: CORRELATED INCIDENTS ────────────────────────────────────────

with tab2:
    st.header("Correlated Incidents")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Incidents", len(incidents))
    with col2:
        st.metric("Time Window", f"{time_window} min")

    st.markdown("---")

    for inc in incidents:
        severity_emoji = severity_color(inc.max_severity)

        with st.expander(
            f"{severity_emoji} {inc.incident_id} — "
            f"{inc.alert_count} alerts | "
            f"Severity: {inc.max_severity.upper()} | "
            f"Assets: {', '.join(sorted(inc.involved_assets))}",
            expanded=False,
        ):
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.write(f"**Time Range:** {inc.time_start.strftime('%H:%M:%S')} - "
                        f"{inc.time_end.strftime('%H:%M:%S')}")
            with col2:
                st.write(f"**Source IP:** {inc.primary_source_ip}")
            with col3:
                st.write(f"**Target IP:** {inc.primary_dest_ip}")
            with col4:
                st.write(f"**Alert Types:** {len(inc.alert_types)}")

            st.markdown("**Alert Types:** " + ", ".join(sorted(inc.alert_types)))
            st.markdown("**Involved IPs:** " + ", ".join(sorted(inc.involved_ips)))

            # Show the alerts in this incident
            st.dataframe(
                alerts_to_dataframe(inc.alerts),
                use_container_width=True,
            )


# ─── TAB 3: BLUF REPORTS ────────────────────────────────────────────────

with tab3:
    st.header("BLUF Intelligence Reports")

    if not run_llm:
        # st.info(
        #     "Enable **'Run LLM Analysis'** in the sidebar and click "
        #     "**'Analyse Alerts'** to generate BLUF reports. "
        #     "This requires an LLM API key configured in your .env file."
        # )

        # Show a preview of what the output would look like
        # st.markdown("### Preview (without LLM)")
        st.markdown("Below are the correlated incidents that would be analysed:")

        for inc in incidents:
            severity_emoji = severity_color(inc.max_severity)
            st.markdown(
                f"**{severity_emoji} {inc.incident_id}** — "
                f"{inc.alert_count} alerts, {inc.max_severity.upper()} severity, "
                f"Assets: {', '.join(sorted(inc.involved_assets))}"
            )

    elif analyse_button or "analysis_results" in st.session_state:

        if analyse_button:
            # Run the full LLM analysis pipeline
            with st.spinner("Running LLM analysis... This may take a minute."):
                try:
                    from classification.classifier import classify_incident
                    from mitre_mapping.mapper import map_to_mitre
                    from bluf.generator import generate_bluf
                    from prioritisation.ranker import rank_incidents
                    from llm.llm_client import get_llm_client

                    llm_client = get_llm_client()

                    classifications = {}
                    mitre_mappings = {}
                    bluf_summaries = {}

                    progress = st.progress(0, text="Classifying incidents...")
                    total_steps = len(incidents) * 3  # classify + mitre + bluf

                    step = 0
                    for incident in incidents:
                        # Classify
                        progress.progress(
                            step / total_steps,
                            text=f"Classifying {incident.incident_id}..."
                        )
                        cls = classify_incident(incident, llm_client)
                        classifications[incident.incident_id] = cls
                        step += 1

                        # MITRE map
                        progress.progress(
                            step / total_steps,
                            text=f"MITRE mapping {incident.incident_id}..."
                        )
                        mitre = map_to_mitre(incident, llm_client)
                        mitre_mappings[incident.incident_id] = mitre
                        step += 1

                        # BLUF
                        progress.progress(
                            step / total_steps,
                            text=f"Generating BLUF for {incident.incident_id}..."
                        )
                        bluf = generate_bluf(incident, cls, mitre, llm_client)
                        bluf_summaries[incident.incident_id] = bluf
                        step += 1

                    progress.progress(1.0, text="Analysis complete!")

                    # Rank
                    ranked = rank_incidents(incidents, classifications)

                    # Store in session state
                    st.session_state["analysis_results"] = {
                        "ranked": ranked,
                        "classifications": classifications,
                        "mitre_mappings": mitre_mappings,
                        "bluf_summaries": bluf_summaries,
                    }

                except Exception as e:
                    st.error(f"Analysis failed: {e}")
                    st.exception(e)
                    st.stop()

        # Display results from session state
        if "analysis_results" in st.session_state:
            results = st.session_state["analysis_results"]
            ranked = results["ranked"]
            classifications = results["classifications"]
            mitre_mappings = results["mitre_mappings"]
            bluf_summaries = results["bluf_summaries"]

            # Summary metrics
            genuine_count = sum(
                1 for _, _ in ranked
                if classifications.get(_.incident_id, {}).get("classification") == "genuine_threat"
                for _ in [_]  # just to access the incident
            )
            # Simpler count
            genuine_count = 0
            fp_count = 0
            for inc, score in ranked:
                if classifications.get(inc.incident_id, {}).get("classification") == "genuine_threat":
                    genuine_count += 1
                else:
                    fp_count += 1

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Incidents", len(ranked))
            with col2:
                st.metric("Genuine Threats", genuine_count)
            with col3:
                st.metric("False Positives", fp_count)

            st.markdown("---")

            # Display each incident
            for rank_num, (incident, score) in enumerate(ranked, start=1):
                inc_id = incident.incident_id
                cls = classifications.get(inc_id, {})
                mitre = mitre_mappings.get(inc_id, [])
                bluf = bluf_summaries.get(inc_id, "No BLUF generated")

                is_threat = cls.get("classification") == "genuine_threat"
                css_class = "genuine-threat" if is_threat else "false-positive"
                badge = "🔴 GENUINE THREAT" if is_threat else "🟢 FALSE POSITIVE"

                st.markdown(
                    f'<div class="{css_class}">'
                    f'<h3>#{rank_num} — {inc_id} [{badge}]</h3>'
                    f'<p><strong>Priority Score:</strong> {score:.4f} | '
                    f'<strong>Confidence:</strong> {cls.get("confidence", 0)}% | '
                    f'<strong>Severity:</strong> {incident.max_severity.upper()} | '
                    f'<strong>Alerts:</strong> {incident.alert_count}</p>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

                with st.expander(f"View Details — {inc_id}", expanded=is_threat):
                    # BLUF Summary
                    st.markdown("#### BLUF Summary")
                    st.markdown(f'<div class="bluf-box">{bluf}</div>',
                               unsafe_allow_html=True)

                    # MITRE mapping
                    if mitre:
                        st.markdown("#### MITRE ATT&CK Mapping")
                        mitre_df = pd.DataFrame(mitre)
                        st.dataframe(mitre_df, use_container_width=True)

                    # Classification reasoning
                    st.markdown(f"**Reasoning:** {cls.get('reasoning', 'N/A')}")

                    # Alerts in this incident
                    st.markdown("#### Alerts")
                    st.dataframe(
                        alerts_to_dataframe(incident.alerts),
                        use_container_width=True,
                    )

                st.markdown("")

    else:
        st.info("Click **'Analyse Alerts'** in the sidebar to start the LLM analysis.")

"""KAVACH Streamlit Dashboard — Soft Pastel Edition.

Clean, human-friendly interface for monitoring network intrusions.
"""

from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3
import sys
import threading
import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.capture import LiveCaptureEngine, check_capture_prerequisites, list_available_interfaces
from src.config import DEFAULT_ALERT_THRESHOLD, DEFAULT_INTERFACE, LOG_DB_PATH, METRICS_PATH, MODELS_DIR
from src.predictor import FlowPredictor
from src.simulate import DatasetReplayer, run_localhost_probe

st.set_page_config(
    page_title="Kavach — Network Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Pastel Design System ──────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

:root {
    --bg:         #faf7f2;
    --surface:    #ffffff;
    --sidebar-bg: #f4efe9;
    --border:     #e9e2d8;

    --rose:       #f4a7b9;
    --rose-soft:  #fdebf0;
    --lavender:   #c8b6e2;
    --lav-soft:   #ede8f8;
    --mint:       #a8d5ba;
    --mint-soft:  #e7f5ec;
    --peach:      #f9c89b;
    --peach-soft: #fef1e3;
    --sky:        #a3c4f3;
    --sky-soft:   #e7effb;

    --text-dark:  #342e2b;
    --text-mid:   #6e645e;
    --text-light: #9e938b;
}

html, body, [class*="css"], .stApp {
    font-family: 'Inter', sans-serif !important;
    background-color: var(--bg) !important;
    color: var(--text-dark) !important;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background-color: var(--sidebar-bg) !important;
    border-right: 1px solid var(--border) !important;
}
section[data-testid="stSidebar"] * { color: var(--text-dark) !important; }

/* ── Main container ── */
.block-container {
    padding-top: 1.8rem !important;
    max-width: 95% !important;
}

/* ── Hero banner ── */
.hero {
    background: linear-gradient(135deg, #fdebf0 0%, #ede8f8 50%, #e7effb 100%);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.6rem 2rem;
    margin-bottom: 1.4rem;
}
.hero-badge {
    display: inline-block;
    background: rgba(255, 255, 255, 0.8);
    color: #6b3fa0;
    border: 1px solid var(--lavender);
    border-radius: 20px;
    padding: 0.2rem 0.8rem;
    font-size: 0.78rem;
    font-weight: 600;
    margin-bottom: 0.6rem;
}
.hero-title {
    font-size: 1.9rem;
    font-weight: 700;
    color: var(--text-dark);
    margin: 0 0 0.3rem 0;
}
.hero-sub {
    font-size: 0.92rem;
    color: var(--text-mid);
    margin: 0;
    line-height: 1.5;
}

/* ── Cards ── */
.p-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
}

/* ── Step-by-step pipeline cards ── */
.step-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
    display: flex;
    gap: 1.2rem;
    align-items: flex-start;
}
.step-number {
    background: var(--lav-soft);
    color: #6b3fa0;
    border: 1px solid var(--lavender);
    font-size: 0.82rem;
    font-weight: 700;
    padding: 0.35rem 0.75rem;
    border-radius: 8px;
    white-space: nowrap;
}
.step-title {
    font-size: 1rem;
    font-weight: 700;
    color: var(--text-dark);
    margin-bottom: 0.3rem;
}
.step-desc {
    font-size: 0.87rem;
    color: var(--text-mid);
    line-height: 1.55;
}
.step-tag {
    display: inline-block;
    background: #fbf8f5;
    color: var(--text-mid);
    border: 1px solid var(--border);
    font-size: 0.75rem;
    padding: 0.15rem 0.55rem;
    border-radius: 6px;
    margin-top: 0.4rem;
    margin-right: 0.4rem;
}

/* ── Novelty section ── */
.novelty-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-bottom: 1.2rem;
}
.novelty-item {
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.1rem 1.3rem;
}
.novelty-item-title {
    font-size: 0.92rem;
    font-weight: 700;
    color: var(--text-dark);
    margin-bottom: 0.35rem;
}
.novelty-item-body {
    font-size: 0.84rem;
    color: var(--text-mid);
    line-height: 1.5;
}

/* ── Comparison section ── */
.diff-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.2rem;
    margin-bottom: 1.2rem;
}
.diff-col {
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
}
.diff-col-title {
    font-size: 0.95rem;
    font-weight: 700;
    margin-bottom: 0.8rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
}
.tradition-title { color: #8a624a; }
.kavach-title { color: #5a4b81; }
.diff-point {
    font-size: 0.84rem;
    color: var(--text-mid);
    line-height: 1.5;
    margin-bottom: 0.7rem;
    padding-left: 0.7rem;
    border-left: 3px solid var(--border);
}
.diff-point strong { color: var(--text-dark); }

/* ── Tabs (Pure Solid Black Font & Modern Pastel Capsule) ── */
.stTabs [data-baseweb="tab-list"],
div[data-testid="stTabs"] [data-baseweb="tab-list"] {
    display: flex !important;
    gap: 0.6rem !important;
    background: #f2ece4 !important;
    padding: 0.4rem 0.5rem !important;
    border-radius: 12px !important;
    border: 1px solid var(--border) !important;
    margin-bottom: 1.5rem !important;
}

/* Hide default red highlight bar */
[data-baseweb="tab-highlight"],
div[data-testid="stTabs"] [data-baseweb="tab-highlight"],
[data-baseweb="tab-border"],
div[data-testid="stTabs"] [data-baseweb="tab-border"] {
    display: none !important;
    background-color: transparent !important;
    height: 0 !important;
}

/* FORCE ALL TAB TEXT TO SOLID BLACK */
button[data-baseweb="tab"],
button[data-baseweb="tab"] *,
button[data-baseweb="tab"] p,
button[data-baseweb="tab"] span,
button[data-baseweb="tab"] div,
[data-testid="stTabs"] button,
[data-testid="stTabs"] button *,
[data-testid="stTabs"] button p,
[data-testid="stTabs"] button span,
[data-testid="stTabs"] button div,
.stTabs [data-baseweb="tab"],
.stTabs [data-baseweb="tab"] * {
    color: #000000 !important;
    -webkit-text-fill-color: #000000 !important;
    font-weight: 700 !important;
    opacity: 1 !important;
    visibility: visible !important;
}

button[data-baseweb="tab"],
[data-testid="stTabs"] button {
    background: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 9px !important;
    padding: 0.55rem 1.15rem !important;
    transition: all 0.2s ease !important;
}

button[data-baseweb="tab"]:hover {
    background: #ffffff !important;
}

button[data-baseweb="tab"][aria-selected="true"],
[data-testid="stTabs"] button[aria-selected="true"] {
    background: #ffffff !important;
    border: 2px solid #c8b6e2 !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: var(--surface) !important;
    color: var(--text-dark) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
}
.stButton > button:hover {
    border-color: var(--lavender) !important;
    background: var(--lav-soft) !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #c8b6e2, #a3c4f3) !important;
    color: #2d2040 !important;
    border: none !important;
    font-weight: 700 !important;
}

/* ── Metric widget override ── */
[data-testid="stMetric"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1rem 1.2rem;
}
[data-testid="stMetricLabel"] { color: var(--text-light) !important; font-size: 0.76rem !important; font-weight: 600 !important; text-transform: uppercase; }
[data-testid="stMetricValue"] { color: var(--text-dark) !important; font-size: 1.8rem !important; font-weight: 700 !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    overflow: hidden !important;
}
</style>
""", unsafe_allow_html=True)

# ── Plotly pastel theme helper ────────────────────────────────────────────────
PASTEL_COLORS = ["#c8b6e2", "#a3c4f3", "#a8d5ba", "#f9c89b", "#f4a7b9", "#b5dde8"]

def pastel_layout(fig, title=""):
    fig.update_layout(
        paper_bgcolor="white",
        plot_bgcolor="#fafafa",
        font=dict(family="Inter", color="#342e2b", size=12),
        title=dict(text=title, font=dict(size=14, color="#342e2b")),
        margin=dict(l=16, r=16, t=40, b=16),
    )
    fig.update_xaxes(gridcolor="#f4efe9", linecolor="#e9e2d8")
    fig.update_yaxes(gridcolor="#f4efe9", linecolor="#e9e2d8")
    return fig


# ── Session state ─────────────────────────────────────────────────────────────
if "engine_running" not in st.session_state:
    st.session_state.engine_running = False
if "capture_engine" not in st.session_state:
    st.session_state.capture_engine = None
if "replayer" not in st.session_state:
    st.session_state.replayer = None
if "predictor" not in st.session_state:
    try:
        st.session_state.predictor = FlowPredictor(threshold=DEFAULT_ALERT_THRESHOLD)
    except Exception as e:
        st.session_state.predictor = None
        st.error(f"Could not load ML model: {e}. Run `python -m src.train` first.")


def load_recent_flows(limit: int = 500) -> pd.DataFrame:
    if not LOG_DB_PATH.exists():
        return pd.DataFrame()
    try:
        with sqlite3.connect(LOG_DB_PATH) as conn:
            df = pd.read_sql_query(f"""
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
                       protocol, label, confidence, top_features, duration_ms, packets, bytes
                FROM flow_logs ORDER BY id DESC LIMIT {limit}
            """, conn)
        return df
    except Exception:
        return pd.DataFrame()


def clear_database():
    if LOG_DB_PATH.exists():
        with sqlite3.connect(LOG_DB_PATH) as conn:
            conn.execute("DELETE FROM flow_logs")
            conn.commit()


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Kavach Controls")
    st.caption("Abhishek Kothari · 24BCE2610")
    st.markdown("---")

    mode = st.radio(
        "Operation Mode",
        ["Simulation (Benchmark Dataset)", "Live Sniffing (Scapy)"],
        index=0,
        help="Simulation replays labeled attack traffic. Live Sniffing captures actual packets from your Wi-Fi/Ethernet."
    )

    threshold = st.slider(
        "Detection Sensitivity",
        min_value=0.10, max_value=0.95,
        value=DEFAULT_ALERT_THRESHOLD, step=0.05,
        help="If attack probability exceeds this threshold → flagged as Suspicious."
    )
    if st.session_state.predictor:
        st.session_state.predictor.threshold = threshold

    if "Simulation" in mode:
        replay_speed = st.slider("Replay Speed (flows/sec)", 1.0, 25.0, 6.0, 1.0)
    else:
        available_ifaces = list_available_interfaces()
        selected_iface = st.selectbox("Network Interface", available_ifaces)
        bpf_filter = st.text_input("BPF Filter (optional)", placeholder="e.g. tcp and not port 8501")
        ok, msg = check_capture_prerequisites()
        if not ok:
            st.warning(msg)

    st.markdown("---")

    if not st.session_state.engine_running:
        if st.button("▶  Start Engine", type="primary", use_container_width=True):
            if "Simulation" in mode and st.session_state.predictor:
                replayer = DatasetReplayer(flows_per_second=replay_speed, predictor=st.session_state.predictor)
                replayer.start()
                st.session_state.replayer = replayer
                st.session_state.engine_running = True
                st.rerun()
            elif "Live" in mode:
                ok, msg = check_capture_prerequisites()
                if not ok:
                    st.error(msg)
                else:
                    engine = LiveCaptureEngine(
                        interface=selected_iface,
                        bpf_filter=bpf_filter.strip() or None,
                        threshold=threshold,
                        predictor=st.session_state.predictor,
                    )
                    engine.start()
                    st.session_state.capture_engine = engine
                    st.session_state.engine_running = True
                    st.rerun()
    else:
        if st.button("⏹  Stop Engine", use_container_width=True):
            if st.session_state.replayer:
                st.session_state.replayer.stop()
                st.session_state.replayer = None
            if st.session_state.capture_engine:
                st.session_state.capture_engine.stop()
                st.session_state.capture_engine = None
            st.session_state.engine_running = False
            st.rerun()

    st.markdown("---")
    if st.button("⚡ Safe Localhost Test Probe", use_container_width=True):
        threading.Thread(target=run_localhost_probe, daemon=True).start()
        st.toast("Dispatched benign test probe to 127.0.0.1")
    if st.button("🗑  Clear Alerts Database", use_container_width=True):
        clear_database()
        st.success("Database cleared!")
        st.rerun()

    auto_refresh = st.checkbox("Auto-refresh (every 2s)", value=True)


# ── Top Hero Banner ───────────────────────────────────────────────────────────
engine_status = "🟢 Running" if st.session_state.engine_running else "⚪ Idle"
st.markdown(f"""
<div class="hero">
  <div class="hero-badge">Project Kavach · Abhishek Kothari · 24BCE2610</div>
  <div class="hero-title">🛡️ Kavach — AI Network Intrusion Detection</div>
  <p class="hero-sub">
    An AI security shield monitoring live network flows in real time. Rather than snooping into private packet data,
    Kavach learns flow behavior (traffic rhythm, packet sizes, and handshake ratios) to flag intrusions in milliseconds.
    &nbsp;·&nbsp; <strong>Engine Status:</strong> {engine_status}
  </p>
</div>
""", unsafe_allow_html=True)

# ── Load telemetry data ───────────────────────────────────────────────────────
df_flows = load_recent_flows(limit=1000)
total     = len(df_flows)
suspicious = int((df_flows["label"] == "Suspicious").sum()) if total > 0 else 0
normal     = total - suspicious
rate       = suspicious / total * 100 if total > 0 else 0.0

flows_per_sec = 0.0
if total > 1:
    try:
        df_flows["dt"] = pd.to_datetime(df_flows["timestamp"])
        recent = (df_flows["dt"] >= df_flows["dt"].max() - timedelta(seconds=10)).sum()
        flows_per_sec = recent / 10.0
    except Exception:
        pass

# ── 4 Main Tabs ───────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "📡 Live Monitor & Alerts",
    "📖 How the AI Model Works",
    "⚖️ Novelty & vs Traditional Firewalls",
    "📊 Threat Analytics & Performance",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: Live Monitor & Alerts
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    # KPI row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Flows Analysed", f"{total:,}", help="Total network flows inspected since start.")
    with c2:
        st.metric("Attacks Caught", f"{suspicious:,}",
                  delta=f"{rate:.1f}% attack rate" if total > 0 else None,
                  delta_color="inverse")
    with c3:
        st.metric("Safe Traffic Flows", f"{normal:,}")
    with c4:
        st.metric("Throughput", f"{flows_per_sec:.1f} flows/s", help="Flows inspected per second.")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### Real-Time Network Flow Stream")
    st.caption("Each row represents a 5-second bidirectional conversation between two devices. "
               "Safe flows are marked in soft green; suspicious attacks are flagged in soft rose with confidence score.")

    if df_flows.empty:
        st.info("No network activity captured yet. Click **▶ Start Engine** in the left sidebar to begin streaming.")
    else:
        display = df_flows.head(100)[[
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "label", "confidence", "packets", "bytes",
        ]].copy()

        def highlight(val):
            if val == "Suspicious":
                return "background-color: #fdebf0; color: #b83253; font-weight:600;"
            return "background-color: #e7f5ec; color: #236c46; font-weight:600;"

        styled = display.style.map(highlight, subset=["label"]).format({
            "confidence": "{:.1%}", "packets": "{:,}", "bytes": "{:,}"
        })
        try:
            st.dataframe(styled, use_container_width=True, height=450)
        except TypeError:
            st.dataframe(styled, height=450)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: How the AI Model Works (Dedicated Easy Explanation Page)
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("""
    <div class="p-card" style="background: linear-gradient(135deg, #ede8f8 0%, #fef1e3 100%);">
      <div style="font-size: 1.15rem; font-weight: 700; color: var(--text-dark); margin-bottom: 0.4rem;">
        💡 The Simple Mental Model: The Smart Security Guard
      </div>
      <div style="font-size: 0.9rem; color: var(--text-mid); line-height: 1.6;">
        Imagine a security guard standing at a building entrance. They don't open every visitor's private letters or bags (that would violate privacy and take too long).
        Instead, they watch <strong>behavioral body language</strong>: Is someone pacing back and forth nervously? Are they testing 50 door handles in 3 seconds?
        <br><br>
        <strong>Kavach does the exact same thing for computer networks:</strong> It doesn't read encrypted passwords or message contents.
        It measures the <em>rhythm, speed, packet size differences, and TCP handshake patterns</em> of network conversations to catch attacks with over 99% accuracy.
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🛠️ Step-by-Step Technical Pipeline")

    st.markdown("""
    <div class="step-card">
      <div class="step-number">STEP 1</div>
      <div class="step-content">
        <div class="step-title">Raw Packet Sniffing (Scapy Engine)</div>
        <div class="step-desc">
          Kavach hooks into the host's physical network adapter (Wi-Fi or Ethernet) using Scapy. It intercepts raw IP packets,
          reading only packet headers (Source IP, Destination IP, Ports, TCP Flags like SYN/ACK/FIN, and packet byte length).
        </div>
        <span class="step-tag">Zero-Payload Access</span>
        <span class="step-tag">Wi-Fi & Ethernet</span>
        <span class="step-tag">Non-Intrusive Sniffing</span>
      </div>
    </div>

    <div class="step-card">
      <div class="step-number">STEP 2</div>
      <div class="step-content">
        <div class="step-title">5-Second Micro-Flow Aggregation (Flow Builder)</div>
        <div class="step-desc">
          Individual packets don't tell the whole story. Kavach groups packets into <strong>bidirectional conversations (Flows)</strong>
          between client and server across a 5-second sliding window. For every flow, it computes <strong>50 statistical features</strong>:
          <br>• <strong>Packet Size Variance:</strong> Do packets vary naturally in size, or are they uniform dummy probe payloads?
          <br>• <strong>Inter-Arrival Times (IAT):</strong> How many milliseconds between packets? Automated bot attacks burst with inhuman precision.
          <br>• <strong>Forward vs. Backward Balance:</strong> In a DoS attack, millions of bytes flow inbound while zero bytes flow outbound.
        </div>
        <span class="step-tag">50 Features Computed</span>
        <span class="step-tag">Bidirectional Dynamics</span>
        <span class="step-tag">5s Temporal Window</span>
      </div>
    </div>

    <div class="step-card">
      <div class="step-number">STEP 3</div>
      <div class="step-content">
        <div class="step-title">Feature Normalization (StandardScaler)</div>
        <div class="step-desc">
          Raw feature numbers have vastly different scales — for example, <code>Flow Duration</code> might be 5,000,000 microseconds,
          while <code>SYN Flag Count</code> is just 1. The pre-fitted <strong>StandardScaler</strong> centers each feature around mean 0
          with unit variance so no single metric unfairly biases the model.
        </div>
        <span class="step-tag">Z-Score Normalization</span>
        <span class="step-tag">Numeric Stability</span>
      </div>
    </div>

    <div class="step-card">
      <div class="step-number">STEP 4</div>
      <div class="step-content">
        <div class="step-title">The Ensemble Committee (Random Forest with 100 Trees)</div>
        <div class="step-desc">
          Instead of relying on a single fallible decision rule, Kavach deploys a <strong>Random Forest of 100 independent Decision Trees</strong>.
          Each tree independently evaluates different subsets of the 50 flow features and casts a vote: <em>Normal (0)</em> or <em>Attack (1)</em>.
          <br><br>
          Using <strong>Balanced Class Weighting</strong>, the algorithm prevents normal traffic (which accounts for ~80% of volume) from
          drowning out rare, dangerous intrusion attempts.
        </div>
        <span class="step-tag">100 Decision Trees</span>
        <span class="step-tag">Balanced Class Weights</span>
        <span class="step-tag">Majority Voting</span>
      </div>
    </div>

    <div class="step-card">
      <div class="step-number">STEP 5</div>
      <div class="step-content">
        <div class="step-title">Confidence Scoring & Explainability (XAI)</div>
        <div class="step-desc">
          Kavach tallies all 100 tree votes to produce an Attack Probability:
          <br>• If 92 out of 100 trees vote Attack → <strong>Confidence = 92.0%</strong>.
          <br>• If Confidence > Alert Threshold (default 50%), an alert is logged to SQLite and sent to the dashboard.
          <br>• <strong>Explainable AI:</strong> The system surfaces the top 3 mathematical reasons why the alert was fired (e.g., <em>High SYN count, zero backward payload, short flow duration</em>).
        </div>
        <span class="step-tag">Sub-Millisecond Inference</span>
        <span class="step-tag">Explainable Triggers</span>
        <span class="step-tag">SQLite Persistence</span>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: Novelty & vs Traditional Firewalls
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### ✨ The 4 Novelty Pillars of Project Kavach")
    st.caption("Key technological innovations that differentiate Kavach from conventional network tools.")

    st.markdown("""
    <div class="novelty-grid">
      <div class="novelty-item">
        <div class="novelty-item-title">🔒 1. Zero-Payload Inspection</div>
        <div class="novelty-item-body">
          Preserves complete user privacy and operates naturally across <strong>TLS / HTTPS encrypted traffic</strong> without invasive packet decryption or SSL interception.
        </div>
      </div>
      <div class="novelty-item">
        <div class="novelty-item-title">⚡ 2. Live-to-Benchmark Parity</div>
        <div class="novelty-item-body">
          Bridges the gap between academic dataset training (CICIDS2017) and <strong>real-time Scapy sniffing</strong> via mathematical feature parity across 50 bidirectional metrics.
        </div>
      </div>
      <div class="novelty-item">
        <div class="novelty-item-title">💡 3. Real-Time Explainable AI (XAI)</div>
        <div class="novelty-item-body">
          No black-box guesses. Flags include <strong>driving feature attributions</strong> (inter-arrival time, packet length variance, TCP flags) so analysts know *why* an alert fired.
        </div>
      </div>
      <div class="novelty-item">
        <div class="novelty-item-title">🍃 4. Lightweight Edge Inference</div>
        <div class="novelty-item-body">
          Achieves sub-millisecond classification on <strong>commodity CPUs</strong> without requiring specialized GPU clusters or expensive hardware appliances.
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### ⚖️ Detailed Comparison: Kavach vs. Traditional Firewalls")

    st.markdown("""
    <div class="diff-grid">
      <div class="diff-col">
        <div class="diff-col-title tradition-title">🧱 Traditional Firewalls (Packet/Stateful)</div>
        <div class="diff-point">
          <strong>Static Rules:</strong> Filters based purely on static IP and Port numbers (e.g. Block Port 22). Malicious traffic on open ports (80/443) passes straight through.
        </div>
        <div class="diff-point">
          <strong>Blind to Encrypted Payloads:</strong> Cannot see inside TLS/HTTPS without expensive SSL termination (man-in-the-middle decryption), which harms user privacy.
        </div>
        <div class="diff-point">
          <strong>Fails on Zero-Days:</strong> Relies on known signature lists. New or mutated attack variants bypass detection until vendors issue updates.
        </div>
        <div class="diff-point">
          <strong>Perimeter Only:</strong> Positioned at the network edge; blind to internal lateral compromise between devices on the same subnet.
        </div>
        <div class="diff-point">
          <strong>Opaque Logs:</strong> Outputs simple "Deny / Allow" logs with no behavioral or statistical context.
        </div>
      </div>

      <div class="diff-col">
        <div class="diff-col-title kavach-title">🛡️ Project Kavach (AI Behavioral NIDS)</div>
        <div class="diff-point">
          <strong>Behavioral Analysis:</strong> Evaluates flow statistical geometry regardless of which port or protocol is being abused.
        </div>
        <div class="diff-point">
          <strong>Encrypted-Traffic Native:</strong> Analyzes flow metadata (packet intervals, size variance, flag ratios) — catches attacks inside encrypted sessions without decryption.
        </div>
        <div class="diff-point">
          <strong>Zero-Day Resilience:</strong> Detects mathematical deviations from baseline normal traffic, catching novel and mutated attacks.
        </div>
        <div class="diff-point">
          <strong>Internal Network Visibility:</strong> Sniffs interface traffic to detect internal reconnaissance, port scans, and lateral movement.
        </div>
        <div class="diff-point">
          <strong>Explainable Output:</strong> Provides confidence scores and lists the exact mathematical features that triggered the alert.
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4: Threat Analytics & Performance
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    if df_flows.empty:
        st.info("Analytics charts will appear once traffic flows are captured.")
    else:
        a, b = st.columns(2)
        with a:
            st.markdown("**Traffic Volume Over Time**")
            try:
                df_t = df_flows.copy()
                df_t["second"] = pd.to_datetime(df_t["timestamp"]).dt.strftime("%H:%M:%S")
                agg = df_t.groupby(["second", "label"]).size().reset_index(name="count")
                fig = px.area(agg, x="second", y="count", color="label",
                              color_discrete_map={"Normal": "#a8d5ba", "Suspicious": "#f4a7b9"})
                st.plotly_chart(pastel_layout(fig, "Flow Classification Activity"), use_container_width=True)
            except Exception as e:
                st.warning(f"Chart render error: {e}")

        with b:
            st.markdown("**Top Suspicious IPs Flagged**")
            susp = df_flows[df_flows["label"] == "Suspicious"]
            if susp.empty:
                st.success("✅ No suspicious IP addresses detected yet!")
            else:
                top = susp["src_ip"].value_counts().head(8).reset_index()
                top.columns = ["Source IP", "Alerts"]
                fig2 = px.bar(top, x="Source IP", y="Alerts",
                              color="Alerts", color_continuous_scale=["#fdebf0", "#f4a7b9", "#d95074"])
                st.plotly_chart(pastel_layout(fig2, "Intrusion Origin Distribution"), use_container_width=True)

        c, d = st.columns(2)
        with c:
            st.markdown("**Protocol Distribution**")
            proto = df_flows["protocol"].value_counts().reset_index()
            proto.columns = ["Protocol", "Count"]
            fig3 = px.pie(proto, values="Count", names="Protocol", hole=0.45,
                          color_discrete_sequence=PASTEL_COLORS)
            st.plotly_chart(pastel_layout(fig3, "Observed Protocols"), use_container_width=True)

        with d:
            st.markdown("**Alert Confidence Spread**")
            if not susp.empty:
                fig4 = px.histogram(susp, x="confidence", nbins=15,
                                    color_discrete_sequence=["#c8b6e2"])
                st.plotly_chart(pastel_layout(fig4, "Detection Confidence Histogram"), use_container_width=True)
            else:
                st.info("No suspicious flows to display confidence spread.")

    st.markdown("---")
    st.markdown("### 📈 Model Evaluation on Held-Out Test Data")
    st.caption("Rigorous evaluation metrics on unseen test traffic from the CICIDS2017 benchmark dataset.")

    if METRICS_PATH.exists():
        with open(METRICS_PATH) as f:
            m = json.load(f)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Overall Accuracy",  f"{m.get('accuracy',  0)*100:.2f}%")
        m2.metric("Precision",         f"{m.get('precision', 0)*100:.2f}%")
        m3.metric("Recall (Catch Rate)", f"{m.get('recall',    0)*100:.2f}%")
        m4.metric("F1 Score",          f"{m.get('f1',        0)*100:.2f}%")

        if "per_attack_recall" in m:
            st.markdown("##### Per-Attack Type Recall Breakdown")
            atk_df = pd.DataFrame([
                {"Attack Type": k, "Detection Rate": f"{v*100:.2f}%"}
                for k, v in m["per_attack_recall"].items()
            ])
            st.table(atk_df)

    feat_img = MODELS_DIR / "feature_importances.png"
    cm_img   = MODELS_DIR / "confusion_matrix.png"
    if feat_img.exists() or cm_img.exists():
        i1, i2 = st.columns(2)
        with i1:
            if feat_img.exists():
                st.image(str(feat_img), caption="Feature Importance (Gini Importance Ranking)")
        with i2:
            if cm_img.exists():
                st.image(str(cm_img), caption="Confusion Matrix on Held-out Test Set")


# ── Auto-refresh loop ─────────────────────────────────────────────────────────
if auto_refresh and st.session_state.engine_running:
    time.sleep(2.0)
    st.rerun()

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
    --bg:         #f8f4f0;
    --surface:    #ffffff;
    --sidebar-bg: #f0ebe5;
    --border:     #e8e0d8;

    --rose:       #f4a7b9;
    --rose-soft:  #fde8ed;
    --lavender:   #c8b6e2;
    --lav-soft:   #ede8f8;
    --mint:       #a8d5ba;
    --mint-soft:  #e4f5eb;
    --peach:      #f9c89b;
    --peach-soft: #fef0e0;
    --sky:        #a3c4f3;
    --sky-soft:   #e4eefb;

    --text-dark:  #3d3530;
    --text-mid:   #7a6f68;
    --text-light: #b0a89e;
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
    padding-top: 2rem !important;
    max-width: 96% !important;
}

/* ── Hero banner ── */
.hero {
    background: linear-gradient(135deg, #fde8ed 0%, #ede8f8 50%, #e4eefb 100%);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.8rem 2.2rem;
    margin-bottom: 1.6rem;
}
.hero-title {
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-dark);
    margin: 0 0 0.3rem 0;
}
.hero-sub {
    font-size: 0.95rem;
    color: var(--text-mid);
    margin: 0;
}
.hero-badge {
    display: inline-block;
    background: var(--lav-soft);
    color: #7c5cbf;
    border: 1px solid var(--lavender);
    border-radius: 20px;
    padding: 0.2rem 0.8rem;
    font-size: 0.78rem;
    font-weight: 600;
    margin-bottom: 0.8rem;
}

/* ── Novelty section ── */
.novelty-card {
    background: linear-gradient(135deg, #fbf7f4 0%, #f7f1fb 50%, #f0f7f3 100%);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1.4rem;
}
.novelty-header {
    font-size: 0.88rem;
    font-weight: 700;
    color: var(--text-dark);
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.novelty-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.9rem;
}
.novelty-item {
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.9rem 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
}
.novelty-item-title {
    font-size: 0.82rem;
    font-weight: 700;
    color: var(--text-dark);
    margin-bottom: 0.3rem;
}
.novelty-item-body {
    font-size: 0.78rem;
    color: var(--text-mid);
    line-height: 1.45;
}

/* ── Explain cards ── */
.explain-row {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    margin-bottom: 1.4rem;
}
.explain-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1rem 1.2rem;
}
.explain-icon { font-size: 1.5rem; margin-bottom: 0.4rem; }
.explain-title { font-size: 0.82rem; font-weight: 700; color: var(--text-dark); margin-bottom: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }
.explain-body  { font-size: 0.84rem; color: var(--text-mid); line-height: 1.5; }

/* ── KPI cards ── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.4rem;
}
.kpi-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.1rem 1.3rem;
}
.kpi-label { font-size: 0.76rem; font-weight: 600; color: var(--text-light); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.4rem; }
.kpi-value { font-size: 2rem; font-weight: 700; color: var(--text-dark); line-height: 1; }
.kpi-sub   { font-size: 0.78rem; color: var(--text-mid); margin-top: 0.35rem; }

/* ── Pill badges ── */
.pill-safe {
    display: inline-block;
    background: var(--mint-soft); color: #2e7d52;
    border: 1px solid var(--mint);
    padding: 0.15rem 0.6rem; border-radius: 20px;
    font-size: 0.74rem; font-weight: 600;
}
.pill-alert {
    display: inline-block;
    background: var(--rose-soft); color: #c0395a;
    border: 1px solid var(--rose);
    padding: 0.15rem 0.6rem; border-radius: 20px;
    font-size: 0.74rem; font-weight: 600;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0.4rem;
    border-bottom: 1px solid var(--border) !important;
    background: transparent !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 8px !important;
    color: var(--text-mid) !important;
    font-weight: 600 !important;
    font-size: 0.87rem !important;
    padding: 0.5rem 1rem !important;
}
.stTabs [aria-selected="true"] {
    background: var(--lav-soft) !important;
    border-color: var(--lavender) !important;
    color: #6b3fa0 !important;
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

/* ── Alerts/info ── */
.stAlert { border-radius: 10px !important; }
</style>
""", unsafe_allow_html=True)

# ── Plotly pastel theme helper ────────────────────────────────────────────────
PASTEL_COLORS = ["#c8b6e2", "#a3c4f3", "#a8d5ba", "#f9c89b", "#f4a7b9", "#b5dde8"]

def pastel_layout(fig, title=""):
    fig.update_layout(
        paper_bgcolor="white",
        plot_bgcolor="#fafafa",
        font=dict(family="Inter", color="#3d3530", size=12),
        title=dict(text=title, font=dict(size=14, color="#3d3530")),
        margin=dict(l=16, r=16, t=40, b=16),
    )
    fig.update_xaxes(gridcolor="#f0ebe5", linecolor="#e8e0d8")
    fig.update_yaxes(gridcolor="#f0ebe5", linecolor="#e8e0d8")
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
        "Mode",
        ["Simulation (Test Dataset)", "Live Capture (Scapy)"],
        index=0,
        help="Simulation replays real attack data offline. Live Capture sniffs your actual network."
    )

    st.markdown("---")
    threshold = st.slider(
        "Alert Threshold",
        min_value=0.10, max_value=0.95,
        value=DEFAULT_ALERT_THRESHOLD, step=0.05,
        help="If attack probability > this value → flag as Suspicious."
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
    if st.button("⚡ Probe Localhost", use_container_width=True):
        threading.Thread(target=run_localhost_probe, daemon=True).start()
        st.toast("Safe probe dispatched to 127.0.0.1!")
    if st.button("🗑  Clear Logs", use_container_width=True):
        clear_database()
        st.success("Logs cleared!")
        st.rerun()

    auto_refresh = st.checkbox("Auto-refresh every 2s", value=True)


# ── Hero Banner ───────────────────────────────────────────────────────────────
engine_status = "🟢 Running" if st.session_state.engine_running else "⚪ Idle"
st.markdown(f"""
<div class="hero">
  <div class="hero-badge">Project Kavach · Abhishek Kothari · 24BCE2610</div>
  <div class="hero-title">🛡️ Kavach — AI Network Intrusion Detection</div>
  <p class="hero-sub">
    Kavach watches your network traffic in real time. It analyses each network
    "flow" (a stream of packets between two machines) and uses a trained AI model
    to decide: <strong>Is this normal traffic or an attack?</strong>
    Suspicious flows are flagged instantly with a confidence score. &nbsp;·&nbsp; Status: {engine_status}
  </p>
</div>
""", unsafe_allow_html=True)

# ── What does each section show? ─────────────────────────────────────────────
st.markdown("""
<div class="explain-row">
  <div class="explain-card">
    <div class="explain-icon">📊</div>
    <div class="explain-title">KPI Cards</div>
    <div class="explain-body">Total flows checked, how many were flagged as attacks, current detection rate, and how fast traffic is arriving.</div>
  </div>
  <div class="explain-card">
    <div class="explain-icon">📡</div>
    <div class="explain-title">Live Flow Stream</div>
    <div class="explain-body">Every network flow Kavach analyses — source IP, destination, protocol, and whether it's safe (green) or suspicious (pink).</div>
  </div>
  <div class="explain-card">
    <div class="explain-icon">🧠</div>
    <div class="explain-title">Model Insights</div>
    <div class="explain-body">Shows which network features (e.g. packet size, flow speed) the AI uses most to make its decisions, plus accuracy metrics.</div>
  </div>
</div>

<div class="novelty-card">
  <div class="novelty-header">✨ Novelty & Core Technical Highlights of Project Kavach</div>
  <div class="novelty-grid">
    <div class="novelty-item">
      <div class="novelty-item-title">🔒 Zero-Payload Inspection</div>
      <div class="novelty-item-body">Preserves complete user privacy and works across <strong>TLS / HTTPS encrypted traffic</strong> without packet decryption or deep-packet overhead.</div>
    </div>
    <div class="novelty-item">
      <div class="novelty-item-title">⚡ Live-to-Benchmark Parity</div>
      <div class="novelty-item-body">Bridges academic dataset (CICIDS2017) to <strong>real-time Scapy packet capture</strong> via strictly aligned 50-feature bidirectional flow computation.</div>
    </div>
    <div class="novelty-item">
      <div class="novelty-item-title">💡 Real-Time Explainable AI (XAI)</div>
      <div class="novelty-item-body">No black-box guesswork. Flags include <strong>driving feature attributions</strong> (inter-arrival time, packet length variance, TCP flags) per intrusion.</div>
    </div>
    <div class="novelty-item">
      <div class="novelty-item-title">🍃 Lightweight Edge Inference</div>
      <div class="novelty-item-body">Achieves sub-millisecond classification on <strong>commodity CPUs</strong> without requiring specialized GPU clusters or heavy appliances.</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Load data ─────────────────────────────────────────────────────────────────
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

# ── KPI row ───────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Flows Analysed", f"{total:,}", help="Total network flows checked since the engine started.")
with c2:
    st.metric("Attacks Detected", f"{suspicious:,}",
              delta=f"{rate:.1f}% of traffic" if total > 0 else None,
              delta_color="inverse")
with c3:
    st.metric("Safe Flows", f"{normal:,}")
with c4:
    st.metric("Throughput", f"{flows_per_sec:.1f} flows/s", help="Average flows per second in the last 10 seconds.")

st.markdown("<br>", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["📡 Live Flow Stream", "📊 Threat Analytics", "🧠 Model Insights"])

# ── TAB 1: Live Flow Stream ───────────────────────────────────────────────────
with tab1:
    st.markdown("**Every row below is one network flow** — a conversation between two machines. "
                "🟢 Safe flows are normal. 🔴 Suspicious flows are potential attacks.")

    if df_flows.empty:
        st.info("No data yet. Click **▶ Start Engine** in the sidebar to begin.")
    else:
        display = df_flows.head(100)[[
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "label", "confidence", "packets", "bytes",
        ]].copy()

        def highlight(val):
            if val == "Suspicious":
                return "background-color: #fde8ed; color: #c0395a; font-weight:600;"
            return "background-color: #e4f5eb; color: #2e7d52; font-weight:600;"

        styled = display.style.map(highlight, subset=["label"]).format({
            "confidence": "{:.1%}", "packets": "{:,}", "bytes": "{:,}"
        })
        try:
            st.dataframe(styled, use_container_width=True, height=430)
        except TypeError:
            st.dataframe(styled, height=430)

# ── TAB 2: Threat Analytics ───────────────────────────────────────────────────
with tab2:
    if df_flows.empty:
        st.info("Data will appear here once the engine is running.")
    else:
        a, b = st.columns(2)

        with a:
            st.markdown("**Traffic over time** — how many flows were safe vs suspicious each second.")
            try:
                df_t = df_flows.copy()
                df_t["second"] = pd.to_datetime(df_t["timestamp"]).dt.strftime("%H:%M:%S")
                agg = df_t.groupby(["second", "label"]).size().reset_index(name="count")
                fig = px.area(agg, x="second", y="count", color="label",
                              color_discrete_map={"Normal": "#a8d5ba", "Suspicious": "#f4a7b9"})
                st.plotly_chart(pastel_layout(fig, "Flow Activity Over Time"), use_container_width=True)
            except Exception as e:
                st.warning(f"Chart error: {e}")

        with b:
            st.markdown("**Top attack sources** — which source IPs triggered the most alerts.")
            susp = df_flows[df_flows["label"] == "Suspicious"]
            if susp.empty:
                st.success("✅ No suspicious IPs detected yet!")
            else:
                top = susp["src_ip"].value_counts().head(8).reset_index()
                top.columns = ["Source IP", "Alerts"]
                fig2 = px.bar(top, x="Source IP", y="Alerts",
                              color="Alerts", color_continuous_scale=["#fde8ed", "#f4a7b9", "#e05880"])
                st.plotly_chart(pastel_layout(fig2, "Top Suspicious IPs"), use_container_width=True)

        c, d = st.columns(2)
        with c:
            st.markdown("**Protocol split** — what types of traffic Kavach has seen.")
            proto = df_flows["protocol"].value_counts().reset_index()
            proto.columns = ["Protocol", "Count"]
            fig3 = px.pie(proto, values="Count", names="Protocol", hole=0.45,
                          color_discrete_sequence=PASTEL_COLORS)
            st.plotly_chart(pastel_layout(fig3, "Protocol Distribution"), use_container_width=True)

        with d:
            st.markdown("**Confidence spread** — how certain the AI was when flagging attacks.")
            if not susp.empty:
                fig4 = px.histogram(susp, x="confidence", nbins=15,
                                    color_discrete_sequence=["#c8b6e2"])
                st.plotly_chart(pastel_layout(fig4, "Detection Confidence"), use_container_width=True)
            else:
                st.info("No suspicious flows to show confidence for yet.")

# ── TAB 3: Model Insights ─────────────────────────────────────────────────────
with tab3:
    st.markdown(
        "Kavach uses a **Random Forest** model trained on the CICIDS2017 dataset — "
        "a benchmark dataset of real-world network attacks. Below are the results "
        "from testing on data the model had never seen before."
    )

    feat_img = MODELS_DIR / "feature_importances.png"
    cm_img   = MODELS_DIR / "confusion_matrix.png"
    roc_img  = MODELS_DIR / "roc_curve.png"

    i1, i2 = st.columns(2)
    with i1:
        if feat_img.exists():
            st.image(str(feat_img), caption="Which features matter most to the AI? (higher = more important)")
        else:
            st.info("Run `python -m src.train` to generate this chart.")
    with i2:
        if cm_img.exists():
            st.image(str(cm_img), caption="Confusion Matrix — how often the model got it right vs wrong.")
        elif roc_img.exists():
            st.image(str(roc_img), caption="ROC Curve — overall detection performance.")

    if METRICS_PATH.exists():
        st.markdown("---")
        st.markdown("#### 📈 Model Performance on Test Data")
        st.caption("These scores are from a held-out test set the model never trained on — so they reflect real-world performance.")
        with open(METRICS_PATH) as f:
            m = json.load(f)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Accuracy",  f"{m.get('accuracy',  0)*100:.1f}%", help="Overall correct predictions.")
        m2.metric("Precision", f"{m.get('precision', 0)*100:.1f}%", help="Of flows flagged as attacks, how many actually were?")
        m3.metric("Recall",    f"{m.get('recall',    0)*100:.1f}%", help="Of actual attacks, how many did we catch?")
        m4.metric("F1 Score",  f"{m.get('f1',        0)*100:.1f}%", help="Balance between Precision and Recall.")

        if "per_attack_recall" in m:
            st.markdown("#### 🔍 Detection Rate by Attack Type")
            st.caption("How well Kavach detects each specific type of network attack.")
            atk_df = pd.DataFrame([
                {"Attack Type": k, "Detection Rate": f"{v*100:.1f}%"}
                for k, v in m["per_attack_recall"].items()
            ])
            st.table(atk_df)


# ── Auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh and st.session_state.engine_running:
    time.sleep(2.0)
    st.rerun()

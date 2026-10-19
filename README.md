# 🛡️ Project Kavach — Network Intrusion Detection System

> **Developed by Abhishek Kothari — 24BCE2610**

---

## 📌 What is Project Kavach?

**Kavach** (meaning *Shield* in Hindi) is an AI-powered **Network Intrusion Detection System (NIDS)**.

It monitors live network traffic in real time, classifies each network flow as either **BENIGN** or an **ATTACK** using a trained Machine Learning model, and displays live alerts on a dashboard — all within seconds.

> 💡 Think of it as a **smart security guard** for your network that never sleeps.

---

## ✨ Core Novelty & Technical Innovation

Traditional intrusion detection systems rely on signature matching (failing against zero-day threats) or Deep Packet Inspection (DPI, which violates privacy and breaks on encrypted traffic). **Kavach introduces four key technical novelties:**

| # | Novelty Pillar | How Kavach Achieves It | Practical Impact |
|---|---|---|---|
| **1** | **Zero-Payload Behavioral Inspection** | Extracts pure bidirectional flow metadata (packet lengths, inter-arrival times, TCP flag distribution, and byte ratios) without inspecting payload data. | **100% Privacy-preserving** and inherently robust to modern **TLS / HTTPS encrypted traffic**. |
| **2** | **Live-to-Benchmark Feature Parity** | Bridges academic dataset training (CICIDS2017) to real-world live traffic by engineering exact 50-feature mathematical parity using Scapy in real time. | Solves the standard "academic lab model fails on live packet interfaces" dilemma. |
| **3** | **Real-Time Explainable AI (XAI)** | Integrates feature importance attribution directly into live inference alerts, highlighting the top 3-5 driving features per alert. | Security analysts immediately understand *why* an alert fired within milliseconds instead of relying on black-box predictions. |
| **4** | **Sub-Millisecond Edge Architecture** | Utilizes an optimized Random Forest architecture with balanced class weights rather than resource-heavy deep learning models. | Runs on **standard commodity hardware / CPU** without requiring expensive GPUs or dedicated ASIC hardware. |

---

## ⚖️ How Kavach Differs from Traditional Firewalls

While traditional firewalls act as **gatekeepers at the perimeter**, Kavach operates as an **intelligent, behavior-aware internal security analyst**. 

| Capability | 🧱 Traditional Firewalls (Packet Filtering / Stateful) | 🛡️ Project Kavach (AI Behavioral NIDS) |
|---|---|---|
| **Inspection Basis** | **Static 5-Tuple**: Checks Source IP, Destination IP, Protocol, Source Port, and Destination Port against predefined rule tables. | **Dynamic Behavioral Dynamics**: Computes 50+ bidirectional flow metrics (inter-arrival variance, packet size distribution, TCP flag ratios). |
| **Encrypted Traffic (HTTPS/TLS)** | **Blind or Invasive**: Cannot inspect payload without terminating TLS (costly SSL decryption / MITM). Once port 443 is open, attacks pass through. | **Zero-Payload Native**: Extracts statistical flow geometry *without* decryption. Detects attacks hiding inside TLS encrypted sessions. |
| **Zero-Day & Mutated Attacks** | **Fails**: Has no rules for unseen attack variants until signatures or manual rules are updated by vendors. | **Resilient**: Flags deviations from normal statistical baseline behavior, successfully surfacing zero-day variants. |
| **Port / Protocol Camouflage** | **Bypassed**: If malicious command-and-control (C2) or exfiltration traffic runs on permitted port 80/443, firewall allows it. | **Detected**: Identifies anomalous flow rates, abnormal byte ratios, and handshake abnormalities regardless of port. |
| **Internal Lateral Movement** | **Often Blind**: Firewalls monitor boundary perimeters; internal peer-to-peer compromise often goes unnoticed. | **Monitored**: Sniffs local subnet broadcast/interface traffic to catch internal reconnaissance and port scans. |
| **Decision Explainability** | **Binary / Opaque**: Simple "Deny by Rule #42" log with no contextual behavioral insight. | **Explainable AI (XAI)**: Attributes alerts to top driving statistical features (e.g., abnormally skewed forward/backward packet ratio). |

---

## 🧠 How the AI Model Works (In Plain English)

### 💡 The Intuition: The Behavioral Security Guard
Imagine a security guard standing at a building entrance. They don't open every visitor's private letters or bags (that would violate privacy and take too long). Instead, they watch **behavioral body language**:
- Is someone testing 50 locked doors in 3 seconds?
- Is someone running in circles at abnormal speeds?
- Are they sending out 1,000 requests without waiting for a reply?

**Kavach works the exact same way for network traffic:** It doesn't decrypt your passwords or inspect private messages. It measures the *rhythm, timing, packet length variance, and handshake ratios* of network conversations to identify attacks.

### ⚙️ The 5-Step Pipeline:

1. **Step 1: Raw Packet Sniffing (`src/capture.py`)**  
   Hooks into the physical network interface (Wi-Fi/Ethernet) via Scapy. Reads IP and TCP/UDP headers (source, destination, ports, flags, byte sizes) without reading packet bodies.

2. **Step 2: 5-Second Micro-Flow Aggregation (`src/flow_builder.py`)**  
   Packets are grouped into bidirectional conversations ("flows") between two machines. For each 5-second flow, Kavach calculates **50 deep statistical features**:
   - **Inter-Arrival Times (IAT):** Microsecond spacing between packets (automated bot attacks burst with inhuman precision).
   - **Packet Length Variance:** Human traffic has natural variance; DDoS and probe tools often spam uniform dummy packet sizes.
   - **Directional Byte Ratios:** Forward vs. backward packet ratios (e.g. DoS floods send millions of bytes inbound with zero replies).
   - **TCP Flag Counts:** Ratios of SYN, ACK, FIN, and RST flags (detects half-open SYN floods and stealth port scans).

3. **Step 3: Feature Scaling (`src/predictor.py`)**  
   Applies a pre-fitted `StandardScaler` to normalize all 50 features around mean 0 with unit variance. This prevents massive values (like 10,000,000 bytes) from drowning out small but critical signals (like 1 TCP SYN flag).

4. **Step 4: The 100-Tree Random Forest Committee (`src/train.py`)**  
   An ensemble of **100 independent Decision Trees** evaluates the flow features. Each tree asks yes/no questions (e.g., *"Is flow duration < 0.05s and backward packet count == 0?"*) and votes either **Safe (0)** or **Attack (1)**. Balanced class weights ensure rare cyber attacks are never ignored.

5. **Step 5: Confidence Scoring & Explainability (XAI)**  
   The votes from all 100 trees are aggregated into an **Attack Probability**:
   - If 94 out of 100 trees vote Attack $\rightarrow$ Confidence = 94.0%.
   - If Confidence > Sensitivity Threshold (default 50%), an alert is logged with the **top driving feature attributions** explaining *why* it was flagged.

---

## 🗺️ System Design Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LIVE NETWORK INTERFACE                        │
│                    (Wi-Fi / Ethernet — Scapy)                        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  Raw packets captured in real-time
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FLOW BUILDER  (flow_builder.py)                   │
│                                                                       │
│  Groups raw packets into 5-second network FLOWS                       │
│  Computes 50+ statistical features per flow:                          │
│  - Packet lengths, IAT (inter-arrival time), flags (SYN/ACK/FIN)     │
│  - Flow bytes/s, Flow packets/s, Forward/Backward packet stats        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  Feature vector (50 features per flow)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  PREDICTOR ENGINE  (predictor.py)                    │
│                                                                       │
│  1. Loads StandardScaler  →  Normalizes feature vector               │
│  2. Loads RandomForestClassifier  →  Predicts: BENIGN or ATTACK       │
│  3. Confidence score attached (e.g., 94.3% attack probability)        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  Prediction + confidence
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   ALERT LOGGER  (capture.py)                         │
│                                                                       │
│  ┌────────────────────┐     ┌──────────────────────────────────┐     │
│  │  SQLite DB         │     │  CSV Log File                    │     │
│  │  (alerts.db)       │     │  (live_alerts.csv)               │     │
│  │  Persists alerts   │     │  Exportable for analysis         │     │
│  └────────────────────┘     └──────────────────────────────────┘     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│               STREAMLIT DASHBOARD  (dashboard/app.py)                │
│                                                                       │
│  📊 Live attack rate gauge                                            │
│  📋 Real-time alert table (source IP, dest port, attack type)         │
│  📈 Traffic trend chart (benign vs attack over time)                  │
│  🔬 Feature importance chart (which features trigger alerts)          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Data & Training Flow

```
┌───────────────────────────────────────────────────────────┐
│            CICIDS2017 DATASET (Benchmark Dataset)          │
│      Real-world labeled network traffic (benign+attack)    │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────────┐
│               PREPROCESSING  (preprocess.py)               │
│  - Remove NaN/Inf values                                   │
│  - Encode labels (BENIGN=0, ATTACK=1)                      │
│  - Select 50 Scapy-computable features only                │
│  - Save as processed_cicids2017.parquet                    │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────────┐
│                 TRAINING  (train.py)                        │
│  - 80/20 stratified train/test split                       │
│  - StandardScaler fitted on training data                  │
│  - RandomForestClassifier (100 trees, balanced weights)    │
│  - Optional: RandomizedSearchCV hyperparameter tuning      │
│  - Saves: rf_model.joblib, scaler.joblib, features.json    │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────────┐
│               EVALUATION  (evaluate.py)                    │
│  - Confusion matrix                                        │
│  - ROC curve + AUC score                                   │
│  - Feature importance plot                                 │
│  - JSON metrics report                                     │
└───────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack & Why We Used Each Technology

| Technology | Role | Why We Chose It |
|------------|------|-----------------|
| **Python** | Core language | Rich ML/data science ecosystem (scikit-learn, pandas, numpy). Perfect for rapid ML prototyping and system integration. |
| **Scapy** | Packet capture | Industry-standard packet sniffing library. Gives raw access to TCP/UDP/IP headers to compute the exact same features as the CICIDS2017 dataset. |
| **scikit-learn (Random Forest)** | ML model | Random Forest is explainable, handles class imbalance well (via `class_weight='balanced'`), and performs excellently on tabular network flow data without needing a GPU. |
| **pandas + numpy** | Data processing | Essential for loading, transforming, and feature-engineering the large CICIDS2017 dataset efficiently. |
| **Streamlit** | Live dashboard | Turns a Python script into an interactive real-time web dashboard in minutes — perfect for hackathon demos. Auto-refreshes to show live alerts. |
| **SQLite** | Alert storage | Lightweight, zero-configuration database. Stores every alert persistently without needing a database server. |
| **joblib** | Model serialization | Efficiently saves/loads large sklearn models (faster than pickle for numpy arrays inside models). |
| **CICIDS2017 Dataset** | Training data | Gold-standard labeled network intrusion dataset from the Canadian Institute for Cybersecurity — contains 15+ attack types and benign traffic. |

---

## 🔄 User / Operator Flow

```
           ┌─────────────────────────────┐
           │  Security Analyst / Operator │
           └──────────────┬──────────────┘
                          │
          ┌───────────────▼──────────────────┐
          │  Step 1: Train the model          │
          │  python -m src.train              │
          │  (or skip if model exists)        │
          └───────────────┬──────────────────┘
                          │
          ┌───────────────▼──────────────────┐
          │  Step 2: Start live capture        │
          │  python -m src.capture            │
          │  Kavach starts sniffing the        │
          │  network interface in real-time    │
          └───────────────┬──────────────────┘
                          │
          ┌───────────────▼──────────────────┐
          │  Step 3: Open the dashboard        │
          │  streamlit run dashboard/app.py   │
          │  Open browser → localhost:8501    │
          └───────────────┬──────────────────┘
                          │
          ┌───────────────▼──────────────────┐
          │  Step 4: Monitor live alerts       │
          │  - See attack vs benign traffic   │
          │  - View source IPs flagged        │
          │  - Export CSV logs                │
          │  - Analyze feature importance     │
          └───────────────────────────────────┘
```

---

## 📊 Model Performance

The trained Random Forest model on CICIDS2017 achieves:

| Metric | Score |
|--------|-------|
| **Accuracy** | ~99% |
| **F1 Score (Attack class)** | ~0.98 |
| **AUC-ROC** | ~0.99 |

> ✅ Confusion matrix, ROC curve, and feature importance charts are saved to `models/` after training.

---

## 📁 Project Structure

```
kavach/
├── src/
│   ├── config.py        # All paths, feature list, thresholds
│   ├── preprocess.py    # Clean & prepare CICIDS2017 dataset
│   ├── train.py         # Model training pipeline
│   ├── evaluate.py      # Confusion matrix, ROC, metrics
│   ├── flow_builder.py  # Convert raw packets → feature vectors
│   ├── predictor.py     # Load model + run inference
│   ├── capture.py       # Live packet capture + alert logger
│   └── simulate.py      # Replay held-out test data (offline demo)
├── dashboard/
│   └── app.py           # Streamlit live dashboard
├── models/
│   ├── rf_model.joblib        # Trained classifier
│   ├── scaler.joblib          # Fitted StandardScaler
│   ├── features.json          # Canonical 50-feature list
│   ├── evaluation_metrics.json
│   ├── confusion_matrix.png
│   ├── roc_curve.png
│   └── feature_importances.png
├── data/
│   ├── processed_cicids2017.parquet
│   ├── held_out_test.parquet
│   ├── alerts.db        # SQLite alert store
│   └── live_alerts.csv
└── tests/
    ├── test_flow_builder.py
    └── test_pipeline.py
```

---

## 🚀 Getting Started

```bash
# Clone the repo
git clone https://github.com/AbhishekKothari511/kavach.git
cd kavach

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Train the model (downloads & processes CICIDS2017 sample automatically)
python -m src.train

# Start live capture (run as administrator for packet sniffing)
python -m src.capture

# Open the dashboard
streamlit run dashboard/app.py
```

---

*Project Kavach — A shield for your network · Abhishek Kothari — 24BCE2610*

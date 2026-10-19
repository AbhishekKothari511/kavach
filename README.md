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

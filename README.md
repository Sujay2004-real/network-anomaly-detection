# Network Traffic Anomaly Detection using Machine Learning

A machine learning-powered intrusion detection system (IDS) proof of concept. The system learns normal network behavior using unsupervised machine learning (Isolation Forest) on baseline benign network flows, and detects common anomalies (such as Port Scanning and DDoS attacks) in real-time.

## Features
- **Offline Training**: Learn normal traffic patterns using standard baseline data.
- **Unsupervised Anomaly Detection**: Employs an Isolation Forest model to isolate anomalies without needing labeled training data.
- **Realistic Dataset Playback**: Streams network flow records from the **CIC-IDS2017** dataset to simulate normal, PortScan, and DDoS behaviors.
- **Interactive Security Dashboard**: Real-time Streamlit dashboard showing:
  - System threat level & alert indicators.
  - Interactive packet rates & anomaly counts (Plotly).
  - Categorized alert logs with classification type, source/destination IPs, ports, and confidence score.
  - Controls to switch live simulation traffic profiles on-the-fly.

---

## Directory Structure
```text
network-anomaly-detection/
│
├── data/
│     ├── live_status.json      # Inter-process status exchange
│     ├── history.json          # Recent stats cache
│     └── alerts.json           # Live alerts feed
│
├── capture/
│     ├── __init__.py
│     └── simulator.py          # Real-time traffic simulation thread
│
├── features/
│     ├── __init__.py
│     └── extractor.py          # Scapy-to-flow feature aggregation
│
├── models/
│     ├── __init__.py
│     ├── detector.py           # Isolation Forest model wrapper
│     └── saved_model/          # Serialized scikit-learn artifacts
│
├── app/
│     └── dashboard.py          # Streamlit user interface
│
├── train.py                    # Script to train Isolation Forest on Monday normal traffic
├── detect.py                   # Script to run the detection pipeline in the background
├── requirements.txt            # System dependencies
└── README.md                   # This guide
```

---

## Getting Started

### 1. Prerequisite: Dataset Download
The dataset is downloaded and cached locally on your machine at:
`C:\Users\sujay\.cache\kagglehub\datasets\chethuhn\network-intrusion-dataset\versions\1`

### 2. Install Dependencies
Ensure you have installed the required python packages:
```bash
pip install -r requirements.txt
```

### 3. Train the Anomaly Detector
Train the Isolation Forest model on Monday's normal/benign traffic:
```bash
python train.py --sample-size 50000
```
This will fit the scaler and model, evaluate them on the training baseline (which should label ~98% of baseline traffic as normal, matching the contamination threshold of 0.02), and save the model under `models/saved_model`.

### 4. Launch the Dashboard
Run the Streamlit web dashboard:
```bash
streamlit run app/dashboard.py
```
This will open the dashboard in your web browser (usually at `http://localhost:8501`).

---

## How to Test and Run the Demo
1. Open the Dashboard in your browser.
2. In the sidebar controls, click **Start Detection Pipeline**. This will launch the background detector process (`detect.py`) automatically.
3. Observe the dashboard in **Normal** simulation mode. The threat status should show as **SAFE** (green), with a low anomaly ratio.
4. Toggle the radio buttons in the sidebar:
   - Select **PortScan**: The simulator will inject Port Scan flows from Tuesday/Friday CSV files. The model will flag the port scan events, the threat level will rise to **CRITICAL ATTACK** (red), and the security log will output alert records specifying "Potential Port Scan" and the attacking source IP.
   - Select **DDoS**: The simulator will inject DDoS flows from Friday's CSV file. The packet rate will spike dramatically (Plotly chart), and the model will trigger alert entries indicating "Potential DDoS / SYN Flood".

# 🛡️ DDoS Detection System

A high-performance Python-based Network DDoS Detection and Mitigation Pipeline that processes network packet captures (`.pcap`), extracts bidirectional flow features, classifies traffic into **Benign**, **Application Attack**, or **Volumetric Attack**, and exports automated firewall block rules (`iptables`).

---

## ⚡ Features

- 📂 **Bidirectional Flow Feature Extraction (`flow_extractor.py`)**:
  - Scapy-based PCAP parsing with deduplication.
  - Computes duration, forward/backward packet counts, packet rates, byte rates, packet length statistics (mean, std, min, max), TCP flags (SYN, ACK, RST), and endpoint metadata (`src_ip`, `dst_ip`).
  - Configurable flow window timeout and customizable noise filtering thresholds.
- 🤖 **Multi-Mode Machine Learning & Heuristic Classification (`predictor.py`)**:
  - Classifies traffic using a pre-trained scikit-learn model (`m2.pkl`).
  - Built-in **Heuristic Rule Classifier Fallback** if the model file is not present.
  - Identifies malicious source IPs while excluding designated host/server IPs.
- 📄 **Structured Reporting & Mitigation Export**:
  - Exports labeled flows to CSV (`predictions.csv`).
  - Generates structured JSON reports (`report.json`) with timestamps, classification metrics, and top attacker IPs.
  - Auto-generates executable firewall mitigation scripts (`block_rules.sh` with `iptables -A INPUT -s <IP> -j DROP`).

---

## 🛠️ Requirements

- Python 3.8+
- Requirements:
  - `pandas`
  - `numpy`
  - `scapy`
  - `joblib`
  - `scikit-learn`

Install dependencies:
```bash
pip install pandas numpy scapy joblib scikit-learn
```

---

## 🚀 Usage

### 1. Packet Capture (Linux / Mininet environment)

Capture live network traffic on an interface (e.g., `s1-eth1`):
```bash
./capture.sh
# or manually:
sudo tcpdump -i s1-eth1 -w live.pcap
```

### 2. Complete Detection Pipeline

Run the full extraction and prediction workflow:
```bash
./run_detection.sh [optional_pcap_file]
```
Example:
```bash
./run_detection.sh live.pcap
```

### 3. Step-by-Step CLI Execution

#### Step 3A: Flow Feature Extraction (`flow_extractor.py`)
```bash
python flow_extractor.py --input live.pcap --output flows.csv --timeout 0.5
```
**Options:**
- `-i`, `--input`: Input PCAP file (default: `live.pcap`)
- `-o`, `--output`: Output CSV file path (default: `flows.csv`)
- `-t`, `--timeout`: Flow aggregation timeout window in seconds (default: `0.5`)
- `--min-packets`: Min packets/s threshold for noise filter (default: `20`)
- `--min-syn`: Min SYN flag count threshold for noise filter (default: `2`)

#### Step 3B: Attack Prediction & Reporting (`predictor.py`)
```bash
python predictor.py --input flows.csv --model m2.pkl --server-ip 10.0.0.5
```
**Options:**
- `-m`, `--model`: Trained model file (default: `m2.pkl`)
- `-i`, `--input`: Input flows CSV (default: `flows.csv`)
- `-o`, `--output`: Output prediction CSV (default: `predictions.csv`)
- `-j`, `--json-report`: JSON report export path (default: `report.json`)
- `-s`, `--server-ip`: Server IP to exclude from attacker lists (default: `10.0.0.5`)
- `-r`, `--export-rules`: Firewall block rules output script (default: `block_rules.sh`)

---

## 📊 Generated Output Files

1. `flows.csv`: Extracted flow statistics and feature vectors.
2. `predictions.csv`: Flow records augmented with model `prediction` labels (`0`: App Attack, `1`: Benign, `2`: Volumetric Attack).
3. `report.json`: High-level summary of network analysis, counts, and top attacker classifications.
4. `block_rules.sh`: Executable bash script containing `iptables DROP` rules for identified attack sources.

---

## 🛡️ Mitigation Example (`block_rules.sh`)

To apply generated firewall block rules to block detected attackers:
```bash
chmod +x block_rules.sh
sudo ./block_rules.sh
```

# 🛡️ DDoS Detection & Mitigation System

<p align="center">
  <strong>Machine Learning-Based Network Traffic Analysis, Attack Detection & Automated Mitigation</strong>
</p>

<p align="center">
  A Python-based cybersecurity pipeline for detecting, classifying, and mitigating Distributed Denial-of-Service (DDoS) attacks from network traffic.
</p>

---

## 📌 Overview

The **DDoS Detection & Mitigation System** is a Python-based network security pipeline that analyzes captured network traffic, extracts bidirectional flow-level features, classifies traffic using machine learning and heuristic rules, identifies potential attack sources, and generates firewall rules for mitigation.

The system processes `.pcap` network captures and classifies traffic into three categories:

* 🟢 **Benign Traffic**
* 🟠 **Application Attack**
* 🔴 **Volumetric Attack**

The detection results can be exported as structured reports, while identified malicious IP addresses can be converted into `iptables` firewall rules for defensive mitigation.

---

## ⚡ Key Features

### 📂 Bidirectional Flow Feature Extraction

The `flow_extractor.py` module uses **Scapy** to parse PCAP files and construct bidirectional network flows.

It extracts features including:

* Flow duration
* Forward and backward packet counts
* Packet rates
* Byte rates
* Packet length statistics
* Mean, standard deviation, minimum, and maximum packet lengths
* TCP SYN, ACK, and RST flag counts
* Source and destination IP information
* Configurable flow timeout
* Noise filtering based on packet and SYN thresholds
* Packet deduplication

---

### 🤖 Machine Learning & Heuristic Classification

The `predictor.py` module provides multi-mode traffic classification.

It can:

* Load a pre-trained **scikit-learn** model
* Classify network flows into attack categories
* Fall back to a **heuristic rule-based classifier** when the model is unavailable
* Identify potentially malicious source IP addresses
* Exclude configured server/host IP addresses from attacker lists

### Classification Labels

```text
0 → Application Attack
1 → Benign
2 → Volumetric Attack
```

---

### 📊 Structured Reporting

The system generates detailed machine-readable outputs containing:

* Traffic classification results
* Detection statistics
* Attack counts
* Top attacker IP addresses
* Analysis timestamps

Generated reports include:

```text
predictions.csv
report.json
```

---

### 🛡️ Automated Mitigation

Identified malicious source IP addresses can be converted into Linux firewall rules.

Example:

```bash
iptables -A INPUT -s <ATTACKER_IP> -j DROP
```

These rules are exported to:

```text
block_rules.sh
```

The generated script can then be reviewed and executed by an authorized administrator.

---

# 🏗️ System Architecture

```text
                 ┌──────────────────────┐
                 │   Network Traffic    │
                 │       (.pcap)        │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Flow Extraction    │
                 │  flow_extractor.py   │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Feature Vectors    │
                 │      flows.csv       │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Traffic Classification│
                 │    predictor.py      │
                 └──────────┬───────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          🟢 Benign    🟠 App Attack  🔴 Volumetric
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Attacker IP Analysis│
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Firewall Rule Export │
                 │   block_rules.sh     │
                 └──────────────────────┘
```

---

# 🔄 Detection Workflow

The complete pipeline follows these stages:

### 1️⃣ Capture

Network traffic is collected from a network interface or supplied as a `.pcap` file.

### 2️⃣ Extract

Packets are grouped into bidirectional flows.

### 3️⃣ Feature Engineering

Statistical and TCP-level characteristics are extracted from each flow.

### 4️⃣ Classify

The machine-learning model or heuristic fallback classifies each flow.

### 5️⃣ Analyze

Malicious flows are analyzed to identify potential attack sources.

### 6️⃣ Report

Detection results are exported to CSV and JSON formats.

### 7️⃣ Mitigate

Firewall rules are generated for identified malicious source IP addresses.

---

# 🛠️ Technology Stack

| Technology      | Purpose                             |
| --------------- | ----------------------------------- |
| 🐍 Python       | Core implementation                 |
| 🕵️ Scapy       | Packet and network traffic analysis |
| 📊 Pandas       | Data processing                     |
| 🔢 NumPy        | Numerical operations                |
| 🤖 Scikit-learn | Machine learning classification     |
| 💾 Joblib       | Model loading                       |
| 🐧 Linux        | Network and firewall environment    |
| 🔥 iptables     | Traffic mitigation                  |

---

# 📂 Project Structure

```text
DDOS-Detection/
│
├── 📄 README.md
├── 🐍 flow_extractor.py
├── 🐍 predictor.py
├── 🐍 run_cic.py
│
├── 🔧 capture.sh
├── 🚀 run_detection.sh
│
├── 📊 flows.csv
│
└── 🚫 .gitignore
```

---

# 🛠️ Requirements

* Python 3.8+
* Linux environment recommended for packet capture and firewall mitigation

### Python Dependencies

* `pandas`
* `numpy`
* `scapy`
* `joblib`
* `scikit-learn`

Install the dependencies:

```bash
pip install pandas numpy scapy joblib scikit-learn
```

---

# 🚀 Usage

## 1. Capture Network Traffic

In a Linux/Mininet environment, capture traffic using:

```bash
./capture.sh
```

Or manually:

```bash
sudo tcpdump -i s1-eth1 -w live.pcap
```

---

## 2. Run the Complete Detection Pipeline

```bash
./run_detection.sh [optional_pcap_file]
```

Example:

```bash
./run_detection.sh live.pcap
```

The complete workflow is:

```text
PCAP
 ↓
Flow Extraction
 ↓
Feature Generation
 ↓
Traffic Classification
 ↓
Attacker Identification
 ↓
Report Generation
 ↓
Firewall Rule Generation
```

---

# 🔬 Step-by-Step Execution

## Step 3A — Flow Feature Extraction

Run:

```bash
python flow_extractor.py --input live.pcap --output flows.csv --timeout 0.5
```

### Available Options

| Option            | Description              | Default     |
| ----------------- | ------------------------ | ----------- |
| `-i`, `--input`   | Input PCAP file          | `live.pcap` |
| `-o`, `--output`  | Output CSV file          | `flows.csv` |
| `-t`, `--timeout` | Flow aggregation timeout | `0.5`       |
| `--min-packets`   | Minimum packet threshold | `20`        |
| `--min-syn`       | Minimum SYN threshold    | `2`         |

---

## Step 3B — Attack Prediction & Reporting

Run:

```bash
python predictor.py --input flows.csv --model m2.pkl --server-ip 10.0.0.5
```

### Available Options

| Option                 | Description          | Default           |
| ---------------------- | -------------------- | ----------------- |
| `-m`, `--model`        | Trained model file   | `m2.pkl`          |
| `-i`, `--input`        | Input flow CSV       | `flows.csv`       |
| `-o`, `--output`       | Prediction CSV       | `predictions.csv` |
| `-j`, `--json-report`  | JSON report          | `report.json`     |
| `-s`, `--server-ip`    | Server IP to exclude | `10.0.0.5`        |
| `-r`, `--export-rules` | Firewall rule script | `block_rules.sh`  |

---

# 📊 Generated Output Files

| File              | Description                                                      |
| ----------------- | ---------------------------------------------------------------- |
| `flows.csv`       | Extracted network-flow statistics and feature vectors            |
| `predictions.csv` | Flow records with predicted traffic categories                   |
| `report.json`     | Structured summary of detection results and attacker information |
| `block_rules.sh`  | Generated `iptables` rules for identified attack sources         |

---

# 🛡️ Applying Mitigation Rules

The generated firewall rules should be reviewed before execution.

Make the script executable:

```bash
chmod +x block_rules.sh
```

Then apply the rules:

```bash
sudo ./block_rules.sh
```

> ⚠️ **Security Notice:** Firewall rules can affect network connectivity. Only execute generated rules in an authorized testing or production environment where you have permission to modify firewall configuration.

---

# 🎯 Project Objectives

The project aims to demonstrate an end-to-end approach to defensive network security by combining:

* Network packet analysis
* Flow-based feature extraction
* Machine learning
* Heuristic detection
* Attack classification
* Attacker identification
* Structured security reporting
* Automated firewall mitigation

---

# 🔮 Future Improvements

Potential extensions include:

* [ ] Real-time traffic monitoring
* [ ] Deep learning-based traffic classification
* [ ] Web-based monitoring dashboard
* [ ] Real-time security alerts
* [ ] Automated model retraining
* [ ] Additional attack categories
* [ ] Network traffic visualization
* [ ] SIEM integration
* [ ] Containerized deployment
* [ ] Distributed DDoS detection

---

# 👥 Project

**DDoS Detection & Mitigation System**

A collaborative cybersecurity project focused on applying **network traffic analysis, machine learning, and automated mitigation techniques** to detect and respond to DDoS activity.

---

## ⭐ What This Project Demonstrates

```text
Network Security
       +
Packet Analysis
       +
Feature Engineering
       +
Machine Learning
       +
Attack Classification
       +
Attacker Identification
       +
Automated Mitigation
```

### 🛡️ From raw network packets to actionable security rules.

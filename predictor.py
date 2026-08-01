import os
import sys
import json
import argparse
from datetime import datetime, timezone
import pandas as pd
import numpy as np


def parse_args():
    parser = argparse.ArgumentParser(description="Predict DDoS attack flows using trained ML model or fallback heuristics.")
    parser.add_argument("-m", "--model", default="m2.pkl", help="Path to trained model file (default: m2.pkl)")
    parser.add_argument("-i", "--input", default="flows.csv", help="Input flows CSV file (default: flows.csv)")
    parser.add_argument("-o", "--output", default="predictions.csv", help="Output predictions CSV file (default: predictions.csv)")
    parser.add_argument("-j", "--json-report", default="report.json", help="Path to export JSON report (default: report.json)")
    parser.add_argument("-s", "--server-ip", default="10.0.0.5", help="Server/Host IP to exclude from attacker list (default: 10.0.0.5)")
    parser.add_argument("-r", "--export-rules", default="block_rules.sh", help="Path to export firewall block rules script (default: block_rules.sh)")
    parser.add_argument("--min-packets", type=float, default=20.0, help="Noise filter min packets/s threshold (default: 20)")
    parser.add_argument("--min-syn", type=int, default=2, help="Noise filter min SYN count threshold (default: 2)")
    return parser.parse_args()


def heuristic_predict(df_features):
    preds = []
    for _, row in df_features.iterrows():
        pkts_s = row.get("Flow Packets/s", 0)
        syn_cnt = row.get("SYN Flag Count", 0)
        bytes_s = row.get("Flow Bytes/s", 0)

        if pkts_s > 500 or bytes_s > 500000:
            preds.append(2)
        elif syn_cnt > 10 or pkts_s > 100:
            preds.append(0)
        else:
            preds.append(1)
    return np.array(preds)


def main():
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] Input flows file '{args.input}' not found. Please run flow_extractor.py first.")
        sys.exit(1)

    print(f"[INFO] Loading flows from '{args.input}'...")
    df = pd.read_csv(args.input)

    if df.empty:
        print("[WARN] Flows CSV is empty. No flows to evaluate.")
        sys.exit(0)

    df = df.replace([np.inf, -np.inf], 0)
    df = df.fillna(0)

    features = [
        "Protocol",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Packet Length Mean",
        "Packet Length Std",
        "Max Packet Length",
        "Min Packet Length",
        "SYN Flag Count",
        "ACK Flag Count",
        "RST Flag Count"
    ]

    missing = [col for col in features if col not in df.columns]
    if missing:
        print("[ERROR] Missing required feature columns:", missing)
        sys.exit(1)

    df = df[
        (df["Flow Packets/s"] > args.min_packets) |
        (df["SYN Flag Count"] > args.min_syn)
    ].copy()

    if df.empty:
        print("[INFO] No flows remaining after noise filtering.")
        sys.exit(0)

    X = df[features]

    print("\n[STATS] Feature Stats:")
    print(f"  - Max Flow Packets/s: {X['Flow Packets/s'].max():.2f}")
    print(f"  - Max Flow Bytes/s:   {X['Flow Bytes/s'].max():.2f}")
    print(f"  - Max SYN Count:      {X['SYN Flag Count'].max()}")

    model = None
    if os.path.exists(args.model):
        try:
            import joblib
            print(f"\n[INFO] Loading ML model from '{args.model}'...")
            model = joblib.load(args.model)
            preds = model.predict(X)
            prediction_mode = "Machine Learning Model"
        except Exception as e:
            print(f"[WARN] Could not load model '{args.model}': {e}")
            print("[INFO] Falling back to heuristic classifier...")
            preds = heuristic_predict(X)
            prediction_mode = "Heuristic Rule Classifier (Fallback)"
    else:
        print(f"\n[WARN] Model file '{args.model}' not found.")
        print("[TIP] Provide your trained model file as 'm2.pkl' or use -m <path>.")
        print("[INFO] Running with Heuristic Rule Classifier...")
        preds = heuristic_predict(X)
        prediction_mode = "Heuristic Rule Classifier (Fallback)"

    df["prediction"] = preds

    df.to_csv(args.output, index=False)
    print(f"[SUCCESS] Saved predictions to '{args.output}'")

    benign = df[df["prediction"] == 1]
    app_attack = df[df["prediction"] == 0]
    vol_attack = df[df["prediction"] == 2]

    print("\n[SUMMARY] Detection Summary:")
    print(f"  - Classification Mode: {prediction_mode}")
    print(f"  - Total Flows Evaluated: {len(df)}")
    print(f"  - Benign Flows:          {len(benign)}")
    print(f"  - Application Attacks:   {len(app_attack)}")
    print(f"  - Volumetric Attacks:    {len(vol_attack)}")

    attacks = df[df["prediction"] != 1]
    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": prediction_mode,
        "total_flows": len(df),
        "benign_flows": len(benign),
        "app_attack_flows": len(app_attack),
        "volumetric_attack_flows": len(vol_attack),
        "attack_detected": len(attacks) > 0,
        "attacker_ips": {}
    }

    if len(attacks) == 0:
        print("\n[SUCCESS] No attack detected.")
    else:
        print("\n[ALERT] ATTACK DETECTED!")

        attacker_scores = {}

        if "src_ip" in attacks.columns:
            for _, row in attacks.iterrows():
                src = row["src_ip"]
                packets = row["Total Fwd Packets"]
                attacker_scores[src] = attacker_scores.get(src, 0) + packets

            sorted_attackers = sorted(attacker_scores.items(), key=lambda x: x[1], reverse=True)

            attackers = [ip for ip, _ in sorted_attackers if ip != args.server_ip]

            print(f"\n[ATTACKERS] Top Attacker IPs (excluding host {args.server_ip}):")
            for ip in attackers[:5]:
                print(f"  - {ip}")

            print("\n[CLASSIFICATION] Attack Type per IP:")
            firewall_rules = ["#!/bin/bash", "# Auto-generated DDoS Mitigation Script", ""]

            for ip in attackers[:5]:
                ip_data = df[df["src_ip"] == ip]
                ip_attacks = ip_data[ip_data["prediction"] != 1]

                if len(ip_attacks) == 0:
                    continue

                majority_pred = ip_attacks["prediction"].value_counts().idxmax()

                if majority_pred == 0:
                    label = "APPLICATION_ATTACK"
                elif majority_pred == 2:
                    label = "VOLUMETRIC_ATTACK"
                else:
                    label = "BENIGN"

                print(f"  - {ip} -> {label}")

                report_data["attacker_ips"][ip] = {
                    "attack_type": label,
                    "score": attacker_scores.get(ip, 0)
                }

                firewall_rules.append(f"echo 'Blocking attacker IP: {ip} ({label})'")
                firewall_rules.append(f"sudo iptables -A INPUT -s {ip} -j DROP")

            if args.export_rules:
                with open(args.export_rules, "w") as f:
                    f.write("\n".join(firewall_rules) + "\n")
                print(f"\n[SUCCESS] Exported firewall mitigation script to '{args.export_rules}'")
        else:
            print("[WARN] 'src_ip' column not present in input flows CSV.")

    if args.json_report:
        with open(args.json_report, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"[SUCCESS] Exported structured JSON report to '{args.json_report}'")


if __name__ == "__main__":
    main()


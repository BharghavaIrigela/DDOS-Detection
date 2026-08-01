import os
import sys
import argparse
import pandas as pd
from collections import defaultdict
import numpy as np


def parse_args():
    parser = argparse.ArgumentParser(description="Extract flow features from PCAP for DDoS detection.")
    parser.add_argument("-i", "--input", default="live.pcap", help="Input PCAP file (default: live.pcap)")
    parser.add_argument("-o", "--output", default="flows.csv", help="Output CSV file (default: flows.csv)")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Flow timeout in seconds (default: 0.5)")
    parser.add_argument("--min-packets", type=float, default=20.0, help="Minimum Flow Packets/s filter threshold (default: 20)")
    parser.add_argument("--min-syn", type=int, default=2, help="Minimum SYN Flag Count filter threshold (default: 2)")
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] Input PCAP file '{args.input}' not found.")
        sys.exit(1)

    print(f"[INFO] Processing PCAP '{args.input}' (FLOW TIMEOUT: {args.timeout}s)...")

    from scapy.all import PcapReader, IP, TCP, UDP

    flows = defaultdict(lambda: {
        "times": [],
        "fwd_pkts": 0,
        "bwd_pkts": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "lengths": [],
        "syn": 0,
        "ack": 0,
        "rst": 0
    })

    seen_packets = set()
    total_packets_parsed = 0

    try:
        for pkt in PcapReader(args.input):
            if IP not in pkt:
                continue

            total_packets_parsed += 1

            try:
                pkt_id = (
                    pkt[IP].src,
                    pkt[IP].dst,
                    pkt[IP].proto,
                    len(pkt),
                    int(pkt.time * 1e6)
                )
                if pkt_id in seen_packets:
                    continue
                seen_packets.add(pkt_id)

                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = int(pkt[IP].proto)

                sport = dport = 0
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport

                time_bucket = int(pkt.time // args.timeout)

                if (src, sport) <= (dst, dport):
                    key = (src, dst, sport, dport, proto, time_bucket)
                    direction = "fwd"
                else:
                    key = (dst, src, dport, sport, proto, time_bucket)
                    direction = "bwd"

                flow = flows[key]

                pkt_len = len(pkt)
                flow["times"].append(pkt.time)
                flow["lengths"].append(pkt_len)

                if direction == "fwd":
                    flow["fwd_pkts"] += 1
                    flow["fwd_bytes"] += pkt_len
                else:
                    flow["bwd_pkts"] += 1
                    flow["bwd_bytes"] += pkt_len

                if TCP in pkt:
                    flags = pkt[TCP].flags
                    if flags & 0x02:
                        flow["syn"] += 1
                    if flags & 0x10:
                        flow["ack"] += 1
                    if flags & 0x04:
                        flow["rst"] += 1

            except Exception:
                continue
    except Exception as e:
        print(f"[ERROR] Error reading PCAP file: {e}")
        sys.exit(1)

    print(f"[STATS] Packets parsed: {total_packets_parsed}")
    print(f"[STATS] Total unique flows extracted: {len(flows)}")

    data = []

    for key, flow in flows.items():
        times = flow["times"]

        if len(times) < 2:
            continue

        duration = max(times) - min(times)
        if duration <= 0:
            continue

        src, dst, sport, dport, proto, _ = key

        total_packets = flow["fwd_pkts"] + flow["bwd_pkts"]
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

        flow_pkts_s = total_packets / duration
        flow_bytes_s = total_bytes / duration

        lengths = flow["lengths"]

        data.append([
            proto,
            duration * 1e6,
            flow["fwd_pkts"],
            flow["bwd_pkts"],
            flow["fwd_bytes"],
            flow["bwd_bytes"],
            flow_bytes_s,
            flow_pkts_s,
            np.mean(lengths),
            np.std(lengths),
            np.max(lengths),
            np.min(lengths),
            flow["syn"],
            flow["ack"],
            flow["rst"],
            src,
            dst
        ])

    columns = [
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
        "RST Flag Count",
        "src_ip",
        "dst_ip"
    ]

    df = pd.DataFrame(data, columns=columns)

    raw_flow_count = len(df)

    df = df[
        (df["Flow Packets/s"] > args.min_packets) |
        (df["SYN Flag Count"] > args.min_syn)
    ]

    df.to_csv(args.output, index=False)

    print(f"[SUCCESS] Filtered {raw_flow_count - len(df)} noise flows. Retained {len(df)} active flows.")
    print(f"[SUCCESS] Flow feature extraction completed. Output saved to '{args.output}'")


if __name__ == "__main__":
    main()


from scapy.all import PcapReader, IP, TCP, UDP
import pandas as pd
from collections import defaultdict
import numpy as np

print("📂 Processing PCAP (FINAL ALIGNED - NO SCALER)...")

FLOW_TIMEOUT = 0.5  # small window → better attack visibility

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

for pkt in PcapReader("live.pcap"):
    if IP not in pkt:
        continue

    try:
        # 🔥 Deduplicate (Mininet flooding fix)
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

        # 🔥 time-based flow split
        time_bucket = int(pkt.time // FLOW_TIMEOUT)

        # 🔥 bidirectional flow
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

        # 🔥 TCP flags
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02:
                flow["syn"] += 1
            if flags & 0x10:
                flow["ack"] += 1
            if flags & 0x04:
                flow["rst"] += 1

    except:
        continue

print(f"🔢 Total flows: {len(flows)}")

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

    # 🔥 rates per second
    flow_pkts_s = total_packets / duration
    flow_bytes_s = total_bytes / duration

    lengths = flow["lengths"]

    data.append([
        proto,
        duration * 1e6,  # microseconds (important)
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
        src
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
    "src_ip"
]

df = pd.DataFrame(data, columns=columns)

# 🔥 Remove noise (VERY IMPORTANT)
df = df[
    (df["Flow Packets/s"] > 20) |
    (df["SYN Flag Count"] > 2)
]

df.to_csv("flows.csv", index=False)

print("✅ flows.csv generated (FINAL WORKING VERSION 🚀)")
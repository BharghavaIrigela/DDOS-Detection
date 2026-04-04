import pandas as pd
import joblib
import numpy as np

print("📥 Loading model...")

model = joblib.load("m2.pkl")

print("📂 Loading flows.csv...")
df = pd.read_csv("flows.csv")

# 🔥 CLEAN DATA
df = df.replace([np.inf, -np.inf], 0)
df = df.fillna(0)

# ✅ FEATURES (MATCH TRAINING)
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

# 🔥 CHECK FEATURES
missing = [col for col in features if col not in df.columns]
if missing:
    print("❌ Missing columns:", missing)
    exit()

X = df[features]

# 🔍 DEBUG
print("\n🔍 Feature Stats:")
print("Max Flow Packets/s:", X["Flow Packets/s"].max())
print("Max Flow Bytes/s:", X["Flow Bytes/s"].max())
print("Max SYN Count:", X["SYN Flag Count"].max())

# 🔥 REMOVE NOISE FLOWS
df = df[
    (df["Flow Packets/s"] > 20) |
    (df["SYN Flag Count"] > 2)
]

X = df[features]

print("\n🤖 Predicting...")
preds = model.predict(X)

df["prediction"] = preds

# ✅ LABEL COUNTS
benign = df[df["prediction"] == 1]
app_attack = df[df["prediction"] == 0]
vol_attack = df[df["prediction"] == 2]

print("\n📊 Summary:")
print(f"Benign flows: {len(benign)}")
print(f"Application attacks: {len(app_attack)}")
print(f"Volumetric attacks: {len(vol_attack)}")

# 🚨 ATTACK DETECTION
attacks = df[df["prediction"] != 1]

if len(attacks) == 0:
    print("\n✅ No attack detected")
else:
    print("\n🚨 ATTACK DETECTED!")

    # 🔥 FIND ATTACKERS BASED ON TRAFFIC VOLUME
    attacker_scores = {}

    for _, row in attacks.iterrows():
        src = row["src_ip"]
        packets = row["Total Fwd Packets"]
        attacker_scores[src] = attacker_scores.get(src, 0) + packets

    # 🔥 SORT ATTACKERS
    sorted_attackers = sorted(attacker_scores.items(), key=lambda x: x[1], reverse=True)

    # 🔥 REMOVE SERVER
    attackers = [ip for ip, _ in sorted_attackers if ip != "10.0.0.5"]

    print("\n🔥 Attacker IPs:")
    for ip in attackers[:5]:
        print(ip)

    # 🔥 MAJORITY ATTACK TYPE (FIXED)
    print("\n📌 Attack Type per IP:")

    for ip in attackers[:5]:
        ip_data = df[df["src_ip"] == ip]

        # consider only attack flows
        ip_attacks = ip_data[ip_data["prediction"] != 1]

        if len(ip_attacks) == 0:
            continue

        # 🔥 majority voting
        majority_pred = ip_attacks["prediction"].value_counts().idxmax()

        if majority_pred == 0:
            label = "APPLICATION_ATTACK"
        elif majority_pred == 2:
            label = "VOLUMETRIC_ATTACK"
        else:
            label = "BENIGN"

        print(f"{ip} → {label}")
#!/bin/bash

PCAP_FILE="${1:-live.pcap}"

echo "📊 Extracting flows from '$PCAP_FILE'..."
python3 flow_extractor.py -i "$PCAP_FILE"

echo "🤖 Running DDoS prediction..."
python3 predictor.py -i flows.csv
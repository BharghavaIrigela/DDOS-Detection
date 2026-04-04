#!/bin/bash

echo "🚀 Starting packet capture..."

sudo tcpdump -i s1-eth1 -w live.pcap

echo "✅ Capture saved to live.pcap"
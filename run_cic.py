from cicflowmeter.flow_session import generate_flows

print("📂 Generating flows using CICFlowMeter...")

flows = generate_flows("live.pcap")

flows.to_csv("flows.csv", index=False)

print("✅ flows.csv generated successfully")
h1 tcpreplay --mbps=10 --loop=50 -i h1-eth0 h1_syn.pcap &
h2 tcpreplay --mbps=10 --loop=50 -i h2-eth0 h2_syn.pcap &



h3 tcpreplay --mbps=8 --loop=50 -i h3-eth0 h3_dns.pcap &

h6 while true; do curl -s http://10.0.0.5 > /dev/null; done &
#!/usr/bin/python3
from scapy.all import *
import sys
import math

if len(sys.argv) != 4:
    print("Usage: measure-webserver.py <input-file> <server-ip> <server-port>")
    sys.exit(1)

pcap_filename = sys.argv[1]
server_ip = sys.argv[2]
server_port = int(sys.argv[3])

load_layer("http")
processed_file = rdpcap(pcap_filename)
sessions = processed_file.sessions()

request_times = {}
latencies = []

for session in sessions:
    for packet in sessions[session]:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if packet.haslayer(HTTPRequest) and dst_ip == server_ip and dst_port == server_port:
                request_times[(src_ip, src_port, dst_ip, dst_port)] = packet.time
            elif packet.haslayer(HTTPResponse) and src_ip == server_ip and src_port == server_port:
                key = (dst_ip, dst_port, src_ip, src_port)
                if key in request_times:
                    latency = packet.time - request_times[key]
                    latencies.append(latency)
                    del request_times[key]

def calculate_percentiles(latencies, percentiles):
    sorted_latencies = sorted(latencies)
    results = []
    for percentile in percentiles:
        index = int(math.ceil(percentile / 100.0 * len(sorted_latencies)) - 1)
        results.append(sorted_latencies[index])
    return results

def calculate_kl_divergence(): return calculate_kl_divergence(latencies, average_latency)

if latencies:
    average_latency = sum(latencies) / len(latencies)
    percentiles = calculate_percentiles(latencies, [25, 50, 75, 95, 99])
	kl_divergence = calculate_kl_divergence() , average_latency
    print(f"AVERAGE LATENCY: {average_latency:.5f}")
    print(f"PERCENTILES: {', '.join(f'{p:.5f}' for p in percentiles)}")
	print(f"KL DIVERGENCE: {kl_divergence:.5f}")
else:
    print("No HTTP request-response pairs found.")
#!/usr/bin/python3
from scapy.all import *
import sys
import time
import math

def calculate_percentiles(latencies, percentiles):
    latencies.sort()
    results = []
    for percentile in percentiles:
        index = int(math.ceil((percentile / 100.0) * len(latencies))) - 1
        results.append(latencies[max(0, min(index, len(latencies) - 1))])
    return results

def exponential_cdf(x, rate):
    return 1 - math.exp(-rate * x)

def calculate_kl_divergence(measured, modeled):
    kl_divergence = 0
    for p, q in zip(measured, modeled):
        if p > 0 and q > 0:
            kl_divergence += p * math.log2(p / q)
    return kl_divergence

def main(pcap_filename, server_ip, server_port):
    load_layer("http")  # load the HTTP layer
    processed_file = rdpcap(pcap_filename)  # read in the pcap file

    requests = {}
    latencies = []

    for packet in processed_file:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if packet.haslayer(HTTPRequest) and dst_ip == server_ip and dst_port == server_port:
                # Record request time
                requests[(src_ip, src_port, dst_ip, dst_port)] = packet.time
            elif packet.haslayer(HTTPResponse) and src_ip == server_ip and src_port == server_port:
                # Match response with request
                request_key = (dst_ip, dst_port, src_ip, src_port)
                if request_key in requests:
                    latency = packet.time - requests[request_key]
                    latencies.append(latency)
                    del requests[request_key]  # Remove matched request

    if not latencies:
        print("No HTTP request-response pairs found.")
        return

    average_latency = sum(latencies) / len(latencies)
    percentiles_values = calculate_percentiles(latencies, [25, 50, 75, 95, 99])

    print(f"AVERAGE LATENCY: {average_latency:.5f}")
    print("PERCENTILES: " + ', '.join(f"{p:.5f}" for p in percentiles_values))
    
    # Calculate measured distribution
    num_buckets = 10
    max_latency = max(latencies)
    bucket_size = max_latency / num_buckets
    measured_distribution = [0] * num_buckets
    for latency in latencies:
        bucket_index = int(latency // bucket_size)
        if bucket_index == num_buckets:
            bucket_index -= 1  # Handle maximum value
        measured_distribution[bucket_index] += 1
    measured_distribution = [x / len(latencies) for x in measured_distribution]

    # Calculate modeled distribution
    rate = 1.0 / float(average_latency)
    modeled_distribution = []
    for i in range(num_buckets):
        lower_bound = i * bucket_size
        upper_bound = (i + 1) * bucket_size if i < num_buckets - 1 else float('inf')
        lower_cdf = exponential_cdf(lower_bound, rate)
        upper_cdf = exponential_cdf(upper_bound, rate)
        modeled_distribution.append(upper_cdf - lower_cdf)

    # Calculate KL Divergence
    kl_divergence = calculate_kl_divergence(measured_distribution, modeled_distribution)

    print(f"KL DIVERGENCE: {kl_divergence:.5f}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: measure-webserver.py <input-file> <server-ip> <server-port>")
        sys.exit(1)

    pcap_filename = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = int(sys.argv[3])

    main(pcap_filename, server_ip, server_port)

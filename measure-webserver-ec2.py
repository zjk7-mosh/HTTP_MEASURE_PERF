#!/usr/bin/python3
from scapy.all import *
import sys
import math

def exponential_cdf(x, rate):
    return 1 - math.exp(-rate * x)

def calculate_kl_divergence(measured_dist, modeled_dist):
    kl_divergence = 0
    for p, q in zip(measured_dist, modeled_dist):
        if p > 0 and q > 0:
            kl_divergence += p * math.log(p / q)
    return kl_divergence

def calculate_percentiles(latencies, percentiles):
    sorted_latencies = sorted(latencies)
    results = []
    for percentile in percentiles:
        index = int(math.ceil(percentile / 100.0 * len(sorted_latencies)) - 1)
        results.append(sorted_latencies[index])
    return results

def main():
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

    if latencies:
        average_latency = sum(latencies) / len(latencies)
        average_latency = float(average_latency)  # Convert EDecimal to float

        percentiles = calculate_percentiles(latencies, [25, 50, 75, 95, 99])

        # Bucketing for measured distribution
        max_latency = max(latencies)
        bucket_size = max_latency / 10
        bucket_counts = [0] * 10
        for latency in latencies:
            index = min(int(latency / bucket_size), 9)
            bucket_counts[index] += 1
        measured_dist = [count / len(latencies) for count in bucket_counts]

        # Exponential model distribution
        rate = 1.0 / average_latency
        modeled_dist = []
        for i in range(10):
            lower_bound = i * bucket_size
            upper_bound = lower_bound + bucket_size
            if i == 9:  # Adjusting for the last bucket
                upper_bound = float('inf')
            modeled_dist.append(exponential_cdf(upper_bound, rate) - exponential_cdf(lower_bound, rate))

        kl_divergence = calculate_kl_divergence(measured_dist, modeled_dist)

        print(f"AVERAGE LATENCY: {average_latency:.5f}")
        print(f"PERCENTILES: {', '.join(f'{p:.5f}' for p in percentiles)}")
        print(f"KL DIVERGENCE: {kl_divergence:.5f}")
    else:
        print("No HTTP request-response pairs found.")

if __name__ == "__main__":
    main()

#!/usr/bin/python3
from scapy.all import *
import sys
import math

def calculate_percentiles(latencies, percentiles):
    latencies.sort()
    results = []
    for percentile in percentiles:
        index = int(math.ceil((percentile / 100.0) * len(latencies))) - 1
        results.append(latencies[max(0, min(index, len(latencies) - 1))])
    return results

def main(pcap_filename, server_ip, server_port):
    load_layer("http")  # load the HTTP layer
    processed_file = rdpcap(pcap_filename)  # read in the pcap file
    sessions = processed_file.sessions()  # get the list of sessions

    request_response_times = []

    for session in sessions:
        request_time = None
        response_time = None

        for packet in sessions[session]:
            if packet.haslayer(TCP) and packet[IP].dst == server_ip and packet[TCP].dport == server_port:
                if HTTPRequest in packet:
                    request_time = packet.time
                elif HTTPResponse in packet and request_time is not None:
                    response_time = packet.time
                    latency = response_time - request_time
                    request_response_times.append(latency)
                    request_time = None  # Reset for next request-response pair

    if not request_response_times:
        print("No HTTP request-response pairs found.")
        return

    average_latency = sum(request_response_times) / len(request_response_times)
    percentiles = calculate_percentiles(request_response_times, [25, 50, 75, 95, 99])

    print(f"AVERAGE LATENCY: {average_latency:.5f}")
    print("PERCENTILES: " + ', '.join(f"{p:.5f}" for p in percentiles))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: measure-webserver.py <input-file> <server-ip> <server-port>")
        sys.exit(1)

    pcap_filename = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = int(sys.argv[3])

    main(pcap_filename, server_ip, server_port)

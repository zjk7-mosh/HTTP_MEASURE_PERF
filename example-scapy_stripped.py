#!/usr/bin/python3 
from scapy.all import *
import sys
import time
import math

load_layer("http") # make sure to load the HTTP layer or your code will silently fail
pcap_filename = "pcap2.pcap" # name of the pcap file to load 
processed_file = rdpcap(pcap_filename)  # read in the pcap file 
sessions = processed_file.sessions()    #  get the list of sessions 
for session in sessions:                   
    for packet in sessions[session]:    # for each packet in each session
        if packet.haslayer(TCP):        # check if the packet is a TCP packet
            source_ip = packet[IP].src   # note that a packet is represented as a python hash table with keys corresponding to 
            dest_ip = packet[IP].dst     #  layer field names and the values of the hash table as the packet field values.
            if (packet.haslayer(HTTP)):  # test for an HTTP packet 
                if HTTPRequest in packet:   
                    arrival_time = packet.time # get unix time of the packet
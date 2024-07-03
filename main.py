import os
import socket
import struct
import time
from scapy.all import *

try:
    from scapy.all import *
except ImportError:
    print("Scapy is not installed. Installing...")
    os.system("pip install scapy")
    print("Scapy installed successfully.")
    from scapy.all import *

# Rest of your code here

def get_network_interfaces():
    interfaces = []
    for iface in os.listdir('/sys/class/net/'):
        interfaces.append(iface)
    return interfaces

def print_packet_info(packet, detailed=False):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet.protocol
    if not detailed:
        print(f"Packet captured: {src_ip} -> {dst_ip} ({protocol})")
    else:
        src_port = packet.sport
        dst_port = packet.dport
        packet_size = len(packet)
        payload = packet.payload
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"Packet Captured: {src_ip} --> {dst_ip} ({protocol})")
        print(f"Source IP Address: {src_ip}")
        print(f"Destination IP Address: {dst_ip}")
        print(f"Source Port Number: {src_port}")
        print(f"Destination Port Number: {dst_port}")
        print(f"Protocol: {protocol}")
        print(f"Packet Size: {packet_size} bytes")
        print(f"Payload: {payload}")
        print(f"Timestamp: {timestamp}")

def main():
    print("Packet Sniffer Tool")
    print("------------------")
    while True:
        print("1. Start Sniffing")
        print("2. Quit")
        choice = input("Enter your choice: ")
        if choice == "1":
            interfaces = get_network_interfaces()
            print("Available Network Interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"{i+1}. {iface}")
            iface_choice = int(input("Enter the interface number: ")) - 1
            iface = interfaces[iface_choice]
            packet_limit = int(input("Enter the number of packets to scan: "))
            print(f"Sniffing on interface {iface}...")
            sniff(iface=iface, count=packet_limit, prn=lambda packet: print_packet_info(packet, detailed=False))
            while True:
                print("1. Detailed Analysis")
                print("2. Continue Sniffing")
                analysis_choice = input("Enter your choice: ")
                if analysis_choice == "1":
                    sniff(iface=iface, count=1, prn=lambda packet: print_packet_info(packet, detailed=True))
                elif analysis_choice == "2":
                    break
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
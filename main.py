import os  # Provides functions to interact with the operating system.
import time  # Provides various time-related functions.

try:
    from scapy.all import *  # Import all functions and classes from Scapy, a powerful packet manipulation library.
except ImportError:
    print("Scapy is not installed. Installing...")  # Print a message if Scapy is not installed.
    os.system("pip install scapy")  # Install Scapy using pip if it's not already installed.
    print("Scapy installed successfully.")  # Print a message after successful installation.
    from scapy.all import *  # Import Scapy again after installation.

# Check if npcap is installed and set the appropriate sniffing interface
try:
    from scapy.arch.windows import get_windows_if_list

    def get_npcap_interface(ifname):
        for i in get_windows_if_list():
            if i["name"] == ifname:
                return i.get("pcap_name", ifname)
        raise ValueError(f"Interface '{ifname}' not found in npcap interfaces list")

except ImportError:
    print("npcap is not installed. Ensure it is installed for proper functionality.")
    exit(1)

def get_network_interfaces():
    interfaces = get_windows_if_list()  # Get the list of interfaces from Windows
    return [iface['name'] for iface in interfaces]  # Extract and return the names

def print_packet_info(packet, detailed=False):
    """
    Prints information about a captured packet.
    Args:
        packet: A Scapy packet object
        detailed: A boolean indicating whether to print detailed information (default: False)
    """
    if Ether in packet:
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        eth_type = packet[Ether].type
        print(f"Ethernet Frame captured: {eth_src} -> {eth_dst} (Type: {eth_type})")
        if detailed:
            print(f"Payload: {packet.payload}")

    if ARP in packet:
        arp_src_ip = packet[ARP].psrc
        arp_dst_ip = packet[ARP].pdst
        arp_src_mac = packet[ARP].hwsrc
        arp_dst_mac = packet[ARP].hwdst
        print(f"ARP Packet captured: {arp_src_ip} -> {arp_dst_ip}")
        if detailed:
            print(f"Source MAC Address: {arp_src_mac}")
            print(f"Destination MAC Address: {arp_dst_mac}")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"IP Packet captured: {src_ip} -> {dst_ip} (Protocol: {protocol})")
        if detailed:
            print(f"Source Port Number: {packet.sport}")
            print(f"Destination Port Number: {packet.dport}")
            print(f"Packet Size: {len(packet)} bytes")
            print(f"Payload: {packet.payload}")
            print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")

    if ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        print(f"ICMP Packet captured: Type {icmp_type}, Code {icmp_code}")
        if detailed:
            print(f"Payload: {packet.payload}")

    if TCP in packet:
        tcp_src_port = packet[TCP].sport
        tcp_dst_port = packet[TCP].dport
        print(f"TCP Packet captured: {tcp_src_port} -> {tcp_dst_port}")
        if detailed:
            print(f"Flags: {packet[TCP].flags}")
            print(f"Payload: {packet.payload}")

    if UDP in packet:
        udp_src_port = packet[UDP].sport
        udp_dst_port = packet[UDP].dport
        print(f"UDP Packet captured: {udp_src_port} -> {udp_dst_port}")
        if detailed:
            print(f"Payload: {packet.payload}")

    if DNS in packet:
        dns_qname = packet[DNS].qd.qname
        print(f"DNS Packet captured: {dns_qname}")
        if detailed:
            print(f"Query Type: {packet[DNS].qd.qtype}")
            print(f"Response: {packet[DNS].an}")

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
            sniff(iface=get_npcap_interface(iface), count=packet_limit, prn=lambda packet: print_packet_info(packet, detailed=False))
            while True:
                print("1. Detailed Analysis")
                print("2. Continue Sniffing")
                analysis_choice = input("Enter your choice: ")
                if analysis_choice == "1":
                    sniff(iface=get_npcap_interface(iface), count=1, prn=lambda packet: print_packet_info(packet, detailed=True))
                elif analysis_choice == "2":
                    break
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

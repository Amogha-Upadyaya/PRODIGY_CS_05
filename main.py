import os  # Import the os module, which provides functions to interact with the operating system.
import time  # Import the time module, which provides various time-related functions.

try:
    from scapy.all import *  # Try importing all functions and classes from Scapy, a powerful packet manipulation library.
except ImportError:
    print("Scapy is not installed. Installing...")  # Print a message if Scapy is not installed.
    os.system("pip install scapy")  # Install Scapy using pip if it's not already installed.
    print("Scapy installed successfully.")  # Print a message after successful installation.
    from scapy.all import *  # Import Scapy again after installation.

def get_network_interfaces():
    interfaces = []  # Initialize an empty list to store network interfaces.
    for iface in os.listdir('/sys/class/net/'):  # List all items in the '/sys/class/net/' directory.
        interfaces.append(iface)  # Append each item (network interface) to the interfaces list.
    return interfaces  # Return the list of network interfaces.

def print_packet_info(packet, detailed=False):
    """
    Prints information about a captured packet.

    Args:
        packet: A Scapy packet object
        detailed: A boolean indicating whether to print detailed information (default: False)
    """
    # Ethernet Frames
    if Ether in packet:  # Check if the packet contains an Ethernet layer.
        eth_src = packet[Ether].src  # Get the source MAC address from the packet.
        eth_dst = packet[Ether].dst  # Get the destination MAC address from the packet.
        eth_type = packet[Ether].type  # Get the Ethernet type from the packet.
        if not detailed:
            print(f"Ethernet Frame captured: {eth_src} -> {eth_dst} (Type: {eth_type})")  # Print basic Ethernet frame information.
        else:
            print(f"Ethernet Frame captured: {eth_src} -> {eth_dst} (Type: {eth_type})")  # Print detailed Ethernet frame information.
            print(f"Source MAC Address: {eth_src}")
            print(f"Destination MAC Address: {eth_dst}")
            print(f"Ethernet Type: {eth_type}")
            print(f"Payload: {packet.payload}")

    # ARP Packets
    if ARP in packet:  # Check if the packet contains an ARP layer.
        arp_src_ip = packet[ARP].psrc  # Get the source IP address from the ARP packet.
        arp_dst_ip = packet[ARP].pdst  # Get the destination IP address from the ARP packet.
        arp_src_mac = packet[ARP].hwsrc  # Get the source MAC address from the ARP packet.
        arp_dst_mac = packet[ARP].hwdst  # Get the destination MAC address from the ARP packet.
        if not detailed:
            print(f"ARP Packet captured: {arp_src_ip} -> {arp_dst_ip}")  # Print basic ARP packet information.
        else:
            print(f"ARP Packet captured: {arp_src_ip} -> {arp_dst_ip}")  # Print detailed ARP packet information.
            print(f"Source MAC Address: {arp_src_mac}")
            print(f"Destination MAC Address: {arp_dst_mac}")
            print(f"Source IP Address: {arp_src_ip}")
            print(f"Destination IP Address: {arp_dst_ip}")

    # IP Packets
    if IP in packet:  # Check if the packet contains an IP layer.
        src_ip = packet[IP].src  # Get the source IP address from the packet.
        dst_ip = packet[IP].dst  # Get the destination IP address from the packet.
        protocol = packet[IP].proto  # Get the protocol number from the IP layer.
        if not detailed:
            print(f"IP Packet captured: {src_ip} -> {dst_ip} (Protocol: {protocol})")  # Print basic IP packet information.
        else:
            src_port = packet.sport  # Get the source port from the packet.
            dst_port = packet.dport  # Get the destination port from the packet.
            packet_size = len(packet)  # Get the size of the packet.
            payload = packet.payload  # Get the payload of the packet.
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())  # Get the current timestamp.
            print(f"IP Packet captured: {src_ip} -> {dst_ip} (Protocol: {protocol})")  # Print detailed IP packet information.
            print(f"Source IP Address: {src_ip}")
            print(f"Destination IP Address: {dst_ip}")
            print(f"Source Port Number: {src_port}")
            print(f"Destination Port Number: {dst_port}")
            print(f"Packet Size: {packet_size} bytes")
            print(f"Payload: {payload}")
            print(f"Timestamp: {timestamp}")

    # ICMP Packets
    if ICMP in packet:  # Check if the packet contains an ICMP layer.
        icmp_type = packet[ICMP].type  # Get the ICMP type from the packet.
        icmp_code = packet[ICMP].code  # Get the ICMP code from the packet.
        if not detailed:
            print(f"ICMP Packet captured: Type {icmp_type}, Code {icmp_code}")  # Print basic ICMP packet information.
        else:
            print(f"ICMP Packet captured: Type {icmp_type}, Code {icmp_code}")  # Print detailed ICMP packet information.
            print(f"Payload: {packet.payload}")

    # TCP Packets
    if TCP in packet:  # Check if the packet contains a TCP layer.
        tcp_src_port = packet[TCP].sport  # Get the source port from the TCP packet.
        tcp_dst_port = packet[TCP].dport  # Get the destination port from the TCP packet.
        if not detailed:
            print(f"TCP Packet captured: {tcp_src_port} -> {tcp_dst_port}")  # Print basic TCP packet information.
        else:
            print(f"TCP Packet captured: {tcp_src_port} -> {tcp_dst_port}")  # Print detailed TCP packet information.
            print(f"Source Port: {tcp_src_port}")
            print(f"Destination Port: {tcp_dst_port}")
            print(f"Flags: {packet[TCP].flags}")
            print(f"Payload: {packet.payload}")

    # UDP Packets
    if UDP in packet:  # Check if the packet contains a UDP layer.
        udp_src_port = packet[UDP].sport  # Get the source port from the UDP packet.
        udp_dst_port = packet[UDP].dport  # Get the destination port from the UDP packet.
        if not detailed:
            print(f"UDP Packet captured: {udp_src_port} -> {udp_dst_port}")  # Print basic UDP packet information.
        else:
            print(f"UDP Packet captured: {udp_src_port} -> {udp_dst_port}")  # Print detailed UDP packet information.
            print(f"Source Port: {udp_src_port}")
            print(f"Destination Port: {udp_dst_port}")
            print(f"Payload: {packet.payload}")

    # Application Layer Packets
    # HTTP/HTTPS Packets
    if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):  # Check if the packet is an HTTP packet.
        print("HTTP Packet captured")  # Print that an HTTP packet was captured.
        if detailed:
            print(f"Payload: {packet.payload}")  # Print the payload if detailed information is requested.

    if TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):  # Check if the packet is an HTTPS packet.
        print("HTTPS Packet captured")  # Print that an HTTPS packet was captured.
        if detailed:
            print(f"Payload: {packet.payload}")  # Print the payload if detailed information is requested.

    # FTP Packets
    if TCP in packet and (packet[TCP].dport == 21 or packet[TCP].sport == 21):  # Check if the packet is an FTP packet.
        print("FTP Packet captured")  # Print that an FTP packet was captured.
        if detailed:
            print(f"Payload: {packet.payload}")  # Print the payload if detailed information is requested.

    # SMTP Packets
    if TCP in packet and (packet[TCP].dport == 25 or packet[TCP].sport == 25):  # Check if the packet is an SMTP packet.
        print("SMTP Packet captured")  # Print that an SMTP packet was captured.
        if detailed:
            print(f"Payload: {packet.payload}")  # Print the payload if detailed information is requested.

    # IMAP Packets
    if TCP in packet and (packet[TCP].dport == 143 or packet[TCP].sport == 143):  # Check if the packet is an IMAP packet.
        print("IMAP Packet captured")  # Print that an IMAP packet was captured.
        if detailed:
            print(f"Payload: {packet.payload}")  # Print the payload if detailed information is requested.

    # POP3 Packets
    if TCP in packet and (packet[TCP].dport == 110 or packet[TCP].sport == 110):  # Check if the packet is a POP3 packet.
        print("POP3 Packet captured")  # Print that a POP3 packet was captured.
        if detailed:
            print(f"Payload: {packet.payload}")  # Print the payload if detailed information is requested.

    # DNS Packets
    if DNS in packet:  # Check if the packet contains a DNS layer.
        dns_qname = packet[DNS].qd.qname  # Get the DNS query name from the packet.
        if not detailed:
            print(f"DNS Packet captured: {dns_qname}")  # Print basic DNS packet information.
        else:
            print(f"DNS Packet captured: {dns_qname}")  # Print detailed DNS packet information.
            print(f"Query Type: {packet[DNS].qd.qtype}")
            print(f"Response: {packet[DNS].an}")

    # DHCP Packets
    if DHCP in packet:  # Check if the packet contains a DHCP layer.
        dhcp_message_type = packet[DHCP].options[0][1]  # Get the DHCP message type from the packet.
        if not detailed:
            print(f"DHCP Packet captured: {dhcp_message_type}")  # Print basic DHCP packet information.
        else:
            print(f"DHCP Packet captured: {dhcp_message_type}")  # Print detailed DHCP packet information.
            print(f"Options: {packet[DHCP].options}")

def main():
    print("Packet Sniffer Tool")  # Print the title of the tool.
    print("------------------")  # Print a separator.
    while True:  # Start an infinite loop for the main menu.
        print("1. Start Sniffing")  # Print the option to start sniffing.
        print("2. Quit")  # Print the option to quit the program.
        choice = input("Enter your choice: ")  # Prompt the user to enter their choice.
        if choice == "1":  # If the user chooses to start sniffing:
            interfaces = get_network_interfaces()  # Get the list of network interfaces.
            print("Available Network Interfaces:")  # Print the available network interfaces.
            for i, iface in enumerate(interfaces):  # Iterate through the list of interfaces.
                print(f"{i+1}. {iface}")  # Print each interface with a corresponding number.
            iface_choice = int(input("Enter the interface number: ")) - 1  # Prompt the user to select an interface.
            iface = interfaces[iface_choice]  # Get the selected interface.
            packet_limit = int(input("Enter the number of packets to scan: "))  # Prompt the user to enter the number of packets to scan.
            print(f"Sniffing on interface {iface}...")  # Print a message indicating the selected interface.
            sniff(iface=iface, count=packet_limit, prn=lambda packet: print_packet_info(packet, detailed=False))  # Start sniffing packets on the selected interface and print basic information for each packet.
            while True:  # Start an infinite loop for the detailed analysis menu.
                print("1. Detailed Analysis")  # Print the option for detailed analysis.
                print("2. Continue Sniffing")  # Print the option to continue sniffing.
                analysis_choice = input("Enter your choice: ")  # Prompt the user to enter their choice.
                if analysis_choice == "1":  # If the user chooses detailed analysis:
                    sniff(iface=iface, count=1, prn=lambda packet: print_packet_info(packet, detailed=True))  # Sniff one packet and print detailed information.
                elif analysis_choice == "2":  # If the user chooses to continue sniffing:
                    break  # Break out of the detailed analysis menu.
        elif choice == "2":  # If the user chooses to quit:
            print("Exiting...")  # Print an exit message.
            break  # Break out of the main menu loop.
        else:
            print("Invalid choice. Please try again.")  # Print an error message for invalid choices.

if __name__ == "__main__":
    main()  # Call the main function to start the program.

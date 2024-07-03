import socket
import time
import struct

def get_mac_addr(interface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))
    data = s.recv(6)
    return ':'.join('%02x' % b for b in data)

def sniff(interface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))

    output_file = "packet_sniffer_log.txt"

    print(f"Started sniffing on {interface}")

    while True:
        data = s.recv(65535)  # Capture full packet

        # Parse Ethernet header
        dest_mac, src_mac, ether_proto = struct.unpack('! 6s 6s H', data[:14])
        dest_mac = ':'.join('%02x' % b for b in dest_mac)
        src_mac = ':'.join('%02x' % b for b in src_mac)

        # Parse IP header (assuming IPv4)
        if ether_proto == 0x0800:  # Check for IPv4
            ip_header = data[14:34]
            version_ihl = ip_header[0] & 0xF
            iph_len = ((version_ihl & 0xF) * 4)

            # Extract source and destination IPs
            src_ip = '.'.join(map(str, ip_header[12:16]))
            dst_ip = '.'.join(map(str, ip_header[16:20]))

            # Check for TCP or UDP protocol
            protocol = ip_header[9]
            if protocol == 6:
                protocol_name = "TCP"
            elif protocol == 17:
                protocol_name = "UDP"
            else:
                protocol_name = "Unknown"

            # Payload data (assuming ASCII encoding)
            payload = data[iph_len:].decode("ascii", errors="ignore")

            with open(output_file, "a") as file:
                file.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write(f"Source MAC: {src_mac}\n")
                file.write(f"Destination MAC: {dest_mac}\n")
                file.write(f"Source IP: {src_ip}\n")
                file.write(f"Destination IP: {dst_ip}\n")
                file.write(f"Protocol: {protocol_name}\n")
                file.write(f"Payload: {payload}\n")
                file.write("\n")

def choose_interface():
    interfaces = [socket.gethostbyname(socket.gethostname())]  # Get default interface
    print("Available interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")
    choice = int(input("Choose an interface (number): ")) - 1
    if 0 <= choice < len(interfaces):
        return interfaces[choice]
    else:
        print("Invalid choice. Exiting.")
        exit()

def main_menu():
    while True:
        print("\nPacket Sniffer Tool")
        print("1. Start Sniffing")
        print("2. Stop Sniffing (not supported)")
        print("3. Exit Program")
        choice = input("Enter your choice: ")
        if choice == '1':
            interface = choose_interface()
            sniff(interface)
        elif choice == '3':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main_menu()
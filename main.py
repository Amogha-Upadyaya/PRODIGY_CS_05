import scapy.all as scapy
import time

output_file = "packet_sniffer_log.txt"

def write_packet(packet):
    with open(output_file, "a") as file:
        file.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write(f"Source IP: {packet[scapy.IP].src if scapy.IP in packet else 'N/A'}\n")
        file.write(f"Destination IP: {packet[scapy.IP].dst if scapy.IP in packet else 'N/A'}\n")
        file.write(f"Protocol: {packet[scapy.IP].proto if scapy.IP in packet else 'N/A'}\n")
        file.write(f"Payload: {bytes(packet[scapy.Raw].load) if scapy.Raw in packet else 'N/A'}\n")
        file.write("\n")

def packet_callback(packet):
    write_packet(packet)

def start_sniffing(interface):
    print(f"Started sniffing on {interface}")
    scapy.sniff(iface=interface, prn=packet_callback, store=False)

def stop_sniffing():
    print("Stopped sniffing")

def choose_interface():
    interfaces = scapy.get_if_list()
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
        print("2. Stop Sniffing")
        print("3. Exit Program")
        choice = input("Enter your choice: ")
        if choice == '1':
            interface = choose_interface()
            start_sniffing(interface)
        elif choice == '2':
            stop_sniffing()
        elif choice == '3':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main_menu()

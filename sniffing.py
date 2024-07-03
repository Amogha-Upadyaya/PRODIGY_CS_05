import sys
from scapy.all import *

def get_interfaces():
    return [i.name for i in ifaces.values()]

def handle_packet(packet, log):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.protocol
        payload = packet.payload
        log.write(f"Packet captured: {src_ip} -> {dst_ip} ({protocol})\n")
        log.write(f"Payload: {payload}\n\n")

def start_sniffing(interface="eth0", verbose=False):
    logfile_name = f"sniffer_{interface}_log.txt"
    with open(logfile_name, 'w') as logfile:
        try:
            if verbose:
                print(f"Sniffing on interface {interface} with verbose mode enabled...")
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
            else:
                print(f"Sniffing on interface {interface}...")
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffing.py <interface> [verbose]")
        sys.exit(1)
    interface = sys.argv[1]
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
    start_sniffing(interface, verbose)
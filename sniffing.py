from scapy.all import sniff
def start_sniffing(iface, count):
    try:
        packets = sniff(count=count, iface=iface)
        return packets # Return captured packets for further processing (optional)
    except Exception as e:
        print(f"Error: {e}")
        return None # Indicate error (optional)
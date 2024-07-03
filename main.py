from scapy.all import sniff
import time

def start_sniffing(iface, count, timeout):
  """
  Sniffs packets on the specified interface with a timeout.

  Args:
      iface: The network interface name to capture packets from.
      count: The number of packets to capture (or capture until timeout).
      timeout: The maximum time (in seconds) to capture packets.
  """
  start_time = time.time()
  packets = []
  try:
    while len(packets) < count and time.time() - start_time < timeout:
      packet = sniff(count=1, iface=iface, timeout=1)[0]  # Capture one packet with timeout
      packets.append(packet)
  except Exception as e:
    print(f"Error: {e}")
  finally:
    # Optional cleanup (close sockets etc.)
    pass
  return packets

# Example usage
iface = "eth0"  # Replace with your desired interface
count = 10  # Capture 10 packets
timeout = 5  # Timeout after 5 seconds

captured_packets = start_sniffing(iface, count, timeout)

if captured_packets:
  print("Captured packets:")
  for packet in captured_packets:
    print(packet.summary())  # Display packet summary
else:
  print("No packets captured within the timeout.")

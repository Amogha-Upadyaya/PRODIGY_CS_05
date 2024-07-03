# sniffing.py

import socket

def get_interfaces():
  """
  Retrieves a list of available network interfaces.

  Returns:
      A list of interface names or None if no interfaces found.
  """
  try:
    # Use socket library to get interface names
    interfaces = [socket.gethostbyname(socket.gethostname())]  # Get default interface (optional)
    return interfaces
  except Exception as e:
    print(f"Error getting interfaces: {e}")
    return None

from scapy.all import sniff

def start_sniffing(iface, count):
  """
  Sniffs packets on the specified interface and displays the captured packets.

  Args:
      iface: The network interface name to capture packets from.
      count: The number of packets to capture.
  """
  try:
    packets = sniff(count=count, iface=iface)
    return packets  # Return captured packets for further processing (optional)
  except Exception as e:
    print(f"Error: {e}")
    return None  # Indicate error (optional)

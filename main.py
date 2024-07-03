from sniffing import start_sniffing  # Assuming "packet_sniffing.py" is renamed

# Get user input for interface and packet count
iface = input("Enter network interface (e.g., eth0): ")
count = int(input("Enter number of packets to capture: "))

# Start sniffing and capture packets
captured_packets = start_sniffing(iface, count)

# Process captured packets (optional)
if captured_packets:
  print(f"Captured {len(captured_packets)} packets:")
  # You can loop through captured_packets and process them further (e.g., print details)
else:
  print("No packets captured.")
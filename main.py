# main.py

from sniffing import get_interfaces, start_sniffing  # Import both functions

# Get available interfaces
interfaces = get_interfaces()

if not interfaces:
  print("Error: No network interfaces found.")
  exit()

# Print available interfaces
print("Available network interfaces:")
for i, interface in enumerate(interfaces):
  print(f"{i + 1}. {interface}")

# Get user input for interface selection and packet count
choice = int(input("Choose an interface (number): ")) - 1
if 0 <= choice < len(interfaces):
  iface = interfaces[choice]
else:
  print("Invalid choice. Exiting.")
  exit()

count = int(input("Enter number of packets to capture: "))

# Start sniffing and capture packets
captured_packets = start_sniffing(iface, count)

# Process captured packets (optional)
if captured_packets:
  print(f"Captured {len(captured_packets)} packets:")
  # You can loop through captured_packets and process them further (e.g., print details)
else:
  print("No packets captured.")

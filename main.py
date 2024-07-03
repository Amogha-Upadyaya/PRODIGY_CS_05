import sniffing

print("Welcome to the Network Packet Sniffer Tool!")
print("Please select an option:")
print("1. Start packet sniffing")
print("2. Quit")

while True:
    option = input("Enter your choice: ")
    if option == "1":
        interfaces = sniffing.get_interfaces()
        print("Available network interfaces:")
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")
        interface_choice = input("Enter the number of the interface to sniff: ")
        try:
            interface_choice = int(interface_choice)
            if 1 <= interface_choice <= len(interfaces):
                interface = interfaces[interface_choice - 1]
                verbose_choice = input("Do you want to enable verbose mode? (yes/no): ")
                if verbose_choice.lower() == "yes":
                    sniffing.start_sniffing(interface, verbose=True)
                else:
                    sniffing.start_sniffing(interface)
            else:
                print("Invalid interface choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    elif option == "2":
        print("Goodbye!")
        break
    else:
        print("Invalid option. Please try again.")
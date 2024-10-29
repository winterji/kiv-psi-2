from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff
import threading
import time

conf.iface = "eth0"

# Callback function for sniffing DHCP responses
def dhcp_sniffer(packet):
    if packet.haslayer(DHCP):
        print("Zachycena DHCP odpověď:")
        # packet.show()
        # print("----- print packet -------")
        # Attempt to extract gateway information if available
        gateway = packet.route()[2]
        print("Gateway: " + gateway)

# Function to send the DHCP Discover packet
def send_dhcp_discover():
    # Create the DHCP discover packet
    discover_packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr="fe:b7:82:07:28:ff") /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    # Send the DHCP discover packet
    sendp(discover_packet)
    print("DHCP Discover packet sent.")

# Function to run sniffing in a separate thread
def start_sniffing():
    sniff(filter="udp and port 68", prn=dhcp_sniffer, timeout=2, store=False)

# Create threads for parallel execution
sniffer_thread = threading.Thread(target=start_sniffing)

# Start both threads
sniffer_thread.start()
time.sleep(0.5)
send_dhcp_discover()

# Wait for both threads to complete
sniffer_thread.join()


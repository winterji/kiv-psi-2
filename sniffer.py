from scapy.all import sniff, DHCP

def dhcp_sniffer(packet):
    if packet.haslayer(DHCP):
        print("Zachycena DHCP odpověď:")
        packet.show()
        print("----- print packet -------")
        gateway = packet.route()[2]
        print(gateway)
        # print(default_gateway)

sniff(filter="udp and port 68", prn=dhcp_sniffer, timeout=10, store=False)

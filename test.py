from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp

def send_dhcp_discover():
    # Vytvoření DHCP discover paketu
    discover_packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr="12:34:56:78:9a:bc") /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    # Odeslání a zachycení odpovědi
    ans, _ = srp(discover_packet, timeout=5, verbose=False)
    if ans:
        for _, response in ans:
            print(response.show())  # Zobrazení obsahu odpovědi
    else:
        print("Žádná odpověď od DHCP serveru.")

send_dhcp_discover()
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff
import threading
import time
from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
import ipaddress

# Callback function for sniffing DHCP responses
def dhcp_sniffer(packet):
    if packet.haslayer(DHCP):
        print("Zachycena DHCP odpověď:")
        # packet.show()
        # print("----- print packet -------")
        # Attempt to extract gateway information if available
        try:
            gateway = packet.route()[2]
            print("Gateway: " + gateway)
            asyncio.run(discover_network_topology(gateway))
        except Exception as e:
            print(f"Error extracting gateway: {e}")

# Discover the network topology using SNMP
async def get_routing_table(router_ip, community="PSIPUB"):
    """Získá směrovací tabulku z routeru."""
    oid_routing_table = "1.3.6.1.2.1.4.21.1.1"  # IP Route Table OID
    routing_table = []
    try:
        error_indication, error_status, error_index, var_binds = await nextCmd(
            SnmpEngine(),
            CommunityData(community),
            await UdpTransportTarget.create((router_ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid_routing_table)),
            lexicographicMode=False,
        )
        print(var_binds)
        for var_bind in var_binds:
            route = str(var_bind[1])
            if route != "0.0.0.0":
                routing_table.append(route)
        print(routing_table)
        
        # if result is None:
        #     raise Exception(f"No SNMP response from {router_ip}")
        # for error_indication, error_status, error_index, var_binds in result:
        #     if error_indication or error_status:
        #         raise Exception(error_indication or error_status)
        #     print(var_binds)
        #     for var_bind in var_binds:
        #         routing_table.append(str(var_bind[1]))
        return routing_table
    except Exception as e:
        print(f"Failed to fetch routing table from {router_ip}: {e}")
        return []

async def discover_network_topology(start_router_ip, community="PSIPUB"):
    """Discover network topology based on SNMP routing information."""
    visited = set()
    topology = {}

    async def discover(router_ip):
        if router_ip in visited:
            return
        visited.add(router_ip)
        print(f"Discovering router: {router_ip}")
        topology[router_ip] = []
        routes = await get_routing_table(router_ip, community)
        for route in routes:
            try:
                ip = str(ipaddress.ip_address(route))
                topology[router_ip].append(ip)
                if ip not in visited:
                    await discover(ip)
            except ValueError:
                continue

    await discover(start_router_ip)
    print("\nNetwork Topology:")
    for router, neighbors in topology.items():
        print(f"{router} -> {', '.join(neighbors)}")

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


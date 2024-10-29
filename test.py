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
        try:
            gateway = packet.route()[2]
            print("Gateway: " + gateway)
            asyncio.run(discover_network_topology(gateway))
        except Exception as e:
            print(f"Error extracting gateway: {e}")

def convert_to_ipv4(raw_value):
    try:
        # Convert raw bytes to a list of integers
        ip_parts = [int(b) for b in raw_value]
        # Join the parts to form the IPv4 address
        return '.'.join(map(str, ip_parts))
    except Exception as e:
        print(f"Error converting value to IPv4: {e}")
        return None

async def get_arp_table(router_ip, community="PSIPUB"):
    oid_arp_table = "1.3.6.1.2.1.4.22"
    arp_ip_addr_prefix = "SNMPv2-SMI::mib-2.4.22.1.3."
    arp_table = []
    stop2 = False
    try:
        print("getting arp table")
        arp_objects = walkCmd(
            SnmpEngine(),
            CommunityData(community),
            await UdpTransportTarget.create((router_ip, 161), timeout=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid_arp_table)),
        )

        async for error_indication, error_status, error_index, var_binds in arp_objects:
            # Check for errors
            if error_indication:
                print(f"Error: {error_indication}")
                break
            elif error_status:
                print(f"SNMP Error: {error_status.prettyPrint()} at {error_index}")
                break
            # Process var_binds to extract OIDs and values
            for var_bind in var_binds:
                oid, value = var_bind  # Unpack ObjectType
                if str(oid).startswith(oid_arp_table):
                    if str(var_bind).startswith(arp_ip_addr_prefix):
                        addr = str(var_bind).split(" = ")[1]
                        arp_table.append(addr)
                        # print(f"OID: {oid}: {addr}")
                else:
                    print(f"stopping for {oid}")
                    stop2 = True
                    break
            if stop2:
                break
        print(arp_table)
        return arp_table
    except Exception as e:
        print(f"Failed to fetch arp table from {router_ip}: {e}")
        # print(e.with_traceback(e.__traceback__))
        return []

# Discover the network topology using SNMP
async def get_routing_table(router_ip, community="PSIPUB"):
    """Získá směrovací tabulku z routeru."""
    oid_routing_table = "1.3.6.1.2.1.4.21.1.1."  # IP Route Table OID
    routing_table = []
    stop = False
    try:
        print("getting route table")
        objects = walkCmd(
            SnmpEngine(),
            CommunityData(community),
            await UdpTransportTarget.create((router_ip, 161), timeout=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid_routing_table)),
            # lexicographicMode=False,
        )
        async for error_indication, error_status, error_index, var_binds in objects:
            # Check for errors
            if error_indication:
                print(f"Error: {error_indication}")
                break
            elif error_status:
                print(f"SNMP Error: {error_status.prettyPrint()} at {error_index}")
                break

            # Process var_binds to extract OIDs and values
            for var_bind in var_binds:
                oid, value = var_bind  # Unpack ObjectType
                if str(oid).startswith(oid_routing_table):  # Ensure it's within the OID range
                    addr = convert_to_ipv4(value)
                    # print(f"OID: {oid}, Value: {addr}")
                    if addr != "0.0.0.0" and addr.endswith(".0"):
                        routing_table.append(addr)  # Store the value as a string
                else:
                    print(f"Skipping unrelated OID: {oid}")
                    stop = True
                    break
            if stop:
                break
        print(routing_table)
        return routing_table
    except Exception as e:
        print(f"Failed to fetch routing table from {router_ip}: {e}")
        # print(e.with_traceback(e.__traceback__))
        return []

def submask(addr: str):
    print(f"net: {addr}")
    if addr.endswith(".0.0.0"):
        addr = addr.rsplit("0.0.0", maxsplit=1)[0]
    elif addr.endswith(".0.0"):
        addr = addr.rsplit("0.0", maxsplit=1)[0]
    elif addr.endswith(".0"):
        addr = addr.rsplit("0", maxsplit=1)[0]
    print(f"cut as {addr}")
    return addr

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
                # topology[router_ip].append(ip)
                if ip not in visited:
                    await discover(ip)
            except ValueError:
                continue
        arp = await get_arp_table(router_ip, community)
        net_addr = submask(str(router_ip))
        print(f"subnet mask for {router_ip}: " + net_addr)
        for dev in arp:
            if str(dev).startswith(net_addr):
                topology[router_ip].append(str(dev))

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


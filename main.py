from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp import debug
from scapy.all import conf, sr1, DHCP
import ipaddress
import asyncio

# Enabling debugging to see SNMP operations
# debug.setLogger(debug.Debug('all'))

def get_default_gateway():
    """Zjistí výchozí bránu pomocí DHCP."""
    conf.checkIPaddr = False
    dhcp_discover = DHCP() / DHCP(options=[("message-type", "discover")])
    response = sr1(dhcp_discover, timeout=5, verbose=False)
    if response:
        return response[0][1].options.get("router")
    return None

def snmp_get(host, oid, community="public"):
    """Vykoná SNMP GET dotaz na daný OID."""
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication:
            raise Exception(error_indication)
        elif error_status:
            raise Exception(f"{error_status.prettyPrint()} at {error_index}")
        else:
            return var_binds[0][1]
    except Exception as e:
        print(f"SNMP error on host {host}: {e}")
        return None

async def get_routing_table(router_ip, community="PSIPUB"):
    """Získá směrovací tabulku z routeru."""
    oid_routing_table = "1.3.6.1.2.1.4.21.1.1"  # IP Route Table
    routing_table = []
    try:
        for error_indication, error_status, error_index, var_binds in await getCmd(
            SnmpEngine(),
            CommunityData(community),
            await UdpTransportTarget.create((router_ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid_routing_table)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                raise Exception(error_indication or error_status)
            print(var_binds)
            for var_bind in var_binds:
                print(f"Raw SNMP response: {var_bind}")
                routing_table.append(str(var_bind[1]))
        return routing_table
    except Exception as e:
        print(f"Failed to fetch routing table from {router_ip}: {e}")
        return []

async def discover_network_topology(start_router_ip, community="PSIPUB"):
    """Rekurzivně zjišťuje topologii sítě."""
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
    return topology

async def main():
    """Hlavní funkce aplikace."""
    print("Zjišťuji výchozí bránu...")
    default_gateway = "10.0.2.254"
    if not default_gateway:
        print("Nepodařilo se zjistit výchozí bránu.")
        return

    print(f"Výchozí brána: {default_gateway}")
    print("Zjišťuji topologii sítě...")
    topology = await discover_network_topology(default_gateway, community="PSIPUB")
    print("\nTopologie sítě:")
    for router, neighbors in topology.items():
        print(f"{router} -> {', '.join(neighbors)}")

if __name__ == "__main__":
    asyncio.run(main())

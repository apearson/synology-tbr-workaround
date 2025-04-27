#!/usr/bin/env python3

import subprocess
import logging
import threading
import time
import os
from scapy.all import sniff, IPv6, ICMPv6ND_RA, ICMPv6NDOptRouteInfo, conf

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

# Store known routes for cleanup
known_routes = {}

# Get interface from environment or use default
IFACE = os.environ.get('IFACE', 'ovs_eth2')
TABLE = int(os.environ.get('TABLE', '2'))

def add_ipv6_route(prefix, prefix_len, gateway=None, dev=IFACE, table=TABLE):
    route = f"{prefix}/{prefix_len} dev {dev} table {table}"
    if gateway:
        route += f" via {gateway}"

    try:
        subprocess.run(['ip', '-6', 'route', 'add'] + route.split(), check=True)
        known_routes[prefix] = gateway
        logging.info(f"Added IPv6 route: {route}")
    except subprocess.CalledProcessError:
        logging.warning(f"Failed to add route or it already exists: {route}")

def remove_ipv6_route(prefix, prefix_len, dev=IFACE):
    route = f"{prefix}/{prefix_len} dev {dev}"
    try:
        subprocess.run(['ip', '-6', 'route', 'del'] + route.split(), check=True)
        logging.info(f"Removed IPv6 route: {route}")
    except subprocess.CalledProcessError:
        logging.warning(f"Failed to delete route: {route}")

def process_ra(packet):
    if ICMPv6ND_RA in packet:
        src = packet[IPv6].src
        logging.info(f"Received RA from {src}")

        # Check for RIO options
        for option in packet[ICMPv6ND_RA].payload:
            if option.type == 24:  # Route Information Option type
                prefix = option.prefix
                plen = option.plen
                lifetime = option.rtlifetime
                logging.info(f"Found RIO - Prefix: {prefix}/{plen} lifetime: {lifetime}s")

                # Only add routes with non-zero lifetime
                if lifetime > 0:
                    add_ipv6_route(prefix, plen, gateway=src)

        # Debug output
        logging.debug("Full packet details:")
        logging.debug(packet.show(dump=True))

def dead_neighbor_monitor():
    while True:
        try:
            process = subprocess.Popen(['ip', '-6', 'monitor', 'neigh'],
                                    stdout=subprocess.PIPE,
                                    universal_newlines=True)

            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                ip = parts[0]
                state = parts[-1]

                if state in ['FAILED', 'INCOMPLETE', 'STALE']:
                    for prefix, gw in list(known_routes.items()):
                        if ip == gw:
                            logging.warning(f"Neighbor {ip} is in state {state}, removing route to {prefix}")
                            remove_ipv6_route(prefix, 64)
                            known_routes.pop(prefix, None)

        except Exception as e:
            logging.error(f"Error monitoring neighbors: {e}")
            time.sleep(5)

def main():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        return

    logging.info("Starting IPv6 RA listener with dead neighbor detection...")

    # Start dead neighbor monitor in background
    t = threading.Thread(target=dead_neighbor_monitor, daemon=True)
    t.start()

    while True:
        try:
            # Use specific filter for ICMPv6 Router Advertisements (type 134)
            sniff(iface=IFACE,
                 filter="icmp6 and ip6[40] == 134",
                 prn=process_ra,
                 store=False,
                 timeout=None)
        except Exception as e:
            logging.error(f"Sniffing error: {e}")
            time.sleep(5)  # Wait before retrying

if __name__ == "__main__":
    main()

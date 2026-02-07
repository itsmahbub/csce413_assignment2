#!/usr/bin/env python3

import argparse
import ipaddress
import sys

from scapy.all import ARP, Ether, srp


# ----------------------------
# ARP Scan
# ----------------------------

def arp_scan(network):
    """
    Discover live hosts using ARP
    """

    print(f"[*] ARP scanning {network}...")

    # Build ARP request
    arp = ARP(pdst=network)

    # Broadcast Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    # Send and receive packets
    answered, _ = srp(packet, timeout=2, verbose=0)

    hosts = []

    for sent, received in answered:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return hosts


# ----------------------------
# Main
# ----------------------------

def main():

    parser = argparse.ArgumentParser(
        description="ARP-based host discovery"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target network (e.g. 172.20.0.0/24)"
    )

    args = parser.parse_args()


    # Validate network
    try:
        ipaddress.ip_network(args.target, strict=False)
    except ValueError:
        print("[!] Invalid network format")
        sys.exit(1)


    hosts = arp_scan(args.target)


    print("\n========== Live Hosts ==========\n")

    for h in hosts:
        print(f"{h['ip']:15}  {h['mac']}")

    print(f"\nTotal alive hosts: {len(hosts)}")


if __name__ == "__main__":
    main()

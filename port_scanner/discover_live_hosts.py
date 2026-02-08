#!/usr/bin/env python3

import socket
import ipaddress
import threading
import argparse
import sys


# ----------------------------
# Config
# ----------------------------

# Common ports used for host discovery (TCP "ping")
COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443,
    3306, 5000, 6379,
    8080, 8443, 9000
]



TIMEOUT = 1.0
MAX_THREADS = 100


# ----------------------------
# Host Check
# ----------------------------

def check_host(ip, alive_hosts, lock):
    """
    Try connecting to common ports.
    If any succeeds, host is alive.
    """

    for port in COMMON_PORTS:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)

            result = sock.connect_ex((str(ip), port))

            sock.close()

            if result == 0:

                with lock:

                    if str(ip) not in alive_hosts:
                        print(f"[+] Host alive: {ip}")
                        alive_hosts.append(str(ip))

                return

        except Exception:
            continue


# ----------------------------
# Network Scan
# ----------------------------

def scan_network(network):

    try:
        net = ipaddress.ip_network(network, strict=False)

    except ValueError:
        print("[!] Invalid network format")
        sys.exit(1)


    print(f"[*] Scanning {net}...")


    alive_hosts = []
    threads = []
    lock = threading.Lock()


    for ip in net.hosts():

        t = threading.Thread(
            target=check_host,
            args=(ip, alive_hosts, lock),
            daemon=True
        )

        threads.append(t)
        t.start()


        # Limit number of active threads
        if len(threads) >= MAX_THREADS:

            for t in threads:
                t.join()

            threads = []


    # Wait for remaining threads
    for t in threads:
        t.join()


    return alive_hosts


# ----------------------------
# Main
# ----------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Simple threaded network host scanner"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target network (e.g. 172.20.0.0/24)"
    )

    args = parser.parse_args()


    hosts = scan_network(args.target)


    print("\n========== Results ==========\n")

    for h in hosts:
        print(h)

    print(f"\nTotal alive hosts: {len(hosts)}")


if __name__ == "__main__":
    main()

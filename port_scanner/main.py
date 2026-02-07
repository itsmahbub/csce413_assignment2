#!/usr/bin/env python3

import socket
import argparse
import ipaddress
import sys
import threading
from queue import Queue


# ----------------------------
# Globals
# ----------------------------

task_queue = Queue()
results = {}
lock = threading.Lock()


# ----------------------------
# Core
# ----------------------------

def scan_port(target, port, timeout):
    """
    Check if TCP port is open
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        res = sock.connect_ex((target, port))

        sock.close()

        return res == 0

    except:
        return False


def worker(timeout):
    """
    Worker thread
    """

    while True:

        try:
            target, port = task_queue.get_nowait()

        except:
            break


        if scan_port(target, port, timeout):

            with lock:

                results[target].append(port)

                print(f"[+] {target}:{port} open")


        task_queue.task_done()


# ----------------------------
# Helpers
# ----------------------------

def parse_ports(port_str):

    ports = set()

    try:

        for part in port_str.split(","):

            part = part.strip()

            if "-" in part:

                start, end = part.split("-")

                start = int(start)
                end = int(end)

                if start < 1 or end > 65535 or start > end:
                    raise ValueError

                for p in range(start, end + 1):
                    ports.add(p)

            else:

                p = int(part)

                if p < 1 or p > 65535:
                    raise ValueError

                ports.add(p)

        if not ports:
            raise ValueError

        return sorted(ports)

    except:
        raise argparse.ArgumentTypeError(
            "Invalid port format"
        )


def parse_targets(target_str):

    targets = []

    # CIDR
    if "/" in target_str:

        try:
            net = ipaddress.ip_network(target_str, strict=False)

            for ip in net.hosts():
                targets.append(str(ip))

        except:
            print("[-] Invalid CIDR")
            sys.exit(1)

    # Hostname / IP
    else:

        try:
            ip = socket.gethostbyname(target_str)
            targets.append(ip)

        except:
            print("[-] Cannot resolve target")
            sys.exit(1)

    return targets


# ----------------------------
# CLI
# ----------------------------

def build_parser():

    parser = argparse.ArgumentParser(
        prog="port_scanner",
        description="Multithreaded TCP Port Scanner"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="IP, hostname, or CIDR"
    )

    parser.add_argument(
        "-p", "--ports",
        required=True,
        type=parse_ports,
        help="Ports (e.g. 1-1024,22,80)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout (default: 1s)"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of threads (default: 100)"
    )

    return parser


# ----------------------------
# Main
# ----------------------------

def main():

    parser = build_parser()
    args = parser.parse_args()

    targets = parse_targets(args.target)
    ports = args.ports
    timeout = args.timeout
    thread_count = args.threads


    print("=" * 50)
    print(" Multithreaded Port Scanner")
    print("=" * 50)
    print(f"[*] Targets : {len(targets)}")
    print(f"[*] Ports   : {len(ports)}")
    print(f"[*] Threads : {thread_count}")
    print("=" * 50)


    # Init results dict
    for t in targets:
        results[t] = []


    # Build task queue
    for target in targets:
        for port in ports:

            task_queue.put((target, port))


    print(f"[*] Total scans: {task_queue.qsize()}")


    # Start workers
    threads = []

    for _ in range(thread_count):

        t = threading.Thread(
            target=worker,
            args=(timeout,),
            daemon=True
        )

        threads.append(t)
        t.start()


    # Wait
    task_queue.join()


    # Summary
    print("\n" + "=" * 50)
    print(" Scan Summary")
    print("=" * 50)


    for target, open_ports in results.items():

        if open_ports:

            print(f"\n[+] {target}")

            for p in sorted(open_ports):
                print(f"    {p}/tcp open")

        # else:

        #     print(f"\n[-] {target}: No open ports")



if __name__ == "__main__":
    main()

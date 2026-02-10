import socket
import argparse
import ipaddress
import sys
import threading
from queue import Queue
import json

# ----------------------------
# Globals
# ----------------------------

task_queue = Queue()
results = {}
lock = threading.Lock()


# ----------------------------
# Core
# ----------------------------

def probe_http(sock):

    try:
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)

        return data.decode(errors="ignore")

    except:
        return None

def grab_banner(sock, timeout=2):

    try:
        sock.settimeout(timeout)

        data = sock.recv(1024)

        if data:
            return data.decode(errors="ignore").strip()

    except:
        pass

    return None

def guess_service(banner):


    b = banner.lower()

    if "ssh" in b:
        return "ssh"

    if "ftp" in b:
        return "ftp"

    if "smtp" in b:
        return "smtp"

    if "http" in b:
        return "http"

    if "nginx" in b:
        return "nginx"

    if "apache" in b:
        return "apache"

    if "redis" in b:
        return "redis"

    if "mysql" in b:
        return "mysql"

    return "unknown"


def scan_port(target, port, timeout):
    """
    Check if TCP port is open and try to identify service
    """

    result = {
        "open": False,
        "service": None,
        "banner": None
    }

    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if sock.connect_ex((target, port)) != 0:
            return result


        # Port is open
        result["open"] = True


        # Try banner grab
        banner = grab_banner(sock)
        
        if not banner:
            banner = probe_http(sock)



        if banner:
            result["banner"] = banner
            result["service"] = guess_service(banner)
            return result

    except:
        pass

    finally:
        if sock:
            sock.close()


    return result


def worker(timeout):
    """
    Worker thread
    """

    while True:

        try:
            target, port = task_queue.get_nowait()

        except:
            break


        scan_result = scan_port(target, port, timeout)
        if scan_result["open"]:

            with lock:
                results[target][port] = scan_result
                # print(f"[+] {target}:{port} open")


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
    """
    Parse targets:
      - IP
      - Hostname
      - CIDR
      - Comma-separated mix
    """

    targets = []


    parts = [p.strip() for p in target_str.split(",") if p.strip()]


    for part in parts:

        # CIDR
        if "/" in part:

            try:
                net = ipaddress.ip_network(part, strict=False)

                for ip in net.hosts():
                    targets.append(str(ip))

            except:
                print(f"[-] Invalid CIDR: {part}")
                sys.exit(1)


        # IP / Hostname
        else:

            try:
                ip = socket.gethostbyname(part)
                targets.append(ip)

            except:
                print(f"[-] Cannot resolve: {part}")
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
    # liveness_only = args.liveness_only


    print("=" * 50)
    print(" Multithreaded Port Scanner")
    print("=" * 50)
    print(f"[*] Targets : {len(targets)}")
    print(f"[*] Ports   : {len(ports)}")
    print(f"[*] Threads : {thread_count}")
    print("=" * 50)

    # Init results dict
    for t in targets:
        results[t] = {}


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


    for target, ports in results.items():
        if ports:
            print(f"\n[+] {target}")
            for p, info in sorted(ports.items()):
                line = f"    {p}/tcp open"
                # if info["banner"]:
                #     line += f" | {info['banner']}"
                print(line)
    with open("port_scanner/results.json", "w") as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    main()

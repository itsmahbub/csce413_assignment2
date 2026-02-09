#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import threading
import subprocess
import os

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 60.0
ACCESS_TIMEOUT = 900   # 15 minutes

# Store progress per IP
clients = {}

LOG_PATH = "/app/logs/knock_server.log"

def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_PATH),
            logging.StreamHandler()
        ],
    )


def block_protected_port(port):
    """
    Block all access to protected port by default
    """
    logging.info("Blocking port %s by default", port)

    subprocess.run([
        "iptables",
        "-I", "INPUT",
        "-p", "tcp",
        "--dport", str(port),
        "-j", "REJECT"
    ], check=False)

def schedule_close(port, ip):

    def worker():
        time.sleep(ACCESS_TIMEOUT)
        close_protected_port(port, ip)

    t = threading.Thread(target=worker, daemon=True)
    t.start()

def open_protected_port(port, ip):
    """
    Allow only this IP
    """
    logging.info("Opening %s for %s", port, ip)

    subprocess.run([
        "iptables",
        "-I", "INPUT",
        "-p", "tcp",
        "-s", ip,
        "--dport", str(port),
        "-j", "ACCEPT"
    ], check=False)

def close_protected_port(port, ip):
    """
    Remove rule
    """
    logging.info("Closing %s for %s", port, ip)

    subprocess.run([
        "iptables",
        "-D", "INPUT",
        "-p", "tcp",
        "-s", ip,
        "--dport", str(port),
        "-j", "ACCEPT"
    ], check=False)


def listen_for_knocks(sequence, window_seconds, protected_port):

    logger = logging.getLogger("KnockServer")

    logger.info("Listening for knocks: %s", sequence)

    sockets = []

    # Create socket for each port
    for port in sequence:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind(("0.0.0.0", port))
        s.listen(5)

        sockets.append((port, s))

        logger.info("Listening on %s", port)

    while True:

        for port, sock in sockets:

            sock.settimeout(1)

            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue

            ip = addr[0]
            now = time.time()

            conn.close()

            # Initialize client
            if ip not in clients:
                clients[ip] = {
                    "index": 0,
                    "start": now
                }

            state = clients[ip]

            # Check timeout
            if now - state["start"] > window_seconds:
                logger.info("Timeout: %s", ip)
                clients[ip] = {"index": 0, "start": now}
                del clients[ip]
                continue

            expected = sequence[state["index"]]

            # Wrong port
            if port != expected:
                logger.info(f"Wrong knock from {ip}: Expected: {expected}, Got: {port}")
                del clients[ip]
                # clients[ip] = {"index": 0, "start": now}
                continue

            # Correct knock
            state["index"] += 1

            logger.info("Knock %s/%s from %s",
                        state["index"],
                        len(sequence),
                        ip)

            # Completed
            if state["index"] == len(sequence):

                logger.info("Access granted to %s", ip)

                open_protected_port(protected_port, ip)
                schedule_close(protected_port, ip)

                # Reset
                clients[ip] = {"index": 0, "start": now}


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    block_protected_port(args.protected_port)
    listen_for_knocks(sequence, args.window, args.protected_port)

if __name__ == "__main__":
    main()

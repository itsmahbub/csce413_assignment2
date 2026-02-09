#!/usr/bin/env python3

import socket
import threading
import paramiko
import os
import time
from collections import defaultdict

from logger import create_logger, log_event


# ---------------------------
# Alert Configuration
# ---------------------------

MAX_FAILED_LOGINS = 5

failed_logins = defaultdict(list)

# Blacklist
blacklisted_ips = set()


# ---------------------------
# SSH Host Key
# ---------------------------

KEY_FILE = "server.key"

if os.path.exists(KEY_FILE):
    HOST_KEY = paramiko.RSAKey(filename=KEY_FILE)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_FILE)


# ---------------------------
# Logger
# ---------------------------

logger = create_logger("ssh_honeypot")


# ---------------------------
# Fake Credential Database
# ---------------------------

VALID_USERS = {
    "root": "toor",
    "admin": "admin123",
    "test": "test"
}


# ---------------------------
# Virtual File System
# ---------------------------

VFS = {
    "/": ["home", "etc", "var"],
    "/home": ["root", "admin", "test"],
    "/home/root": ["secret.txt"],
    "/etc": ["passwd", "shadow"],
}


# ---------------------------
# Fake SSH Server
# ---------------------------

class FakeSSHServer(paramiko.ServerInterface):

    def __init__(self, client_ip, client_port):

        self.client_ip = client_ip
        self.client_port = client_port

        self.event = threading.Event()


    def check_auth_password(self, username, password):

        # Log login attempt
        log_event(
            "login_attempt",
            client_ip=self.client_ip,
            client_port=self.client_port,
            username=username,
            password=password
        )

        logger.warning(
            f"[SSH LOGIN] {self.client_ip} | {username}:{password}"
        )


        # Successful login
        if username in VALID_USERS and VALID_USERS[username] == password:

            logger.info(
                f"[SSH SUCCESS] {self.client_ip} | {username}"
            )

            failed_logins[self.client_ip].clear()

            return paramiko.AUTH_SUCCESSFUL


        # Failed login
        failed_logins[self.client_ip].append(time.time())


        # Brute-force detection
        if len(failed_logins[self.client_ip]) >= MAX_FAILED_LOGINS:

            log_event(
                "bruteforce_detected",
                client_ip=self.client_ip,
                client_port=self.client_port,
                attempts=len(failed_logins[self.client_ip])
            )

            logger.critical(
                f"[ALERT] Brute-force detected from {self.client_ip}"
            )

            blacklisted_ips.add(self.client_ip)


        return paramiko.AUTH_FAILED


    def get_allowed_auths(self, username):
        return "password"


    def check_channel_request(self, kind, chanid):

        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


    def check_channel_shell_request(self, channel):

        self.event.set()
        return True


    def check_channel_pty_request(
        self, channel, term, width, height, pw, ph, modes
    ):
        return True


# ---------------------------
# Command Handler
# ---------------------------

def handle_command(chan, cmd, cwd):

    parts = cmd.split()

    if not parts:
        return cwd, True


    base = parts[0]


    if base == "exit":

        chan.send("\r\nlogout\r\n")
        return cwd, False


    elif base == "pwd":

        chan.send("\r\n" + cwd + "\r\n")


    elif base == "ls":

        files = VFS.get(cwd, [])
        chan.send("\r\n" + "  ".join(files) + "\r\n")


    elif base == "cd":

        if len(parts) < 2:
            return cwd, True


        target = parts[1]


        if target == "..":
            new = os.path.dirname(cwd) or "/"


        elif target.startswith("/"):
            new = target


        else:
            new = cwd.rstrip("/") + "/" + target


        if new in VFS:

            chan.send("\r\n")
            return new, True

        else:

            chan.send("\r\nNo such directory\r\n")


    elif base == "cat":

        if len(parts) < 2:
            return cwd, True


        file = parts[1]


        if file == "secret.txt":

            chan.send("\r\nFLAG{honeytoken_ssh}\r\n")

        else:

            chan.send("\r\nPermission denied\r\n")


    else:

        chan.send(f"\r\n{base}: command not found\r\n")


    return cwd, True


# ---------------------------
# Fake Shell
# ---------------------------

def fake_shell(chan, username, ip, port):

    cwd = "/home/" + username
    hostname = "ubuntu-server"


    chan.send("Welcome to Ubuntu 20.04 LTS\r\n")


    while True:

        prompt = f"{username}@{hostname}:{cwd}$ "
        chan.send(prompt)


        cmd = ""


        while not cmd.endswith("\n") and not cmd.endswith("\r"):

            data = chan.recv(1024).decode(
                "utf-8", errors="ignore"
            )

            if not data:
                return

            chan.send(data)
            cmd += data


        cmd = cmd.replace("\r", "").replace("\n", "").strip()


        logger.info(
            f"[CMD] {ip} | {username} | {cmd}"
        )


        # Secret file detection
        if "cat" in cmd and "secret.txt" in cmd:

            log_event(
                "secret_access_attempt",
                client_ip=ip,
                client_port=port,
                username=username,
                command=cmd
            )


        cwd, running = handle_command(chan, cmd, cwd)


        if not running:
            break


# ---------------------------
# Client Handler
# ---------------------------

def handle_client(client, addr):

    ip, port = addr


    # Log connection
    log_event(
        "connection",
        client_ip=ip,
        client_port=port
    )

    logger.info(f"[SSH CONNECT] {ip}")


    # Blacklist monitoring
    if ip in blacklisted_ips:

        log_event(
            "blacklisted_connection",
            client_ip=ip,
            client_port=port
        )

        logger.warning(
            f"[MONITOR] Blacklisted IP observed: {ip}"
        )

    try:

        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)


        server = FakeSSHServer(ip, port)

        transport.start_server(server=server)


        chan = transport.accept(20)

        if not chan:
            return


        # Wait for authentication
        while not transport.is_authenticated():
            time.sleep(0.1)


        # Wait for shell request
        server.event.wait(10)

        if not server.event.is_set():

            logger.warning("No shell request")

            chan.close()
            return


        username = transport.get_username()


        chan.settimeout(None)
        chan.setblocking(True)


        fake_shell(chan, username, ip, port)


    except Exception as e:

        logger.error(f"SSH error from {ip}: {e}")


    finally:

        client.close()


# ---------------------------
# Listener
# ---------------------------

def start_ssh_honeypot():

    sock = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )


    sock.bind(("0.0.0.0", 22))

    sock.listen(100)


    logger.info(
        "[+] SSH Honeypot listening on port 22"
    )


    while True:

        client, addr = sock.accept()


        t = threading.Thread(
            target=handle_client,
            args=(client, addr),
            daemon=True
        )

        t.start()


# ---------------------------
# Main
# ---------------------------

def run_honeypot():

    logger.info("Starting SSH honeypot...")

    start_ssh_honeypot()


if __name__ == "__main__":

    run_honeypot()

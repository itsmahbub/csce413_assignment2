import socket
import threading
import paramiko
import os
import time
from logger import create_logger

KEY_FILE = "server.key"

if os.path.exists(KEY_FILE):
    HOST_KEY = paramiko.RSAKey(filename=KEY_FILE)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_FILE)


logger = create_logger("ssh_honeypot")

# Fake credential database
VALID_USERS = {
    "root": "toor",
    "admin": "admin123",
    "test": "test"
}

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

    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        logger.warning(
            f"[SSH LOGIN] {self.client_ip} | {username}:{password}"
        )

        if username in VALID_USERS and VALID_USERS[username] == password:
            logger.info(f"[SSH SUCCESS] {self.client_ip} | {username}")
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED


    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True
    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
    return True


def handle_command(chan, cmd, cwd):

    parts = cmd.split()

    if not parts:
        return cwd, True

    base = parts[0]

    if base == "exit":
        chan.send("logout\n")
        return cwd, False

    elif base == "pwd":
        chan.send(cwd + "\n")

    elif base == "ls":
        files = VFS.get(cwd, [])
        chan.send("  ".join(files) + "\n")

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
            return new, True
        else:
            chan.send("No such directory\n")

    elif base == "cat":

        if len(parts) < 2:
            return cwd, True

        file = parts[1]

        if file == "secret.txt":
            chan.send("FLAG{honeytoken_ssh}\n")
        else:
            chan.send("Permission denied\n")

    else:
        chan.send(f"{base}: command not found\n")

    return cwd, True

def fake_shell(chan, username, ip):

    cwd = "/home/" + username
    hostname = "ubuntu-server"

    chan.send(f"Welcome to Ubuntu 20.04 LTS\n\n")

    while True:

        prompt = f"{username}@{hostname}:{cwd}$ "
        chan.send(prompt)

        cmd = ""

        while not cmd.endswith("\n"):
            data = chan.recv(1024).decode("utf-8", errors="ignore")
            if not data:
                return
            cmd += data

        cmd = cmd.strip()

        logger.info(f"[CMD] {ip} | {username} | {cmd}")

        cwd, running = handle_command(chan, cmd, cwd)

        if not running:
            break


# ---------------------------
# Client Handler
# ---------------------------

def handle_client(client, addr):
    ip = addr[0]
    logger.info(f"[SSH CONNECT] {ip}")

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)

        server = FakeSSHServer(ip)

        transport.start_server(server=server)

        chan = transport.accept(20)

        if chan:

            username = transport.get_username()

            fake_shell(chan, username, ip)


    except Exception as e:
        logger.error(f"SSH error from {ip}: {e}")

    finally:
        client.close()


# ---------------------------
# Listener
# ---------------------------

def start_ssh_honeypot():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(("0.0.0.0", 2222))

    sock.listen(100)

    logger.info("[+] SSH Honeypot listening on port 22")

    while True:
        client, addr = sock.accept()

        t = threading.Thread(
            target=handle_client,
            args=(client, addr),
            daemon=True
        )
        t.start()


def run_honeypot():
    logger.info("Starting SSH honeypot...")

    start_ssh_honeypot()


if __name__ == "__main__":
    run_honeypot()

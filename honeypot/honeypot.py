import socket
import threading
import paramiko
import logging
import os
import time

LOG_PATH = "/app/logs/honeypot.log"

HOST_KEY = paramiko.RSAKey.generate(2048)


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


# ---------------------------
# Fake SSH Server
# ---------------------------

class FakeSSHServer(paramiko.ServerInterface):

    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        logging.warning(
            f"[SSH LOGIN] {self.client_ip} | {username}:{password}"
        )
        return paramiko.AUTH_FAILED   # Always reject

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True


# ---------------------------
# Client Handler
# ---------------------------

def handle_client(client, addr):
    ip = addr[0]
    logging.info(f"[SSH CONNECT] {ip}")

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)

        server = FakeSSHServer(ip)

        transport.start_server(server=server)

        chan = transport.accept(20)

        if chan is None:
            return

        chan.send("Access denied.\r\n")
        time.sleep(2)

        chan.close()

    except Exception as e:
        logging.error(f"SSH error from {ip}: {e}")

    finally:
        client.close()


# ---------------------------
# Listener
# ---------------------------

def start_ssh_honeypot():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(("0.0.0.0", 22))
    sock.listen(100)

    logging.info("[+] SSH Honeypot listening on port 22")

    while True:
        client, addr = sock.accept()

        t = threading.Thread(
            target=handle_client,
            args=(client, addr),
            daemon=True
        )
        t.start()


def run_honeypot():
    logging.info("Starting SSH honeypot...")

    start_ssh_honeypot()


if __name__ == "__main__":
    setup_logging()
    run_honeypot()

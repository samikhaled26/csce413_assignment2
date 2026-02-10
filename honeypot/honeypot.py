#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import os
import time
import threading
import socket

import paramiko

LOG_PATH = "/app/logs/honeypot.log"

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.getenv("HONEYPOT_PORT", "22"))

SSH_BANNER = os.getenv("HONEYPOT_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7")

HOST_KEY_PATH = os.getenv("HONEYPOT_HOSTKEY", "/app/host_key.pem")

FAIL_WINDOW_SECONDS = 60
FAIL_THRESHOLD = 5


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )

def _load_or_create_host_key(path: str) -> paramiko.RSAKey:
    """Load an existing RSA host key or generate one if it doesn't exist."""
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key

class HoneypotSSHServer(paramiko.ServerInterface):
    """Paramiko server interface used to capture auth attempts and basic activity."""

    def __init__(self, logger: logging.Logger, src_ip: str, fail_tracker: dict):
        self.logger = logger
        self.src_ip = src_ip
        self.fail_tracker = fail_tracker

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Log username/password attempt (always fail for honeypot)
        self.logger.info(
            "AUTH_ATTEMPT src_ip=%s username=%r password=%r success=%s",
            self.src_ip,
            username,
            password,
            False,
        )

        # Optional simple alerting on repeated failures
        now = time.time()
        lst = self.fail_tracker.setdefault(self.src_ip, [])
        lst.append(now)
        cutoff = now - FAIL_WINDOW_SECONDS
        self.fail_tracker[self.src_ip] = [t for t in lst if t >= cutoff]

        if len(self.fail_tracker[self.src_ip]) >= FAIL_THRESHOLD:
            self.logger.info(
                "ALERT type=repeated_failed_logins src_ip=%s count=%d window_seconds=%d",
                self.src_ip,
                len(self.fail_tracker[self.src_ip]),
                FAIL_WINDOW_SECONDS,
            )

        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Log publickey attempts without storing key material
        self.logger.info(
            "AUTH_ATTEMPT src_ip=%s username=%r password=<publickey> success=%s",
            self.src_ip,
            username,
            False,
        )
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        # Captures commands like: ssh user@host "whoami"
        try:
            cmd = command.decode("utf-8", errors="replace")
        except Exception:
            cmd = str(command)

        self.logger.info("COMMAND src_ip=%s cmd=%r", self.src_ip, cmd)
        return True


def _handle_client(
    client_sock: socket.socket,
    addr,
    host_key: paramiko.RSAKey,
    logger: logging.Logger,
    fail_tracker: dict,
):
    src_ip, src_port = addr[0], addr[1]
    start = time.time()

    logger.info("CONNECTION_OPEN src_ip=%s src_port=%d", src_ip, src_port)

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        # The banner the SSH client sees
        transport.local_version = SSH_BANNER

        transport.add_server_key(host_key)

        server = HoneypotSSHServer(logger, src_ip, fail_tracker)
        transport.start_server(server=server)

        chan = transport.accept(10)
        if chan is None:
            # Client never opened a session channel
            return

        
        chan.send("\r\nPermission denied, please try again.\r\n")
        time.sleep(0.5)
        chan.close()

    except Exception as e:
        logger.info("ERROR src_ip=%s msg=%r", src_ip, str(e))
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass

        duration = time.time() - start
        logger.info("CONNECTION_CLOSE src_ip=%s duration_seconds=%.3f", src_ip, duration)

def run_honeypot():
    logger = logging.getLogger("Honeypot")
    logger.info("Honeypot starting (SSH). listen=%s:%d banner=%r", LISTEN_HOST, LISTEN_PORT, SSH_BANNER)
    # logger.info("TODO: Implement protocol simulation, logging, and alerting.")

    host_key = _load_or_create_host_key(HOST_KEY_PATH)
    fail_tracker = {}  # src_ip -> [timestamps]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(100)

    while True:
        client, addr = sock.accept()
        t = threading.Thread(
            target=_handle_client,
            args=(client, addr, host_key, logger, fail_tracker),
            daemon=True,
        )
        t.start()



if __name__ == "__main__":
    setup_logging()
    run_honeypot()

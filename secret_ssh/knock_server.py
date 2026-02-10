#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import subprocess
import select

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
DEFAULT_OPEN_SECONDS = 30.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )

def _run(cmd):
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def _ensure_default_drop(protected_port: int):
    """Make protected_port closed by default (DROP), so port knocking has an effect."""
    check = _run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])
    if check.returncode == 0:
        return
    ins = _run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])
    if ins.returncode != 0:
        logging.warning("Could not install default DROP for %s: %s", protected_port, ins.stderr.strip())

def open_protected_port(protected_port, src_ip):
    """Open the protected port using firewall rules."""
    # TODO: Use iptables/nftables to allow access to protected_port.
    check = _run(
        ["iptables", "-C", "INPUT", "-p", "tcp", "-s", src_ip, "--dport", str(protected_port), "-j", "ACCEPT"]
    )
    if check.returncode == 0:
        return
    add = _run(
        ["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", src_ip, "--dport", str(protected_port), "-j", "ACCEPT"]
    )
    if add.returncode == 0:
        logging.info("Opened port %s for %s", protected_port, src_ip)
    else:
        logging.info("Failed opening port %s for %s: %s", protected_port, src_ip, add.stderr.strip())


def close_protected_port(protected_port, src_ip):
    """Close the protected port using firewall rules."""
    # TODO: Remove firewall rules for protected_port.
    rem = _run(
        ["iptables", "-D", "INPUT", "-p", "tcp", "-s", src_ip, "--dport", str(protected_port), "-j", "ACCEPT"]
    )
    if rem.returncode == 0:
        logging.info("Closed port %s for %s", protected_port, src_ip)


def listen_for_knocks(sequence, window_seconds, protected_port, open_seconds=DEFAULT_OPEN_SECONDS):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    # TODO: Create UDP or TCP listeners for each knock port.
    socks = []
    for p in sequence:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.listen(50)
        socks.append(s)

    # TODO: Track each source IP and its progress through the sequence.
    progress = {}  # ip -> (idx, start_time)

    _ensure_default_drop(protected_port)

    # TODO: Enforce timing window per sequence.
    while True:
        readable, _, _ = select.select(socks, [], [], 1.0)
        now = time.time()

        # Clean up expired sequences (optional, minimal hygiene)
        for ip, (idx, start) in list(progress.items()):
            if now - start > window_seconds:
                progress.pop(ip, None)

        for srv in readable:
            conn, addr = srv.accept()
            src_ip = addr[0]
            conn.close()

            knock_port = srv.getsockname()[1]

            idx, start = progress.get(src_ip, (0, now))
            if idx == 0:
                start = now

            # Wrong knock -> reset
            expected = sequence[idx]
            if knock_port != expected:
                logger.info("[%s] Wrong knock %s (expected %s) -> reset", src_ip, knock_port, expected)
                progress[src_ip] = (0, now)
                continue

            idx += 1
            progress[src_ip] = (idx, start)
            logger.info("[%s] Knock %s OK (%d/%d)", src_ip, knock_port, idx, len(sequence))


            # TODO: On correct sequence, call open_protected_port().
            if idx == len(sequence) and (now - start) <= window_seconds:
                logger.info("[%s] Sequence complete -> opening protected port", src_ip)
                open_protected_port(protected_port, src_ip)

                # Reset after success
                progress.pop(src_ip, None)

                # Minimal auto-close (optional but nice)
                if open_seconds and open_seconds > 0:
                    time.sleep(open_seconds)
                    close_protected_port(protected_port, src_ip)

    # TODO: On incorrect sequence, reset progress.

    # while True:
    #     time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
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
    parser.add_argument(
        "--open-seconds",
        type=float,
        default=DEFAULT_OPEN_SECONDS,
        help="How long to keep the port open after success (0 disables auto-close)",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port, args.open_seconds)


if __name__ == "__main__":
    main()

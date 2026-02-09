#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(target, port, timeout=1.0, do_banner=True):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)


    try:
        s.connect((target, port))
        rtt_ms = (time.perf_counter() - t0) * 1000.0

        banner = None
        if do_banner:
            try:
                s.settimeout(1.0)
                data = s.recv(256)
                if data:
                    banner = data.decode(errors="replace").strip()
            except Exception:
                pass

            if not banner:
                try:
                    req = f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
                    s.sendall(req)
                    data = s.recv(512)
                    if data:
                        banner = data.decode(errors="replace").strip()
                except Exception:
                    pass
        return True, banner, rtt_ms

    except (socket.timeout, ConnectionRefusedError, OSError):
        rtt_ms = (time.perf_counter() - t0) * 1000.0
        return False, None, rtt_ms
    finally:
        try:
            s.close()
        except Exception:
            pass



def scan_range(target, start_port, end_port, threads=200, timeout=0.3, do_banner=True):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    results = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] Threads={threads}, timeout={timeout}s")

    ports = list(range(start_port, end_port + 1))
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(scan_port, target, p, timeout, do_banner): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            is_open, banner, rtt_ms = fut.result()
            if is_open:
                results.append({"port": p, "banner": banner, "rtt_ms": rtt_ms})

    dt = time.time() - t0
    results.sort(key=lambda x: x["port"])

    print(f"[+] Scan finished in {dt:.2f}s")
    return results


def parse_port_range(s: str):
    s = s.strip()
    if "-" in s:
        a, b = s.split("-", 1)
        start, end = int(a), int(b)
    else:
        start = end = int(s)
    if start < 1 or end > 65535 or start > end:
        raise ValueError("Ports must be 1-65535 and start<=end")
    return start, end

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner_template.py <target>")
        print("Example: python3 port_scanner_template.py 172.20.0.10")
        sys.exit(1)

    target = sys.argv[1]

    if len(sys.argv) >= 4:
        try:
            start_port = int(sys.argv[2])
            end_port = int(sys.argv[3])
        except ValueError:
            print("Error: Ports must be integers")
            sys.exit(1)
    else:
        start_port = 1
        end_port = 1024

    print(f"[*] Starting port scan on {target}")
    results = scan_range(target, start_port, end_port, threads=200, timeout=0.2, do_banner=True)


    print(f"\n[+] Scan complete!")
    print(f"[+] Found {len(results)} open ports:")

    for r in results:
        banner_preview = ""
        if r["banner"]:
            b = r["banner"].replace("\r", " ").replace("\n", " ")
            banner_preview = f" | banner: {b[:120]}"
        print(f"    {r['port']}/tcp open rtt={r['rtt_ms']:.1f}ms{banner_preview}")



if __name__ == "__main__":
    main()

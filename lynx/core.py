"""
MIT License

Copyright (c) 2025 0xf0xy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from scapy.all import IP, TCP, send, sr1, RandShort
from importlib.resources import files
import asyncio
import random
import socket
import os

BLACK = "\033[1;30m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
RESET = "\033[0m"


class Lynx:
    """
    Lynx: Stealthy TCP port scanner.
    """

    def __init__(self):
        """
        Initialize Lynx instance and load the configuration.
        """
        self._load_config()

    def _load_config(self):
        """
        Load data from the TXT file.

        Sets common ports, flags map, and results dict.
        """
        with files("lynx.data").joinpath("common_ports.txt").open("r") as f:
            self.common_ports = [int(port) for port in f.readlines()]

        self.flags_map = {"SYN": "S", "FIN": "F", "NULL": "", "XMAS": "FPU"}
        self.results = {}

    def display_results(self, verbose: bool):
        """
        Display the results of the scan in an ordered format.
        """
        any_open = False

        for port in sorted(self.results.keys()):
            status = self.results[port]

            if status == "open":
                print(f"    Port {port:<5} → {GREEN}OPEN{RESET}")
                any_open = True

            elif status == "closed" and verbose == True:
                print(f"    Port {port:<5} → {RED}CLOSED{RESET}")

            elif status == "filtered" and verbose == True:
                print(f"    Port {port:<5} → {BLACK}FILTERED{RESET}")

            elif "error" in status and verbose == True:
                print(f"    Port {port:<5} → {RED}{status}{RESET}")

        if not any_open and not verbose:
            print(f"    [{RED}x{RESET}] No open ports found.")

    async def scanner(self, target: str, port: int, flag: str, ttl: int):
        """
        Scan a single port on the target host using a specific TCP flag.

        Args:
            target (str): Target IP address.
            port (int): Target port number.
            flag (str): TCP flag to use.
            ttl (int): Time To Live for the IP packet.
        """
        await asyncio.sleep(random.uniform(0.05, 0.2))
        pkt = IP(dst=target, ttl=ttl, id=random.randint(1, 65535)) / TCP(
            sport=RandShort(), dport=port, flags=self.flags_map[flag]
        )

        try:
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:
                    rst = IP(dst=target) / TCP(dport=port, flags="R")
                    send(rst, verbose=0)
                    self.results[port] = "open"

                elif resp[TCP].flags == 0x14:
                    self.results[port] = "closed"

            elif resp is None:
                self.results[port] = "filtered"

        except Exception as e:
            self.results[port] = f"error: {e}"

    async def run(self, target: str, ports: str, flag: str, ttl: int, verbose: bool):
        """
        Run the scanner on a list of ports for the given target.

        Args:
            target (str): Target hostname or IP.
            ports (str): Single port, comma-separated list of port numbers or port range.
            flags (list[str]): TCP flags to use in scans.
            ttl (int): TTL value for packets.
            verbose (bool): Enable verbose output.
        """
        os.system("clear")

        print(f"Target       : {BLUE}{target}{RESET}")
        print(f"Scan Type    : {BLUE}{flag}{RESET}")
        print("─" * 50, "\n")

        try:
            ip = socket.gethostbyname(target)

        except socket.gaierror:
            print(f"    [{RED}x{RESET}] Could not resolve host: {target}")
            return

        if ports:
            if "," in ports or "-" in ports:
                port_list = []
                for port in ports.split(","):
                    port = port.strip()
                    if "-" in port:
                        start, end = port.split("-")
                        port_list.extend(range(int(start), int(end) + 1))
                    else:
                        port_list.append(int(port))

            elif ports.isdigit():
                port_list = [int(ports)]

        else:
            port_list = self.common_ports

        tasks = [self.scanner(ip, port, flag, ttl) for port in port_list]

        try:
            await asyncio.gather(*tasks)

            self.display_results(verbose)

        except asyncio.CancelledError:
            print(f"\r\033[K    [{YELLOW}!{RESET}] Scan stopped by user.", flush=True)

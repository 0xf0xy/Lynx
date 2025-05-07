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
from rich import print
import asyncio
import random
import socket


class Lynx:
    """
    Lynx: Stealth TCP port scanner.
    """

    def __init__(self):
        """
        Initialize Lynx instance and load the configuration.
        """
        self._load_config()

    def _load_config(self):
        """
        Load data from the TXT file.

        Sets common ports, TCP flags, and results.
        """
        with files("lynx.data").joinpath("common_ports.txt").open("r") as f:
            self.common_ports = [int(port) for port in f.readlines()]

        self.flags = {"SYN": "S", "FIN": "F", "NULL": "", "XMAS": "FPU"}
        self.results = {}

    def display_results(self):
        """
        Display the results of the scan in an ordered format.
        """
        print(f"[bold blue]*[/bold blue] Scan Results:")

        for port in sorted(self.results.keys()):
            status = self.results[port]

            if status == "open":
                print(
                    f"[bold green]+[/bold green] Port [bold white]{port}[/bold white]: [bold green]OPEN[/bold green]"
                )
            elif status == "closed":
                print(
                    f"[bold red]-[/bold red] Port [bold white]{port}[/bold white]: [bold red]CLOSED[/bold red]"
                )
            elif status == "filtered":
                print(
                    f"[bold black]~[/bold black] Port [bold white]{port}[/bold white]: [bold black]FILTERED/NO CONNECTION[/bold black]"
                )
            elif "error" in status:
                print(
                    f"[bold red]-[/bold red] Port [bold white]{port}[/bold white]: [bold red]{status}[/bold red]"
                )

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
            sport=RandShort(), dport=port, flags=flag
        )

        try:
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:
                    self.results[port] = "open"
                    rst = IP(dst=target) / TCP(dport=port, flags="R")
                    send(rst, verbose=0)

                elif resp[TCP].flags == 0x14:
                    self.results[port] = "closed"

            elif resp is None:
                self.results[port] = "filtered"

        except Exception as e:
            self.results[port] = f"error ({e})"

    async def scan(self, target: str, ports: str, flag: str, ttl: int):
        """
        Run the scanner on a list of ports for the given target.

        Args:
            target (str): Target hostname or IP.
            ports (str): Comma-separated list of port numbers.
            flag (str): TCP flag to use for all scans.
            ttl (int): TTL value for packets.
        """
        try:
            resolved_ip = socket.gethostbyname(target)
            target = resolved_ip

        except socket.gaierror:
            return

        if ports:
            port_list = [
                int(p.strip()) for p in ports.split(",") if p.strip().isdigit()
            ]

        else:
            port_list = self.common_ports

        print(
            f"[bold blue]*[/bold blue] Starting scan on [bold blue]{target}[/bold blue]\n"
        )

        tasks = [
            self.scanner(target, port, self.flags[flag], ttl) for port in port_list
        ]
        await asyncio.gather(*tasks)

        self.display_results()

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

from lynx.core import Lynx
import argparse
import asyncio


def build_parser():
    parser = argparse.ArgumentParser(
        description="Lynx: Stealthy TCP port scanner", add_help=False
    )

    host = parser.add_argument_group("Target Settings")
    host.add_argument("host", help="Targe host or IP address")
    host.add_argument(
        "-p",
        "--ports",
        help="Ports to scann (comma-separated)",
    )

    scan = parser.add_argument_group("Scan Settings")
    scan.add_argument("-s", "--syn", action="store_true", help="Perform SYN scan")
    scan.add_argument("-f", "--fin", action="store_true", help="Perform FIN scan")
    scan.add_argument("-n", "--null", action="store_true", help="Perform NULL scan")
    scan.add_argument("-x", "--xmas", action="store_true", help="Perform XMAS scan")
    scan.add_argument("-t", "--ttl", type=int, default=64, help="Custom TTL value")

    meta = parser.add_argument_group("Information")
    meta.add_argument(
        "-V", "--verbose", action="store_true", help="Enable verbose output"
    )
    meta.add_argument("-h", "--help", action="help", help="Show this help menu")
    meta.add_argument(
        "-v",
        "--version",
        action="version",
        version="Lynx v1.0.0",
        help="Show program version",
    )

    return parser


def main():
    flags = ["SYN", "FIN", "NULL", "XMAS"]

    parser = build_parser()
    args = parser.parse_args()

    lynx = Lynx()

    flags = [flag for flag in flags if getattr(args, flag.lower())]

    if len(flags) > 1:
        parser.error("you can only specify one scan type at a time.")

    asyncio.run(
        lynx.run(
            target=args.host,
            ports=args.ports,
            flag=flags[0],
            ttl=args.ttl,
            verbose=args.verbose,
        )
    )

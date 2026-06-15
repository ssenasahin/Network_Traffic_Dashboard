#!/usr/bin/env python3
"""Simple runner for app/scanner.py

Usage examples:
  python app/run_scanner.py --target localhost --ports 22,80,443
  python app/run_scanner.py --target 192.168.1.1 --ports 1-1024 --concurrency 200
"""
import argparse
import asyncio
from typing import List

from scanner import resolve_target, scan_ports, parse_ports


async def _main(args: argparse.Namespace) -> None:
    try:
        target = await resolve_target(args.target, allow_public=True)
    except Exception as e:
        print(f"Target error: {e}")
        return

    # determine ports
    ports: List[int]
    if args.mode and args.mode != "custom":
        ports = parse_ports(args.mode, None)
    else:
        ports = parse_ports("custom", args.ports)

    print(f"Scanning {target.ip} ({target.host}) on {len(ports)} ports with concurrency={args.concurrency} timeout={args.timeout}s")

    open_ports = []
    async for res in scan_ports(target, ports, timeout=args.timeout, concurrency=args.concurrency, banner=args.banner):
        if res.get("state") == "open":
            open_ports.append(res)
            name = res.get("service") or "Unknown"
            banner = res.get("banner")
            print(f"OPEN {res['port']:5d}  {name:20}  {res.get('latency_ms')}ms")
            if banner:
                print(f"  banner: {banner}")

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"Found {len(open_ports)} open ports.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run async port scanner from app/scanner.py")
    parser.add_argument("--target", required=True, help="IP or hostname to scan")
    parser.add_argument("--ports", default="22,80,443", help="Comma separated ports or ranges (e.g. 1-1024,80,443)")
    parser.add_argument("--mode", choices=["top20", "top100", "custom"], default="custom", help="Predefined port sets")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connect timeout in seconds")
    parser.add_argument("--concurrency", type=int, default=200, help="Max concurrent connections (capped to 500)")
    parser.add_argument("--banner", action="store_true", help="Try to grab small banner from services")
    args = parser.parse_args()

    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        print("Cancelled by user")


if __name__ == "__main__":
    main()

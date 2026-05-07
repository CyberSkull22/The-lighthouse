'''
_____  _  _ ___    _    ___ ___ _  _ _____ _  _  ___  _   _ ___ ___
|_   _| || | __|  | |  |_ _/ __| || |_   _| || |/ _ \| | | / __| __|
  | | | __ | _|   | |__ | | (_ | __ | | | | __ | (_) | |_| \__ \ _|
  |_| |_||_|___|  |____|___\___|_||_| |_| |_||_|\___/ \___/|___/|___|
'''
'''
           * . * . * . *
             \ . | . /
              ___|___
             | ((@)) |
             |_______|
             |       |
             |  | |  |
             |_______|
             |  | |  |
             |_______|
             |  | |  |
             |_______|
            /|       |\
           / |_______| \
          /______^______\
        _/  \__/ | \__/  \_
     ~~~~~~~~~~~~~~~~~~~~~~~~~
       ~~~   ~~~   ~~~   ~~~
'''
import asyncio
import socket
import sys
import time
import argparse
import json
import csv
import logging
import yaml
from tqdm.asyncio import tqdm

SCAN_LIMIT = 1000
CONCURRENCY = 200
CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 1.0
HTTP_PORTS = {80, 8080, 8000, 8008}

SERVICE_SIGNATURES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
}

async def resolve_target(target: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            target,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        return infos[0][4][0]
    except Exception as exc:
        raise RuntimeError(f"Unable to resolve target '{target}': {exc}") from exc

def parse_ports(port_str: str) -> list[int]:
    parts = [p.strip() for p in port_str.split(",")]
    ports = []
    for part in parts:
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    if len(parts) == 1 and "-" not in port_str and "," not in port_str:
        # Single number means 1 to N
        return list(range(1, ports[0] + 1))
    return sorted(set(ports))

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, address: str, port: int) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
        if data:
            return data.decode(errors="replace").strip()

        if port in HTTP_PORTS:
            request = (
                f"HEAD / HTTP/1.0\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            ).encode()
            writer.write(request)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
            if data:
                return data.decode(errors="replace").strip()
    except asyncio.TimeoutError:
        return None
    except Exception:
        return None
    return None

async def scan_port(
    port: int,
    address: str,
    semaphore: asyncio.Semaphore,
    open_ports: list[int],
    banners: dict[int, str],
    services: dict[int, str],
) -> None:
    async with semaphore:
        for attempt in range(3):
            try:
                connect_coro = asyncio.open_connection(address, port)
                reader, writer = await asyncio.wait_for(connect_coro, timeout=CONNECT_TIMEOUT)
                break
            except (asyncio.TimeoutError, OSError):
                if attempt == 2:
                    return
                await asyncio.sleep(0.1 * (2 ** attempt))  # exponential backoff
        try:
            banner = await grab_banner(reader, writer, address, port)
            open_ports.append(port)
            if banner:
                banners[port] = banner
                # Detect service from banner
                banner_upper = banner.upper()
                if "SSH" in banner_upper:
                    services[port] = "SSH"
                elif "HTTP" in banner_upper:
                    services[port] = "HTTP"
                elif "FTP" in banner_upper:
                    services[port] = "FTP"
                elif "SMTP" in banner_upper:
                    services[port] = "SMTP"
                # Add more as needed
            if port in SERVICE_SIGNATURES:
                services[port] = SERVICE_SIGNATURES[port]
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def main() -> int:
    parser = argparse.ArgumentParser(description="The Lighthouse - Async Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", type=str, default=f"1-{SCAN_LIMIT}", help=f"Ports to scan (range like 1-100 or list like 22,80,443, default: 1-{SCAN_LIMIT})")
    parser.add_argument("-c", "--concurrency", type=int, default=CONCURRENCY, help=f"Number of concurrent connections (default: {CONCURRENCY})")
    parser.add_argument("-t", "--timeout", type=float, default=CONNECT_TIMEOUT, help=f"Connection timeout in seconds (default: {CONNECT_TIMEOUT})")
    parser.add_argument("--output", help="Output file (e.g., results.json or results.csv)")
    parser.add_argument("--config", help="Config file (YAML)")
    args = parser.parse_args()

    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)
        for key, value in config.items():
            if hasattr(args, key):
                setattr(args, key, value)

    logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print('''
_____  _  _ ___    _    ___ ___ _  _ _____ _  _  ___  _   _ ___ ___
|_   _| || | __|  | |  |_ _/ __| || |_   _| || |/ _ \| | | / __| __|
  | | | __ | _|   | |__ | | (_ | __ | | | | __ | (_) | |_| \__ \ _|
  |_| |_||_|___|  |____|___\___|_||_| |_| |_||_|\___/ \___/|___/|___|
''')
    print('''
           * . * . * . *
             \ . | . /
              ___|___
             | ((@)) |
             |_______|
             |       |
             |  | |  |
             |_______|
             |  | |  |
             |_______|
             |  | |  |
             |_______|
            /|       |\
           / |_______| \
          /______^______\
        _/  \__/ | \__/  \_
     ~~~~~~~~~~~~~~~~~~~~~~~~~
       ~~~   ~~~   ~~~   ~~~
''')

    target = args.target
    ports = parse_ports(args.ports)
    scan_limit = len(ports)
    concurrency = args.concurrency
    connect_timeout = args.timeout

    print(f"Scanning {target} for open ports...")

    try:
        address = await resolve_target(target)
    except RuntimeError as exc:
        print(exc)
        return 1

    start_time = time.perf_counter()
    logging.info(f"Starting scan of {target} with {scan_limit} ports")

    semaphore = asyncio.Semaphore(concurrency)
    open_ports: list[int] = []
    banners: dict[int, str] = {}
    services: dict[int, str] = {}

    scan_tasks = [
        asyncio.create_task(scan_port(port, address, semaphore, open_ports, banners, services))
        for port in ports
    ]

    try:
        with tqdm(total=len(ports), desc="Scanning") as pbar:
            for coro in asyncio.as_completed(scan_tasks):
                await coro
                pbar.update(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        for task in scan_tasks:
            task.cancel()
        await asyncio.gather(*scan_tasks, return_exceptions=True)

    elapsed = time.perf_counter() - start_time
    logging.info(f"Scan completed, found {len(open_ports)} open ports in {elapsed:.2f} seconds")

    print("Scan complete!")
    print(f"Scan completed in {elapsed:.2f} seconds.")
    print(f"Scanned {scan_limit} ports with concurrency {concurrency}.")
    if open_ports:
        open_ports.sort()
        print("Open ports:")
        for port in open_ports:
            service = services.get(port, "Unknown")
            print(f"Port {port} ({service}) is open.")
            if port in banners:
                print(f"  Banner: {banners[port]}")
    else:
        print("No open ports detected.")

    if args.output:
        if args.output.endswith(".json"):
            data = {
                "target": target,
                "elapsed": elapsed,
                "open_ports": open_ports,
                "banners": banners,
                "services": services
            }
            with open(args.output, "w") as f:
                json.dump(data, f, indent=4)
        elif args.output.endswith(".csv"):
            with open(args.output, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Service", "Banner"])
                for port in sorted(open_ports):
                    writer.writerow([port, services.get(port, ""), banners.get(port, "")])

    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nScan stopped by user.")
        sys.exit(1)


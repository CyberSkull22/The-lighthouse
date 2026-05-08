from __future__ import annotations
import sys
import asyncio
import logging
import time
import argparse
import csv
import json
import socket
import ipaddress
import importlib
import importlib.util
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections.abc import Callable
from typing import Any
import yaml


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = ""
    version: str = ""
    banner: str | None = None


@dataclass
class HostResult:
    ip: str
    is_up: bool = False
    ports: list[PortResult] = field(default_factory=list)
    os_guess: str = ""
    os_confidence: float = 0.0
    ttl: int | None = None
    tcp_window: int | None = None
    scan_duration: float = 0.0


@dataclass
class ScanResult:
    targets_input: list[str] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    scan_type: list[str] = field(default_factory=list)
    start_time: str = ""
    total_duration: float = 0.0


@dataclass
class ScanConfig:
    targets: list[str] = field(default_factory=list)
    ports: str = "1-1000"
    concurrency: int = 200
    timeout: float = 1.0
    banner_timeout: float = 1.0
    output_file: str = ""
    udp_scan: bool = False
    syn_scan: bool = False
    os_fingerprint: bool = False
    version_detection: bool = False
    host_discovery: bool = True
    scripts: str = ""
    scripts_dir: str = "scripts"
    tui: bool = False


# ---------------------------------------------------------------------------
# Service / banner data
# ---------------------------------------------------------------------------

SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
    194: "irc", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer",
    520: "route", 543: "klogin", 544: "kshell", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1900: "upnp", 2049: "nfs", 2375: "docker", 2376: "docker-ssl",
    3306: "mysql", 3389: "rdp", 4500: "ipsec-nat", 5353: "mdns",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 6379: "redis",
    6443: "k8s-api", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}

BANNER_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    21: b"", 22: b"", 25: b"", 110: b"", 143: b"", 389: b"",
}

UDP_PROBES: dict[int, bytes] = {
    53: b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b" + b"\x00" * 47,
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
}


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

async def normalize_targets(targets: list[str]) -> list[str]:
    result: list[str] = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses == 1:
                result.append(str(network.network_address))
            else:
                result.extend(str(ip) for ip in network.hosts())
            continue
        except ValueError:
            pass
        try:
            loop = asyncio.get_event_loop()
            info = await loop.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
            if info:
                result.append(info[0][4][0])
        except Exception:
            result.append(target)
    return result


def parse_ports(ports_str: str) -> list[int]:
    ports: list[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            ports.extend(range(int(start_s.strip()), int(end_s.strip()) + 1))
        elif part:
            ports.append(int(part))
    return ports


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

async def discover_hosts(ips: list[str], concurrency: int = 100, timeout: float = 0.5) -> list[str]:
    sem = asyncio.Semaphore(concurrency)

    async def _probe(ip: str) -> str | None:
        async with sem:
            for port in (80, 443, 22):
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=timeout
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return ip
                except Exception:
                    continue
            return None

    results = await asyncio.gather(*(_probe(ip) for ip in ips))
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# TCP scanner
# ---------------------------------------------------------------------------

def _parse_version(banner: str, port: int) -> str:
    if not banner:
        return ""
    return banner.splitlines()[0][:100]


class TCPScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def scan_host(
        self,
        ip: str,
        ports: list[int],
        port_found_callback: Callable[[str, PortResult], None] | None = None,
        port_attempt_callback: Callable[[], None] | None = None,
    ) -> list[PortResult]:
        sem = asyncio.Semaphore(self.config.concurrency)
        tasks = [self._scan_port(ip, port, sem, port_found_callback, port_attempt_callback) for port in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def _scan_port(
        self,
        ip: str,
        port: int,
        sem: asyncio.Semaphore,
        callback: Callable[[str, PortResult], None] | None,
        attempt_callback: Callable[[], None] | None,
    ) -> PortResult | None:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.config.timeout
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                if attempt_callback:
                    attempt_callback()
                return None
            except Exception as exc:
                logging.debug("TCP %s:%d — %s", ip, port, exc)
                if attempt_callback:
                    attempt_callback()
                return None

            pr = PortResult(port=port, protocol="tcp", state="open", service=SERVICE_NAMES.get(port, ""))

            if self.config.version_detection:
                pr.banner, pr.version = await self._grab_banner(ip, port, reader, writer)
            else:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            if attempt_callback:
                attempt_callback()
            if callback:
                callback(ip, pr)
            return pr

    async def _grab_banner(
        self,
        ip: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> tuple[str | None, str]:
        try:
            probe = BANNER_PROBES.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()

            raw = await asyncio.wait_for(reader.read(1024), timeout=self.config.banner_timeout)
            banner = raw.decode(errors="replace").strip()[:200] if raw else None

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            version = _parse_version(banner, port) if banner else ""
            return banner, version
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return None, ""


# ---------------------------------------------------------------------------
# UDP scanner
# ---------------------------------------------------------------------------

class UDPScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def scan_host(
        self,
        ip: str,
        ports: list[int],
        port_found_callback: Callable[[str, PortResult], None] | None = None,
        port_attempt_callback: Callable[[], None] | None = None,
    ) -> list[PortResult]:
        sem = asyncio.Semaphore(min(self.config.concurrency, 50))
        tasks = [self._scan_port(ip, port, sem, port_found_callback, port_attempt_callback) for port in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def _scan_port(
        self,
        ip: str,
        port: int,
        sem: asyncio.Semaphore,
        callback: Callable[[str, PortResult], None] | None,
        attempt_callback: Callable[[], None] | None,
    ) -> PortResult | None:
        async with sem:
            probe = UDP_PROBES.get(port, b"\x00")
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setblocking(False)
                sock.sendto(probe, (ip, port))
                await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=self.config.timeout)
            except asyncio.TimeoutError:
                if attempt_callback:
                    attempt_callback()
                return None
            except Exception as exc:
                logging.debug("UDP %s:%d — %s", ip, port, exc)
                if attempt_callback:
                    attempt_callback()
                return None
            finally:
                sock.close()

            pr = PortResult(port=port, protocol="udp", state="open", service=SERVICE_NAMES.get(port, ""))
            if attempt_callback:
                attempt_callback()
            if callback:
                callback(ip, pr)
            return pr


# ---------------------------------------------------------------------------
# OS fingerprinting
# ---------------------------------------------------------------------------

OS_TTL_MAP = [(64, "Linux/Unix"), (128, "Windows"), (255, "Cisco IOS / network device"), (60, "macOS / iOS (older)")]

OS_BANNER_SIGNATURES: list[tuple[str, str]] = [
    ("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"), ("centos", "Linux (CentOS)"),
    ("fedora", "Linux (Fedora)"), ("red hat", "Linux (RHEL)"), ("linux", "Linux"),
    ("windows", "Windows"), ("microsoft", "Windows"), ("iis", "Windows (IIS)"),
    ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD"), ("cisco", "Cisco IOS"),
    ("junos", "Juniper JunOS"), ("darwin", "macOS"), ("macos", "macOS"),
    ("nginx", "Linux (nginx)"), ("apache", "Linux (Apache)"),
]


def fingerprint_os(ttl: int | None, tcp_window: int | None, banners: list[str]) -> tuple[str, float]:
    os_guess = ""
    confidence = 0.0

    for banner in banners:
        banner_lower = banner.lower()
        for sig, name in OS_BANNER_SIGNATURES:
            if sig in banner_lower:
                os_guess = name
                confidence = 0.6
                break
        if os_guess:
            break

    if ttl is not None:
        closest = min(OS_TTL_MAP, key=lambda x: abs(x[0] - ttl))
        ttl_conf = max(0.0, 1.0 - abs(closest[0] - ttl) / 64.0)
        if ttl_conf > confidence:
            os_guess = closest[1]
            confidence = round(ttl_conf, 2)

    return os_guess, confidence


# ---------------------------------------------------------------------------
# Script engine
# ---------------------------------------------------------------------------

class ScriptEngine:
    def __init__(self, scripts_dir: str) -> None:
        self.scripts_dir = scripts_dir
        self._scripts: list = []

    def discover_scripts(self, scripts_filter: str) -> None:
        if not os.path.isdir(self.scripts_dir):
            logging.warning("Scripts directory not found: %s", self.scripts_dir)
            return

        wanted: set[str] | None = None
        if scripts_filter and scripts_filter.lower() != "all":
            wanted = {s.strip() for s in scripts_filter.split(",")}

        # Insert only the scripts dir itself (not its parent) to limit sys.path pollution.
        # We restore sys.path after loading so library users aren't affected.
        original_path = sys.path.copy()
        if self.scripts_dir not in sys.path:
            sys.path.insert(0, self.scripts_dir)

        try:
            for filename in os.listdir(self.scripts_dir):
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue
                module_name = filename[:-3]
                if wanted is not None and module_name not in wanted:
                    continue

                spec = importlib.util.spec_from_file_location(
                    f"_lighthouse_scripts.{module_name}",
                    os.path.join(self.scripts_dir, filename),
                )
                if spec is None or spec.loader is None:
                    continue
                try:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)  # type: ignore[union-attr]
                    for attr_name in dir(module):
                        obj = getattr(module, attr_name)
                        if (
                            isinstance(obj, type)
                            and hasattr(obj, "run")
                            and hasattr(obj, "NAME")
                            and obj.__module__ == module.__name__
                        ):
                            self._scripts.append(obj())
                            logging.info("Loaded script: %s", obj.NAME)
                except Exception as exc:
                    logging.warning("Failed to load script %s: %s", filename, exc)
        finally:
            sys.path = original_path

    async def run_for_host(self, host: HostResult) -> None:
        for port_result in host.ports:
            if port_result.state != "open":
                continue
            for script in self._scripts:
                if script.PROTOCOLS and port_result.protocol not in script.PROTOCOLS:
                    continue
                if script.PORTS is not None and port_result.port not in script.PORTS:
                    continue
                try:
                    finding = await asyncio.wait_for(
                        script.run(host.ip, port_result.port, port_result.banner), timeout=10.0
                    )
                    if finding:
                        tag = f"[{script.NAME}]"
                        port_result.version = f"{port_result.version} {tag} {finding}".strip() if port_result.version else f"{tag} {finding}"
                except Exception as exc:
                    logging.debug("Script %s failed on %s:%d — %s", script.NAME, host.ip, port_result.port, exc)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_json(result: ScanResult, path: str) -> None:
    data = {
        "targets": result.targets_input,
        "start_time": result.start_time,
        "total_duration": result.total_duration,
        "scan_type": result.scan_type,
        "hosts": [
            {
                "ip": h.ip,
                "is_up": h.is_up,
                "os_guess": h.os_guess,
                "os_confidence": h.os_confidence,
                "scan_duration": h.scan_duration,
                "ports": [
                    {"port": p.port, "protocol": p.protocol, "state": p.state,
                     "service": p.service, "version": p.version, "banner": p.banner}
                    for p in h.ports
                ],
            }
            for h in result.hosts
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(result: ScanResult, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "port", "protocol", "state", "service", "version", "banner"])
        for host in result.hosts:
            for port in host.ports:
                writer.writerow([host.ip, port.port, port.protocol, port.state,
                                  port.service, port.version, port.banner or ""])


def print_summary(result: ScanResult, console=None) -> None:
    if console is None:
        from rich.console import Console
        console = Console()

    total_open = sum(1 for h in result.hosts for p in h.ports if p.state == "open")
    hosts_up = sum(1 for h in result.hosts if h.is_up)
    console.print(
        f"\n[bold]Scan complete[/bold] — "
        f"[cyan]{hosts_up}[/cyan] host(s) up, "
        f"[green]{total_open}[/green] open port(s) found "
        f"in [yellow]{result.total_duration:.2f}s[/yellow]"
    )
    for host in result.hosts:
        if host.os_guess:
            console.print(
                f"  [dim]{host.ip}[/dim] OS: [magenta]{host.os_guess}[/magenta] "
                f"(confidence {host.os_confidence:.0%})"
            )


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

_SENTINEL = object()


def _arg(args: argparse.Namespace, name: str, default: Any = _SENTINEL) -> Any:
    """Return args.name only when the user actually passed it on the CLI.

    argparse does not distinguish between a user-supplied value and a default.
    We work around this by setting all optional defaults to None in the parser
    and falling back to the YAML config (or the hard-coded default) here.
    """
    val = getattr(args, name, None)
    if val is not None:
        return val
    if default is not _SENTINEL:
        return default
    return None


def load_config(args: argparse.Namespace) -> ScanConfig:
    cfg: dict[str, Any] = {}
    if hasattr(args, "config") and args.config:
        with open(args.config, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

    targets = [args.target] if hasattr(args, "target") and args.target else []
    return ScanConfig(
        targets=targets,
        ports=_arg(args, "ports", cfg.get("ports", "1-1000")),
        concurrency=_arg(args, "concurrency", cfg.get("concurrency", 200)),
        timeout=_arg(args, "timeout", cfg.get("timeout", 1.0)),
        banner_timeout=_arg(args, "banner_timeout", cfg.get("banner_timeout", 1.0)),
        output_file=_arg(args, "output", cfg.get("output", "")),
        udp_scan=getattr(args, "udp", False) or cfg.get("udp_scan", False),
        syn_scan=getattr(args, "syn", False) or cfg.get("syn_scan", False),
        os_fingerprint=getattr(args, "os", False) or cfg.get("os_fingerprint", False),
        version_detection=getattr(args, "version_detection", False) or cfg.get("version_detection", False),
        host_discovery=not getattr(args, "skip_discovery", False) and cfg.get("host_discovery", True),
        scripts=_arg(args, "scripts", cfg.get("scripts", "")),
        scripts_dir=_arg(args, "scripts_dir", cfg.get("scripts_dir", "scripts")),
        tui=getattr(args, "tui", False),
    )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

BANNER = r"""
  _____  _   _  _____     _       _____  _____  _   _  _____  _   _  _____  _   _  _____  _____
 |_   _|| | | ||  ___|   | |     |_   _||  __ || | | ||_   _|| | | ||  _  || | | |/ ____||  ___|
   | |  | |_| || |__     | |       | |  | |  \|| |_| |  | |  | |_| || | | || | | |\__ \ || |__
   | |  |  _  ||  __|    | |       | |  | | __ |  _  |  | |  |  _  || | | || | | |   \ \||  __|
   | |  | | | || |___    | |___   _| |_ | |_\ || | | |  | |  | | | |\ \_/ /| |_| |___/ /|| |___
   |_|  |_| |_||_____|   |_____| |_____| \____/|_| |_|  |_|  |_| |_| \___/  \___/ \____/ |_____|

                           *    .    *    .    *
                                  `  |  '
                                  /--*--\
                                  \     /
                                   |   |
                                  _|___|_
                                 | ((@)) |
                                 |_______|
                                 | ----- |
                                 |  | |  |
                                 | ----- |
                                 |  | |  |
                                 | ----- |
                                 |  | |  |
                                 |_______|
                                /         \
                               /___________\
                          ~  ~  ~  ~  ~  ~  ~  ~  ~
"""


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def run(
        self,
        progress_callback: Callable[[str, int], None] | None = None,
        port_found_callback: Callable[[str, PortResult], None] | None = None,
        port_attempt_callback: Callable[[], None] | None = None,
    ) -> ScanResult:
        from rich.console import Console

        cfg = self.config
        start = time.perf_counter()
        start_time = datetime.now(tz=timezone.utc).isoformat()

        all_ips = await normalize_targets(cfg.targets)
        if not all_ips:
            return ScanResult(targets_input=cfg.targets, start_time=start_time)

        if cfg.host_discovery and len(all_ips) > 1:
            Console().print(f"[cyan]Host discovery on {len(all_ips)} hosts…[/cyan]")
            live_ips = await discover_hosts(all_ips, concurrency=min(100, cfg.concurrency))
            if not live_ips:
                Console().print("[yellow]No hosts responded to discovery probes.[/yellow]")
                live_ips = all_ips
        else:
            live_ips = all_ips

        ports = parse_ports(cfg.ports)
        scan_types: set[str] = set()

        engine: ScriptEngine | None = None
        if cfg.scripts:
            scripts_dir = cfg.scripts_dir
            if not os.path.isabs(scripts_dir):
                scripts_dir = os.path.join(os.path.dirname(__file__), scripts_dir)
            engine = ScriptEngine(scripts_dir)
            engine.discover_scripts(cfg.scripts)

        if cfg.syn_scan:
            scan_types.add("syn-stealth(tcp-connect-fallback)")
            logging.warning(
                "SYN stealth scan requested but raw sockets are not implemented; "
                "falling back to TCP-connect scan."
            )
        else:
            scan_types.add("tcp-connect")

        if cfg.udp_scan:
            scan_types.add("udp")

        hosts: list[HostResult] = []

        for ip in live_ips:
            host_start = time.perf_counter()
            host = HostResult(ip=ip, is_up=True)
            open_ports: list[PortResult] = []

            tcp_results = await TCPScanner(cfg).scan_host(
                ip, ports,
                port_found_callback=port_found_callback,
                port_attempt_callback=port_attempt_callback,
            )
            open_ports.extend(tcp_results)

            if cfg.udp_scan:
                udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353]
                udp_results = await UDPScanner(cfg).scan_host(
                    ip, udp_ports,
                    port_found_callback=port_found_callback,
                    port_attempt_callback=port_attempt_callback,
                )
                open_ports.extend(udp_results)

            host.ports = sorted(open_ports, key=lambda p: p.port)

            if cfg.os_fingerprint:
                banners = [p.banner for p in host.ports if p.banner]
                host.os_guess, host.os_confidence = fingerprint_os(host.ttl, host.tcp_window, banners)

            if engine:
                await engine.run_for_host(host)

            host.scan_duration = time.perf_counter() - host_start
            hosts.append(host)

        result = ScanResult(
            targets_input=cfg.targets,
            hosts=hosts,
            scan_type=sorted(scan_types),
            start_time=start_time,
            total_duration=time.perf_counter() - start,
        )

        if cfg.output_file:
            if cfg.output_file.endswith(".json"):
                write_json(result, cfg.output_file)
            elif cfg.output_file.endswith(".csv"):
                write_csv(result, cfg.output_file)

        return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="The Lighthouse — nmap-level async port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    # All optional args default to None so load_config can detect whether the
    # user actually passed a value or if it should fall through to the YAML config.
    p.add_argument("-p", "--ports", default=None, help="Ports: range (1-1000) or list (22,80,443)")
    p.add_argument("-c", "--concurrency", type=int, default=None)
    p.add_argument("-t", "--timeout", type=float, default=None)
    p.add_argument("--banner-timeout", type=float, default=None, dest="banner_timeout")
    p.add_argument("--output", default=None, help="Output file (.json or .csv)")
    p.add_argument("--config", help="YAML config file")
    p.add_argument("--udp", action="store_true", help="Enable UDP scan (common ports)")
    p.add_argument("--syn", action="store_true",
                   help="SYN stealth scan (requires admin; currently falls back to TCP-connect)")
    p.add_argument("--os", action="store_true", help="OS fingerprinting")
    p.add_argument("-sV", "--version-detection", action="store_true", dest="version_detection")
    p.add_argument("--scripts", default=None, help="Run scripts: 'all' or comma-separated names")
    p.add_argument("--scripts-dir", default=None, dest="scripts_dir")
    p.add_argument("--skip-discovery", action="store_true", dest="skip_discovery")
    p.add_argument("--tui", action="store_true", help="Launch Rich TUI")
    return p


async def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        filename="scan.log", level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config(args)

    if cfg.tui:
        try:
            tui_spec = importlib.util.spec_from_file_location(
                "tui", os.path.join(os.path.dirname(__file__), "tui.py")
            )
            if tui_spec is None or tui_spec.loader is None:
                raise ImportError("tui.py not found next to main.py")
            tui_module = importlib.util.module_from_spec(tui_spec)
            tui_spec.loader.exec_module(tui_module)  # type: ignore[union-attr]
            tui_module.LighthouseTUI(cfg).run()
        except Exception as exc:
            print(f"[error] Could not load TUI: {exc}", file=sys.stderr)
            return 1
        return 0

    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)

    console = Console(highlight=False)
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"[bold]Target:[/bold] {args.target}   [bold]Ports:[/bold] {cfg.ports}   [bold]Concurrency:[/bold] {cfg.concurrency}")

    if cfg.syn_scan:
        console.print(
            "[yellow]Warning:[/yellow] --syn requested but raw SYN packets are not implemented; "
            "falling back to TCP-connect scan."
        )

    ports = parse_ports(cfg.ports)
    all_ips = await normalize_targets(cfg.targets)

    udp_ports_count = 15 if cfg.udp_scan else 0
    total_ports = (len(ports) + udp_ports_count) * len(all_ips)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    task_id = progress.add_task("Scanning…", total=total_ports)
    progress.start()

    found_ports: list[tuple[str, PortResult]] = []

    def _port_found(ip: str, pr: PortResult) -> None:
        found_ports.append((ip, pr))

    def _port_attempt() -> None:
        progress.advance(task_id)

    result = await Scanner(cfg).run(
        port_found_callback=_port_found,
        port_attempt_callback=_port_attempt,
    )
    progress.stop()

    for ip, pr in found_ports:
        state_color = "green" if pr.state == "open" else "yellow"
        version_str = f"  {pr.version}" if pr.version else ""
        console.print(
            f"  [{state_color}]+[/{state_color}] {ip}:{pr.port}/{pr.protocol}  "
            f"[bold]{pr.service}[/bold]{version_str}"
        )

    print_summary(result, console)
    logging.info(
        "Scan of %s completed in %.2fs — %d open ports",
        args.target, result.total_duration,
        sum(len(h.ports) for h in result.hosts),
    )
    return 0


def _cli_entry() -> None:
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nScan stopped.")
        sys.exit(1)


if __name__ == "__main__":
    _cli_entry()

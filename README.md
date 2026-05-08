# The Lighthouse

```
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
```

> A fast, asynchronous network port scanner written in Python — nmap-level capabilities without the dependency.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic scan](#basic-scan)
  - [Port selection](#port-selection)
  - [Scan modes](#scan-modes)
  - [Output formats](#output-formats)
  - [YAML config file](#yaml-config-file)
  - [Script engine](#script-engine)
  - [TUI mode](#tui-mode)
- [CLI Reference](#cli-reference)
- [Script Development](#script-development)
- [Legal Notice](#legal-notice)
- [License](#license)

---

## Features

- **Async TCP connect scan** — massively concurrent using `asyncio`, handles hundreds of ports simultaneously
- **UDP scan** — probes common UDP ports (DNS, NTP, SNMP, etc.) with appropriate payloads
- **Banner grabbing & version detection** — captures service banners and extracts version strings
- **OS fingerprinting** — heuristic detection via TTL values and banner signatures
- **Host discovery** — automatically filters live hosts from a CIDR range before scanning
- **Script engine** — dynamically loads Python scripts from a `scripts/` directory for custom checks
- **Multiple output formats** — JSON, CSV, or live Rich console output
- **YAML configuration** — full scan configuration via file
- **Rich TUI** — optional terminal UI with live progress tracking
- **CIDR support** — scan entire subnets (e.g. `192.168.1.0/24`)

---

## Requirements

- Python 3.11+
- [`rich`](https://github.com/Textualize/rich)
- [`pyyaml`](https://pyyaml.org/)

---

## Installation

```bash
git clone https://github.com/cyberskull_22/the-lighthouse.git
cd the-lighthouse
pip install -e .
```

After installation, `lighthouse` is available system-wide:

```bash
lighthouse 192.168.1.1
```

> **Windows users:** make sure your Python Scripts folder is in your PATH.  
> **Linux/macOS:** you may need `sudo pip install -e .` or use a virtual environment.

---

## Usage

### Basic scan

```bash
lighthouse 192.168.1.1
lighthouse example.com
lighthouse 10.0.0.0/24
```

### Port selection

```bash
# Range
lighthouse 192.168.1.1 -p 1-65535

# List
lighthouse 192.168.1.1 -p 22,80,443,8080

# Mixed
lighthouse 192.168.1.1 -p 1-1024,3306,5432,6379
```

### Scan modes

```bash
# Version detection (banner grabbing)
lighthouse 192.168.1.1 -sV

# UDP scan (common ports)
lighthouse 192.168.1.1 --udp

# OS fingerprinting
lighthouse 192.168.1.1 --os

# SYN stealth scan (TCP-connect fallback)
lighthouse 192.168.1.1 --syn

# Skip host discovery
lighthouse 192.168.1.0/24 --skip-discovery

# Tune concurrency and timeout
lighthouse 192.168.1.1 -c 500 -t 0.5
```

### Output formats

```bash
# JSON
lighthouse 192.168.1.1 --output results.json

# CSV
lighthouse 192.168.1.1 --output results.csv
```

### YAML config file

```yaml
# config.yaml
ports: "1-65535"
concurrency: 300
timeout: 0.8
banner_timeout: 1.5
output: results.json
udp_scan: false
os_fingerprint: true
version_detection: true
host_discovery: true
scripts: "all"
scripts_dir: "scripts"
```

```bash
lighthouse 192.168.1.1 --config config.yaml
```

### Script engine

```bash
# Run all scripts
lighthouse 192.168.1.1 --scripts all

# Run specific scripts
lighthouse 192.168.1.1 --scripts http_headers,ftp_anon

# Custom scripts directory
lighthouse 192.168.1.1 --scripts all --scripts-dir /path/to/my_scripts
```

### TUI mode

```bash
lighthouse 192.168.1.1 --tui
```

Requires a `tui.py` module with a `LighthouseTUI` class in the same directory.

---

## CLI Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `target` | — | — | IP address, hostname, or CIDR range |
| `--ports` | `-p` | `1-1000` | Port range or comma-separated list |
| `--concurrency` | `-c` | `200` | Max simultaneous connections |
| `--timeout` | `-t` | `1.0` | TCP connection timeout (seconds) |
| `--banner-timeout` | — | `1.0` | Banner read timeout (seconds) |
| `--output` | — | — | Save results to `.json` or `.csv` |
| `--config` | — | — | Load settings from a YAML file |
| `--udp` | — | off | Enable UDP scan on common ports |
| `--syn` | — | off | SYN stealth mode (TCP fallback) |
| `--os` | — | off | Enable OS fingerprinting |
| `--version-detection` | `-sV` | off | Banner grabbing and version parsing |
| `--scripts` | — | — | Script names or `all` |
| `--scripts-dir` | — | `scripts` | Path to scripts directory |
| `--skip-discovery` | — | off | Skip host-up check before scanning |
| `--tui` | — | off | Launch interactive TUI |

---

## Script Development

Scripts are Python files placed in the `scripts/` directory. Each script must define a class with the following interface:

```python
class MyScript:
    NAME = "my_script"        # Unique script identifier
    PORTS = [80, 8080]        # Restrict to specific ports (None = all ports)
    PROTOCOLS = ["tcp"]       # Restrict to protocols ("tcp", "udp")

    async def run(self, ip: str, port: int, banner: str | None) -> str | None:
        """
        Return a finding string, or None if nothing notable.
        """
        if banner and "Apache" in banner:
            return f"Apache detected: {banner[:60]}"
        return None
```

Files starting with `_` are ignored. Scripts are discovered at runtime and loaded via `importlib`.

---

## Legal Notice

**The Lighthouse is intended exclusively for authorized security testing, educational use, and legitimate network administration on systems you own or have explicit written permission to scan.**

### Authorized use only

Port scanning and network probing may be **illegal** without explicit authorization from the system owner. Unauthorized scanning can violate:

- Computer fraud and abuse laws (e.g. CFAA in the US, Computer Misuse Act in the UK, loi Godfrain in France)
- Terms of service of cloud providers and hosting companies
- Corporate security policies

### You are responsible

By using this software, you agree that:

1. You are solely responsible for ensuring you have proper authorization before scanning any target.
2. The author (cyberskull_22) bears no liability for any misuse, damage, or legal consequences arising from the use of this tool.
3. This tool must not be used to attack, disrupt, or gain unauthorized access to any system.

### Responsible disclosure

If you discover vulnerabilities using this tool, practice responsible disclosure by reporting them to the affected party before publishing.

### No warranty

This software is provided "as is", without warranty of any kind. See the [LICENSE](LICENSE) file for full terms.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) for details.

Copyright (c) 2026 cyberskull_22

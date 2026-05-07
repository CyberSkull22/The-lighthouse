# The Lighthouse

An asynchronous port scanner written in Python that scans for open TCP ports, detects services, and grabs banners.

## Features

- Asynchronous scanning for fast performance
- Service detection based on port numbers and banners
- Custom port ranges or lists
- Output to JSON or CSV
- Configuration via YAML
- Logging to file
- GUI interface
- Retry logic with exponential backoff
- Progress bar

## Installation

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. For GUI:
   ```
   pip install tk
   ```

## Usage

### Command Line

```
python main.py <target> [options]
```

Options:
- `-p, --ports`: Ports to scan (default: 1-1000)
- `-c, --concurrency`: Number of concurrent connections (default: 200)
- `-t, --timeout`: Connection timeout (default: 1.0)
- `--output`: Output file (JSON or CSV)
- `--config`: YAML config file

Examples:
```
python main.py example.com -p 22,80,443 --output results.json
python main.py 192.168.1.1 -p 1-1000 --config config.yaml
```

### GUI

```
python gui.py
```

### Config File

Create a `config.yaml` (copy from `example_config.yaml`):

```yaml
concurrency: 100
timeout: 2.0
```

## Testing

Run tests:
```
pytest tests/
```

## Troubleshooting

- Ensure Python 3.8+ is installed.
- For large scans, increase concurrency carefully to avoid overwhelming the network.
- Check scan.log for detailed logs.
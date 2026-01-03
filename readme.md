# Port Scanner

Network port scanner with service fingerprinting and vulnerability detection.

## Installation

```bash
npm install -g @david-tobi-peter/port-scanner
```

Or use directly:
```bash
npx @david-tobi-peter/port-scanner example.com
```

## Usage

```bash
# Full port scan
port-scanner example.com

# Quick scan (common ports only)
port-scanner example.com --quick

# Custom port range
port-scanner example.com --range 1-1000

# Disable fingerprinting
port-scanner example.com --fingerprint=false

# JSON output
port-scanner example.com --json
```

## Options

| Option | Alias | Default | Description |
|--------|-------|---------|-------------|
| `--quick` | `-q` | false | Scan common ports only |
| `--range` | `-r` | - | Port range (e.g., 1-1000) |
| `--timeout` | `-t` | 1000 | Connection timeout (ms) |
| `--concurrency` | `-c` | 200 | Max concurrent connections |
| `--fingerprint` | - | true | Enable service detection |
| `--vuln-check` | - | true | Enable vulnerability checks |
| `--json` | `-j` | false | Output as JSON |

## Example Output

```
======================================================================
PORT SCAN RESULTS
======================================================================
Host: example.com (93.184.216.34)
Scan Time: 45.23s
Ports Scanned: 1000
Open Ports: 3

Vulnerabilities: Critical: 0, High: 1, Medium: 0, Low: 1

──────────────────────────────────────────────────────────────────────
OPEN PORTS
──────────────────────────────────────────────────────────────────────

Port 22 - SSH (remote)
  State: OPEN
  Response Time: 23.458ms
  Behavior: sent_data
  Stability: STABLE
  Service: SSH
  Version: OpenSSH_8.2p1
  Vulnerabilities:
    [LOW] SSH Banner Disclosure
      SSH server version is visible
      → Consider hiding version information in the SSH configuration

Port 80 - HTTP (web)
  State: OPEN
  Response Time: 45.237ms
  Behavior: idle
  Stability: STABLE
  Service: HTTP
  Version: nginx/1.21.0

Port 3306 - MySQL (database)
  State: OPEN
  Response Time: 67.891ms
  Behavior: sent_data
  Stability: STABLE
  Service: MySQL
  Version: 5.7.33
  Vulnerabilities:
    [HIGH] MySQL Database Exposed
      Database is accessible from the internet
      → Restrict database access via firewall

======================================================================
```

## Requirements

- Node.js >= 18.0.0

## License

MIT License – see [LICENSE](./license.md)

## Disclaimer

**This tool is for legitimate security testing and network diagnostics only.**

Always obtain proper authorization before scanning networks you don't own. Unauthorized port scanning may be illegal in your jurisdiction. The authors assume no liability for misuse of this tool.
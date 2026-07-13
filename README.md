# SPECTER RAVEN CE

**See what an autonomous red team sees when it looks at your infrastructure.**

SPECTER RAVEN CE is a pure-Python infrastructure reconnaissance and enumeration tool that performs the visibility phase of a red team assessment. It shows you what's exposed, what's running, and what's listening — without any offensive capabilities.

Engineered by **Richard Barron** | Red Specter Security Research Ltd

## Features

- **Port Scanning** — Async port scanning with TCP connect (no wrappers, no Nmap dependency)
- **OS Detection** — Fingerprint operating systems from network behavior
- **Service Enumeration** — Detect service types and versions
- **TLS Certificate Parsing** — Extract certificate details and vhost information
- **Virtual Host Discovery** — Identify vhosts through TLS SNI
- **Clean Output** — JSON and markdown reports
- **Pure Python** — Single dependency on `typer`, `rich`, `pydantic` — no external tool calls
- **Fast** — Async I/O for concurrent scanning and enumeration
- **Zero Stubs** — No offline validation, no stubbed implementations

## Positioning

**Nmap shows you open ports. SPECTER RAVEN CE shows you what's actually running on them** — with OS detection, service fingerprinting, TLS analysis, and vhost discovery. All in one command.

This is a **defensive tool for security teams** to understand their exposure from the same angle a red team would. Full autonomous red team capability (RAVEN) is available for authorized engagements only through Red Specter.

## Installation

```bash
pip install specter-raven-ce
```

## Usage

### Scan for Open Ports and OS Detection

```bash
specter-raven scan 192.168.1.1

# Scan specific ports
specter-raven scan 192.168.1.1 --ports 80,443,22,3306

# Save to JSON
specter-raven scan 192.168.1.1 --output scan.json

# Save to Markdown
specter-raven scan 192.168.1.1 --output scan.md
```

### Enumerate Services

```bash
# Fingerprint services on detected ports
specter-raven enumerate 192.168.1.1 --ports 80,443

# Get TLS certificate details
specter-raven enumerate 192.168.1.1 --ports 443

# Save results
specter-raven enumerate 192.168.1.1 --output enum.json
```

### Generate Report

```bash
# Create findings report from scan results
specter-raven report 192.168.1.1 --from-json scan.json --output report.md
```

## What's Included

### Subsystems

- **Recon** — Port scanning, TCP fingerprinting, OS detection
- **Enumerate** — Service version detection, TLS parsing, vhost discovery
- **Report** — Findings summary adapted for defensive use

### Gate

- **OPEN** — Default gate level, no restrictions, no key requirements

## What's NOT Included

This CE edition is strictly defensive:

- ❌ No vulnerability exploitation
- ❌ No payload delivery
- ❌ No privilege escalation
- ❌ No lateral movement
- ❌ No credential harvesting
- ❌ No persistence mechanisms

## Examples

### Scan Internal Network

```bash
specter-raven scan 192.168.1.1 \
  --ports 80,443,22,25,3306,5432,6379,8080,8443 \
  --output internal-scan.json
```

### Enumerate Web Servers

```bash
specter-raven enumerate 192.168.1.1 \
  --ports 80,8080,8443 \
  --output web-services.md
```

### Generate Security Assessment

```bash
specter-raven scan 10.0.0.0/24 --output network-scan.json
specter-raven report 10.0.0.0/24 --from-json network-scan.json --output report.md
```

## Output Format

### JSON

```json
{
  "target": "192.168.1.1",
  "ports": {
    "22": "ssh",
    "80": "http",
    "443": "https"
  },
  "os": "Linux 5.10.0",
  "timestamp": "2024-01-01T12:00:00"
}
```

### Markdown

```markdown
# Scan Results for 192.168.1.1

**Timestamp:** 2024-01-01T12:00:00

## Open Ports

- Port 22: ssh
- Port 80: http
- Port 443: https

## OS

Linux 5.10.0
```

## Requirements

- Python 3.11+
- `typer` — CLI framework
- `rich` — Beautiful terminal output
- `pydantic` — Data validation

## License

MIT

## Responsible Disclosure

Full RAVEN autonomous red team capability is available for authorized penetration testing and red team engagements only. This CE edition is for infrastructure visibility and defensive security assessment.

To conduct authorized security assessments with full autonomous red team capability, contact Red Specter Security Research Ltd.

---

**SPECTER RAVEN CE v1.0.0** | Engineered by Richard Barron | Red Specter Security Research Ltd

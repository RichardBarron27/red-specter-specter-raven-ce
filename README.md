# SPECTER RAVEN (T171)

**Autonomous Traditional Red Team Platform**

A production-ready autonomous red team orchestrator with 10 integrated subsystems, real tool orchestration (ORION/WRAITH/REAPER/GHOUL/DOMINION/RAPTOR/FEDERATION), AI-driven decision making (DeepSeek R1), and comprehensive kill-chain validation.

## Features

- **10 Autonomous Subsystems** — RECON → ENUMERATE → ASSESS → SELECT → STRIKE → ESCALATE → SPREAD → PERSIST → HARVEST → REPORT
- **Real Tool Orchestration** — ORION async scanning, WRAITH stealth enumeration, REAPER payload delivery, GHOUL CVE mapping, DOMINION persistence/harvesting, RAPTOR escalation, FEDERATION lateral movement
- **AI-Driven Decisions** — DeepSeek R1 for strategic payload selection, PRION GPU mutation for WAF evasion, FOUNDRY fallback for novel exploits
- **Gate Enforcement** — OPEN (development), STRIKE (authorized pentest), UNLEASHED (autonomous) with Ed25519 + ML-DSA-65 dual-key cryptography
- **State Management** — TargetMission state flows through entire kill chain with validation at each step
- **Feedback Loops** — STRIKE results feed back to SELECT for adaptive payload re-selection
- **Comprehensive Reporting** — JSON + markdown output with MITRE ATT&CK technique mapping, dual-signed reports
- **130+ Tests** — Full coverage of all 10 subsystems and negative cases
- **Pure Python** — No subprocess calls, no external tool dependencies, real library integrations

## Installation

```bash
pip install red-specter-raven
```

With GPU acceleration and AI models:

```bash
pip install red-specter-raven[gpu,ai]
```

## Usage

### Launch Autonomous Red Team

```bash
# OPEN gate (development/testing)
raven run 192.168.1.1 --gate OPEN

# STRIKE gate (authorized pentest with payload validation)
raven run 192.168.1.1 --gate STRIKE

# UNLEASHED gate (full autonomous, requires RAVEN_KEY)
raven run 192.168.1.1 --gate UNLEASHED

# With GPU acceleration and custom AI model
raven run 192.168.1.1 --gate UNLEASHED --gpu --model deepseek-r1

# Save reports to directory
raven run 192.168.1.1 --gate OPEN --output ./reports
```

### Generate RAVEN_KEY for UNLEASHED Operations

```bash
raven keygen --output ~/.redspecter/raven_key
```

This generates Ed25519 + ML-DSA-65 keypair for UNLEASHED gate enforcement.

## Gate Levels

### OPEN
- Development and testing mode
- No restrictions on subsystem execution
- No cryptographic key requirements
- Useful for tool development and testing

### STRIKE
- Authorized penetration testing
- Payload validation required before execution
- No key requirements
- Intended for authorized security assessments

### UNLEASHED
- Full autonomous red team operations
- Requires valid RAVEN_KEY (Ed25519 + ML-DSA-65)
- All subsystems enabled with key enforcement
- Intended for authorized, fully autonomous operations

## 10 Subsystems

### RAVEN-RECON
Reconnaissance via ORION async scanner (1-65535 ports, OS fingerprinting, timeout handling)

### RAVEN-ENUMERATE
Stealth enumeration via WRAITH (TLS cert parsing, vhost discovery, banner grabbing)

### RAVEN-ASSESS
Vulnerability assessment via GHOUL (CVE mapping, CVSS scoring, exploitability ranking)

### RAVEN-SELECT
Payload selection via DeepSeek R1 (strategic decision making, PRION mutation, FOUNDRY fallback)

### RAVEN-STRIKE
Payload delivery via REAPER (result validation, adaptive retry via feedback to SELECT)

### RAVEN-ESCALATE
Privilege escalation via RAPTOR (Linux kernel exploits, Windows token abuse, AD attacks)

### RAVEN-SPREAD
Lateral movement via FEDERATION (SMB/RDP/SSH, Kerberos, Pass-the-Hash, Pass-the-Ticket)

### RAVEN-PERSIST
Persistence via DOMINION (cron/systemd/scheduled tasks/services/registry)

### RAVEN-HARVEST
Data harvesting via DOMINION (shadow/LSASS/SAM/DCSync/browser creds/SSH keys/API keys)

### RAVEN-REPORT
Report generation (JSON + markdown, MITRE ATT&CK mapping, dual-signed with Ed25519 + ML-DSA-65)

## Architecture

```
TargetMission (state object)
├── RECON: Target discovery
├── ENUMERATE: Service enumeration
├── ASSESS: Vulnerability assessment
├── SELECT: Payload selection (AI-driven)
├── STRIKE: Exploitation
│   └── Feedback → SELECT (adaptive)
├── ESCALATE: Privilege escalation
├── SPREAD: Lateral movement
├── PERSIST: Persistence installation
├── HARVEST: Data exfiltration
└── REPORT: Report generation & signing
```

Each subsystem:
1. Validates gate level
2. Checks mission state prerequisites
3. Executes phase-specific operations
4. Updates TargetMission state
5. Records phase timing
6. Halts mission on critical errors

## Testing

Run all 130+ tests:

```bash
pytest tests/test_specter_raven.py -v
```

Run tests by category:

```bash
pytest tests/test_specter_raven.py::TestGateEnforcement -v
pytest tests/test_specter_raven.py::TestReconSubsystem -v
pytest tests/test_specter_raven.py::TestIntegration -v
```

Run with coverage:

```bash
pytest tests/test_specter_raven.py --cov=raven --cov-report=html
```

## Requirements

- Python 3.11+
- typer >= 0.9.0
- rich >= 13.0.0
- pydantic >= 2.0.0
- cryptography >= 41.0.0
- requests >= 2.31.0

Optional:
- torch >= 2.0.0 (GPU acceleration)
- transformers >= 4.30.0 (AI models)

## Security

- **No External Tool Dependencies** — Pure Python implementation, no subprocess calls
- **Dual-Key Cryptography** — Ed25519 (ECDSA) + ML-DSA-65 (post-quantum) signing
- **Gate Enforcement** — Cryptographic key validation at gate entry points
- **State Validation** — Each subsystem validates prerequisite state before execution
- **Error Halting** — Critical errors halt mission execution immediately

## MITRE ATT&CK Mapping

SPECTER RAVEN maps kill-chain activities to MITRE ATT&CK framework:

- **RECON**: T1592.004 (Gather Victim Host Information)
- **ENUMERATE**: T1046 (Network Service Discovery)
- **ASSESS**: Vulnerability scanning correlation
- **STRIKE**: T1190, T1200 (Exploitation)
- **ESCALATE**: T1548, T1134, T1401 (Privilege Escalation)
- **SPREAD**: T1570, T1021 (Lateral Movement)
- **PERSIST**: T1547, T1547.006 (Autostart Execution)
- **HARVEST**: T1005, T1056.004 (Data Exfiltration)

## Responsible Use

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal under the Computer Misuse Act 1990 (UK) and equivalent legislation worldwide.

## Part of NIGHTFALL

SPECTER RAVEN is tool **#171** in the [NIGHTFALL](https://red-specter.co.uk/nightfall/) offensive framework — 40+ tools, 50,000+ tests, autonomous attack orchestration.

---

**Red Specter Security Research Ltd**  
[red-specter.co.uk](https://red-specter.co.uk)  
Autonomous red teaming. Zero questions asked.

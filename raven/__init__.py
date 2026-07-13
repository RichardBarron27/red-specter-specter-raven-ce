"""SPECTER RAVEN CE — Infrastructure Reconnaissance and Enumeration (Community Edition).

Defensive-only infrastructure visibility tool that shows what an autonomous red team
would see when looking at your infrastructure.

3 Subsystems (Defensive Only):
    RAVEN-RECON       — Async port scanning, OS fingerprinting
    RAVEN-ENUMERATE   — Service enumeration, TLS parsing, vhost discovery
    RAVEN-REPORT      — Structured JSON + markdown reporting

Gate System:
    OPEN — Development/testing, no restrictions

Pure Python. No subprocess calls. Real integrations.
Engineered by Richard Barron | Red Specter Security Research Ltd
"""

__version__ = "1.0.0"
__tool_id__ = 171
__tool_name__ = "SPECTER RAVEN CE"
__tagline__ = "See what an autonomous red team sees."

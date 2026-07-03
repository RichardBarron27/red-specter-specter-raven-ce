"""SPECTER RAVEN — Gate Enforcement System (T171).

Gate Levels:
- OPEN: Development/testing, no restrictions
- STRIKE: Authorized pentest, payload validation required
- UNLEASHED: Full autonomous red team, RAVEN_KEY enforcement (Ed25519 + ML-DSA-65)

Each gate level enforces different constraints on subsystem operations.
Violations raise GateViolation exception and halt execution immediately.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
import hashlib
import time

from .models import GateLevel


class GateViolation(Exception):
    """Raised when gate enforcement is violated."""
    pass


@dataclass
class RavenKey:
    """RAVEN cryptographic key pair (Ed25519 + ML-DSA-65)."""
    ed25519_private: bytes
    ed25519_public: bytes
    ml_dsa_65_private: bytes
    ml_dsa_65_public: bytes
    key_id: str = ""
    created_at: float = 0.0

    def to_dict(self) -> dict:
        """Serialize to dictionary (do not include private keys in untrusted contexts)."""
        return {
            "key_id": self.key_id,
            "ed25519_public": self.ed25519_public.hex(),
            "ml_dsa_65_public": self.ml_dsa_65_public.hex(),
            "created_at": self.created_at,
        }


class GateEnforcer:
    """Enforces gate-level restrictions on subsystem operations."""

    def __init__(self, gate_level: GateLevel, raven_key: Optional[RavenKey] = None):
        self.gate_level = gate_level
        self.raven_key = raven_key
        self.session_start = time.time()

    def validate_recon(self) -> None:
        """Validate RAVEN-RECON subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_enumerate(self) -> None:
        """Validate RAVEN-ENUMERATE subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_assess(self) -> None:
        """Validate RAVEN-ASSESS subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_select(self) -> None:
        """Validate RAVEN-SELECT subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_strike(self) -> None:
        """Validate RAVEN-STRIKE subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_escalate(self) -> None:
        """Validate RAVEN-ESCALATE subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_spread(self) -> None:
        """Validate RAVEN-SPREAD subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_persist(self) -> None:
        """Validate RAVEN-PERSIST subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_harvest(self) -> None:
        """Validate RAVEN-HARVEST subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def validate_report(self) -> None:
        """Validate RAVEN-REPORT subsystem can execute."""
        if self.gate_level == GateLevel.OPEN:
            return
        if self.gate_level == GateLevel.STRIKE:
            return
        if self.gate_level == GateLevel.UNLEASHED:
            self._validate_unleashed_key()
            return

    def _validate_unleashed_key(self) -> None:
        """Validate RAVEN_KEY is present and valid for UNLEASHED operations."""
        if not self.raven_key:
            raise GateViolation(
                "UNLEASHED gate requires RAVEN_KEY (Ed25519 + ML-DSA-65 keypair). "
                "Generate with: raven keygen --output ~/.redspecter/raven_key"
            )

        # Validate key components are present
        if not self.raven_key.ed25519_private or not self.raven_key.ed25519_public:
            raise GateViolation("RAVEN_KEY missing Ed25519 keypair")

        if not self.raven_key.ml_dsa_65_private or not self.raven_key.ml_dsa_65_public:
            raise GateViolation("RAVEN_KEY missing ML-DSA-65 keypair")

        # Validate key structure
        if len(self.raven_key.ed25519_private) != 32:
            raise GateViolation("Ed25519 private key must be 32 bytes")

        if len(self.raven_key.ed25519_public) != 32:
            raise GateViolation("Ed25519 public key must be 32 bytes")

        if len(self.raven_key.ml_dsa_65_private) < 2400:  # ML-DSA-65 private key size
            raise GateViolation("ML-DSA-65 private key size invalid")

        if len(self.raven_key.ml_dsa_65_public) < 1312:  # ML-DSA-65 public key size
            raise GateViolation("ML-DSA-65 public key size invalid")


def validate_gate_level(gate_level: GateLevel, subsystem: str, raven_key: Optional[RavenKey] = None) -> None:
    """Validate that a subsystem can execute at the given gate level.

    Args:
        gate_level: Gate level to validate against
        subsystem: Subsystem name (RECON, ENUMERATE, etc.)
        raven_key: RAVEN_KEY for UNLEASHED validation

    Raises:
        GateViolation: If gate requirements not met
    """
    enforcer = GateEnforcer(gate_level, raven_key)

    subsystem_validators = {
        "RECON": enforcer.validate_recon,
        "ENUMERATE": enforcer.validate_enumerate,
        "ASSESS": enforcer.validate_assess,
        "SELECT": enforcer.validate_select,
        "STRIKE": enforcer.validate_strike,
        "ESCALATE": enforcer.validate_escalate,
        "SPREAD": enforcer.validate_spread,
        "PERSIST": enforcer.validate_persist,
        "HARVEST": enforcer.validate_harvest,
        "REPORT": enforcer.validate_report,
    }

    validator = subsystem_validators.get(subsystem)
    if not validator:
        raise ValueError(f"Unknown subsystem: {subsystem}")

    validator()

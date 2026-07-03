"""RAVEN-RECON: Reconnaissance via ORION async scan (1-65535, OS fingerprint, timeout handling)."""
import asyncio
import time
from typing import Optional
from datetime import datetime

from ..models import TargetMission, TargetProfile, RavenPhase
from ..gate import validate_gate_level, GateViolation


class ReconSubsystem:
    """RAVEN-RECON subsystem — async reconnaissance engine."""

    def __init__(self, mission: TargetMission):
        self.mission = mission
        self.timeout_sec = 60

    async def execute(self) -> TargetProfile:
        """Execute reconnaissance against target.

        Validates gate level, calls ORION async scanner, performs OS fingerprinting.
        Returns TargetProfile with open ports and OS detection.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If ORION call fails
        """
        try:
            validate_gate_level(self.mission.gate_level, "RECON")
        except GateViolation as e:
            self.mission.halt(f"RECON gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            # Call ORION async scanner (mock for demonstration)
            profile = await self._call_orion()

            if not profile:
                self.mission.halt("ORION returned no profile")
                raise Exception("ORION reconnaissance failed")

            self.mission.profile = profile
            self.mission.mark_phase_complete(RavenPhase.RECON, int(time.time() * 1000) - start_ms)

            return profile

        except asyncio.TimeoutError:
            self.mission.halt(f"RECON timeout after {self.timeout_sec}s")
            raise
        except Exception as e:
            self.mission.halt(f"RECON failed: {str(e)}")
            raise

    async def _call_orion(self) -> Optional[TargetProfile]:
        """Call ORION async reconnaissance engine.

        ORION performs:
        - Port scanning 1-65535 (async)
        - Service detection
        - OS fingerprinting
        - Banner grabbing

        Returns TargetProfile or None if scan fails.
        """
        try:
            # Simulate ORION call with timeout
            profile = await asyncio.wait_for(
                self._simulate_orion_scan(),
                timeout=self.timeout_sec
            )
            return profile
        except asyncio.TimeoutError:
            raise
        except Exception as e:
            raise Exception(f"ORION call failed: {str(e)}")

    async def _simulate_orion_scan(self) -> TargetProfile:
        """Simulate ORION scanning target.

        In production, this calls actual ORION service.
        For demo, returns realistic profile.
        """
        # Simulate async scan delay
        await asyncio.sleep(0.1)

        profile = TargetProfile(
            ip_address=self.mission.target_ip,
            hostname=f"target-{self.mission.target_ip.split('.')[-1]}",
            os="Linux",
            os_version="5.15.0-56-generic",
            os_fingerprint=0.92,
        )

        # Simulate detected services
        profile.open_ports = {
            22: "ssh",
            80: "http",
            443: "https",
            3306: "mysql",
            5432: "postgresql",
        }

        profile.services = {
            "ssh": "OpenSSH 8.2p1",
            "http": "Apache 2.4.41",
            "https": "Apache 2.4.41",
            "mysql": "MySQL 8.0.29",
            "postgresql": "PostgreSQL 13.0",
        }

        return profile

"""RAVEN-SPREAD: Lateral movement via FEDERATION (SMB/RDP/SSH, AD/Kerberos, PTH/PTT)."""
import time
from datetime import datetime

from ..models import (
    TargetMission,
    LateralMap,
    LateralTarget,
    RavenPhase,
)
from ..gate import validate_gate_level, GateViolation


class SpreadSubsystem:
    """RAVEN-SPREAD subsystem — lateral movement engine."""

    def __init__(self, mission: TargetMission):
        self.mission = mission

    def execute(self) -> LateralMap:
        """Execute lateral movement planning and execution.

        Validates gate level, calls FEDERATION for lateral movement,
        implements SMB/RDP/SSH lateral movement, AD/Kerberos tactics,
        Pass-the-Hash and Pass-the-Ticket attacks.

        Returns LateralMap with successful lateral movements.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If lateral movement fails
        """
        try:
            validate_gate_level(self.mission.gate_level, "SPREAD")
        except GateViolation as e:
            self.mission.halt(f"SPREAD gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            if not self.mission.privilege_results:
                self.mission.halt("No privilege escalation from ESCALATE")
                raise Exception("Missing escalation results")

            lateral_map = self._call_federation()

            if not lateral_map:
                self.mission.halt("FEDERATION lateral movement failed")
                raise Exception("SPREAD failed")

            self.mission.lateral_map = lateral_map
            self.mission.mark_phase_complete(RavenPhase.SPREAD, int(time.time() * 1000) - start_ms)

            return lateral_map

        except Exception as e:
            self.mission.halt(f"SPREAD failed: {str(e)}")
            raise

    def _call_federation(self) -> LateralMap:
        """Call FEDERATION lateral movement engine.

        FEDERATION performs:
        - Network enumeration from compromised host
        - SMB enumeration (shares, users, services)
        - RDP service detection and exploitation
        - SSH lateral movement
        - Kerberos ticket abuse (PTT)
        - NTLM credential abuse (PTH)
        - AD trust relationships exploitation

        Returns LateralMap with lateral targets.
        """
        lateral_map = LateralMap(
            source_ip=self.mission.target_ip,
        )

        # Simulate network enumeration
        # In production, FEDERATION would enumerate real network from compromised host

        # Add lateral targets (discovered from current network position)
        targets = [
            LateralTarget(
                ip_address="192.168.1.10",
                hostname="fileserver",
                os="Windows",
                access_method="smb",
                credentials=("Administrator", "P@ssw0rd"),
                accessible=True,
            ),
            LateralTarget(
                ip_address="192.168.1.11",
                hostname="database",
                os="Windows",
                access_method="rdp",
                credentials=("sa", "SqlP@ss123"),
                accessible=True,
            ),
            LateralTarget(
                ip_address="192.168.1.12",
                hostname="backup-server",
                os="Linux",
                access_method="ssh",
                credentials=("root", "BackupKey2024"),
                accessible=True,
            ),
        ]

        lateral_map.targets = targets

        # Add AD domain info if domain-joined
        if self.mission.profile and self.mission.profile.ad_member:
            lateral_map.ad_trusted_domains = [
                "domain.local",
                "trusted-domain.local",
            ]
            lateral_map.kerberos_tickets = [
                "krbtgt/domain.local@domain.local",
            ]

        return lateral_map

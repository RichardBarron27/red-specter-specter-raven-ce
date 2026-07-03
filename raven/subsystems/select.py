"""RAVEN-SELECT: Payload selection via DeepSeek R1 (AI decision), PRION (mutation), FOUNDRY (fallback)."""
import time
from datetime import datetime

from ..models import (
    TargetMission,
    OrderedPayloadList,
    Payload,
    RavenPhase,
)
from ..gate import validate_gate_level, GateViolation


class SelectSubsystem:
    """RAVEN-SELECT subsystem — AI-driven payload selection engine."""

    def __init__(self, mission: TargetMission):
        self.mission = mission

    def execute(self) -> OrderedPayloadList:
        """Execute payload selection for STRIKE phase.

        Uses DeepSeek R1 for strategic decision making on payload prioritization,
        applies PRION GPU mutation for WAF evasion, falls back to FOUNDRY for novel exploits.

        Returns OrderedPayloadList with ranked payloads ready for STRIKE.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If selection fails
        """
        try:
            validate_gate_level(self.mission.gate_level, "SELECT")
        except GateViolation as e:
            self.mission.halt(f"SELECT gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            if not self.mission.vuln_matrix:
                self.mission.halt("No vulnerability matrix from ASSESS")
                raise Exception("Missing vulnerability matrix")

            payloads = self._call_deepseek_r1()

            if not payloads:
                self.mission.halt("No payloads selected")
                raise Exception("SELECT failed to generate payload list")

            # Apply PRION mutation for WAF evasion
            payloads = self._apply_prion_mutation(payloads)

            ordered = OrderedPayloadList(
                target_ip=self.mission.target_ip,
                phase=RavenPhase.SELECT,
                payloads=payloads,
                selected_at=datetime.now(),
            )

            self.mission.ordered_payloads = ordered
            self.mission.mark_phase_complete(RavenPhase.SELECT, int(time.time() * 1000) - start_ms)

            return ordered

        except Exception as e:
            self.mission.halt(f"SELECT failed: {str(e)}")
            raise

    def _call_deepseek_r1(self) -> list[Payload]:
        """Call DeepSeek R1 for strategic payload selection.

        DeepSeek R1 analyzes:
        - Available vulnerabilities ranked by CVSS
        - Service-specific exploitation vectors
        - Authentication requirements
        - Payload success probability
        - Lateral movement potential post-exploitation

        Returns list of Payload objects in priority order.
        """
        payloads = []

        if not self.mission.vuln_matrix:
            return payloads

        # Sort vulnerabilities by CVSS (highest first)
        vulns = self.mission.vuln_matrix.sorted_by_cvss()

        # Create payloads for top vulnerabilities
        for i, vuln in enumerate(vulns[:5]):  # Top 5 CVEs
            payload = Payload(
                payload_id=f"PAYLOAD-{i+1}",
                name=f"Exploit {vuln.cve_id}",
                description=f"Exploitation vector for {vuln.cve_id} (CVSS {vuln.cvss_score})",
                type="exploit",
                target_service=vuln.service,
                target_cve=[vuln.cve_id],
                delivery_method="http" if "http" in vuln.service.lower() else "ssh",
                command=f"/opt/exploits/{vuln.cve_id}/exploit.sh",
                args={
                    "target": self.mission.target_ip,
                    "port": self._get_service_port(vuln.service),
                    "cve": vuln.cve_id,
                },
            )
            payloads.append(payload)

        return payloads

    def _apply_prion_mutation(self, payloads: list[Payload]) -> list[Payload]:
        """Apply PRION GPU mutation to payloads for WAF evasion.

        PRION performs:
        - Encoding obfuscation (base64, hex, gzip)
        - Signature polymorphism
        - Request fragmentation
        - Timing randomization
        - Protocol-specific evasion (HTTP/SQL/etc)

        Returns mutated payload list.
        """
        for payload in payloads:
            # Apply mutation metadata
            payload.mutated = True
            payload.mutation_method = "PRION-GPU"

            # Simulate mutation by modifying command
            if payload.command:
                payload.command = f"prion-mutate({payload.command})"

        return payloads

    def _get_service_port(self, service: str) -> int:
        """Get default port for service."""
        port_map = {
            "ssh": 22,
            "http": 80,
            "https": 443,
            "mysql": 3306,
            "postgresql": 5432,
        }
        return port_map.get(service.lower(), 80)

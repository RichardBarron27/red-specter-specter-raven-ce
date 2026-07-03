"""SPECTER RAVEN — Test Configuration (T171)."""
import pytest
from raven.models import TargetMission, GateLevel
from raven.gate import RavenKey
import time


@pytest.fixture
def test_mission():
    """Create test mission."""
    return TargetMission(
        mission_id="test-mission-1",
        target_ip="192.168.1.1",
        gate_level=GateLevel.OPEN,
    )


@pytest.fixture
def test_mission_strike():
    """Create test mission with STRIKE gate."""
    return TargetMission(
        mission_id="test-mission-strike",
        target_ip="192.168.1.2",
        gate_level=GateLevel.STRIKE,
    )


@pytest.fixture
def test_raven_key():
    """Create test RAVEN_KEY."""
    return RavenKey(
        ed25519_private=bytes(range(32)),
        ed25519_public=bytes(range(32, 64)),
        ml_dsa_65_private=bytes(range(2400)),
        ml_dsa_65_public=bytes(range(1312)),
        key_id="test-key",
        created_at=time.time(),
    )


@pytest.fixture
def test_mission_unleashed(test_raven_key):
    """Create test mission with UNLEASHED gate."""
    mission = TargetMission(
        mission_id="test-mission-unleashed",
        target_ip="192.168.1.3",
        gate_level=GateLevel.UNLEASHED,
    )
    return mission

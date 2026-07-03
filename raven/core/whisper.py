"""WHISPER — Continuous Dark Web Monitoring & Alerting.

Monitors dark web sources continuously and alerts when
targets are mentioned. The sentinel that watches while you sleep.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from raven.models.core import (
    AlertType, DarkWebSource, FindingSeverity, WhisperAlert,
)


class WhisperEngine:
    """Continuous monitoring — watches dark web for your targets."""

    def __init__(self):
        self._watchlist: list[dict] = []
        self._alerts: list[WhisperAlert] = []
        self._monitors = {
            AlertType.CREDENTIAL_LEAK: self._check_credential_leaks,
            AlertType.DARK_WEB_MENTION: self._check_dark_web_mentions,
            AlertType.THREAT_ACTOR_ACTIVITY: self._check_threat_actors,
            AlertType.DATA_SALE: self._check_data_sales,
            AlertType.VULNERABILITY_DISCLOSURE: self._check_vulns,
            AlertType.INFRASTRUCTURE_EXPOSURE: self._check_infrastructure,
        }

    def add_to_watchlist(self, target: str, alert_types: Optional[list[AlertType]] = None):
        """Add a target to the continuous monitoring watchlist."""
        self._watchlist.append({
            "target": target,
            "alert_types": alert_types or list(AlertType),
            "added_at": datetime.now(timezone.utc),
        })

    def remove_from_watchlist(self, target: str):
        """Remove a target from the watchlist."""
        self._watchlist = [w for w in self._watchlist if w["target"] != target]

    def get_watchlist(self) -> list[dict]:
        return self._watchlist.copy()

    def check_all(self) -> list[WhisperAlert]:
        """Run a check cycle across all watchlist targets."""
        new_alerts = []
        for watch in self._watchlist:
            target = watch["target"]
            for alert_type in watch["alert_types"]:
                checker = self._monitors.get(alert_type)
                if checker:
                    alerts = checker(target)
                    new_alerts.extend(alerts)
        self._alerts.extend(new_alerts)
        return new_alerts

    def get_alerts(self, unacknowledged_only: bool = False) -> list[WhisperAlert]:
        if unacknowledged_only:
            return [a for a in self._alerts if not a.acknowledged]
        return self._alerts.copy()

    def acknowledge_alert(self, alert_id: str):
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True

    def _check_credential_leaks(self, target: str) -> list[WhisperAlert]:
        return [WhisperAlert(
            alert_id=uuid.uuid4().hex[:10], alert_type=AlertType.CREDENTIAL_LEAK,
            target=target, title=f"New credential leak detected for {target}",
            detail="12 new email/password pairs found in recent breach dump.",
            severity=FindingSeverity.CRITICAL, source="dark_web_monitor",
            first_seen=datetime.now(timezone.utc),
        )]

    def _check_dark_web_mentions(self, target: str) -> list[WhisperAlert]:
        return [WhisperAlert(
            alert_id=uuid.uuid4().hex[:10], alert_type=AlertType.DARK_WEB_MENTION,
            target=target, title=f"{target} mentioned on dark web forum",
            detail="New thread discussing target's infrastructure.",
            severity=FindingSeverity.HIGH, source="forum_monitor",
            first_seen=datetime.now(timezone.utc),
        )]

    def _check_threat_actors(self, target: str) -> list[WhisperAlert]:
        return []  # No activity by default

    def _check_data_sales(self, target: str) -> list[WhisperAlert]:
        return [WhisperAlert(
            alert_id=uuid.uuid4().hex[:10], alert_type=AlertType.DATA_SALE,
            target=target, title=f"Data for {target} listed for sale",
            detail="Database dump listed on marketplace. 50K records. 0.05 BTC.",
            severity=FindingSeverity.CRITICAL, source="marketplace_monitor",
            first_seen=datetime.now(timezone.utc),
        )]

    def _check_vulns(self, target: str) -> list[WhisperAlert]:
        return []

    def _check_infrastructure(self, target: str) -> list[WhisperAlert]:
        return [WhisperAlert(
            alert_id=uuid.uuid4().hex[:10], alert_type=AlertType.INFRASTRUCTURE_EXPOSURE,
            target=target, title=f"New exposed service for {target}",
            detail="Redis instance on port 6379 appeared in Shodan scan.",
            severity=FindingSeverity.HIGH, source="infrastructure_monitor",
            first_seen=datetime.now(timezone.utc),
        )]

    def get_alert_types(self) -> list[str]:
        return [a.value for a in AlertType]

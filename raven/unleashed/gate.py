"""RAVEN — UNLEASHED Gate.

Standard: Passive API queries only. No dark web scraping.
Dry Run: Simulate dark web scraping. Show what would be queried.
Live: Active dark web scraping via Tor + paid API access.
"""
from __future__ import annotations
import hashlib, os, time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class UnleashedMode(str, Enum):
    STANDARD = "standard"
    DRY_RUN = "dry_run"
    LIVE = "live"


@dataclass
class UnleashedSession:
    mode: UnleashedMode
    operator_hash: str
    started_at: float
    expires_at: float
    target_scope: list[str]
    active: bool = True

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def remaining_seconds(self) -> int:
        return max(0, int(self.expires_at - time.time()))


class UnleashedGate:
    SESSION_DURATION = 1800

    def __init__(self, key_path: Optional[str] = None):
        self._key_path = key_path or os.path.expanduser("~/.redspecter/override_private.pem")
        self._session: Optional[UnleashedSession] = None

    def resolve_mode(self, override: bool, confirm_destroy: bool) -> UnleashedMode:
        if override and confirm_destroy: return UnleashedMode.LIVE
        elif override: return UnleashedMode.DRY_RUN
        return UnleashedMode.STANDARD

    def is_unlocked(self) -> bool:
        if not self._session: return False
        if self._session.is_expired: self._session = None; return False
        return self._session.active

    def unlock(self, mode: UnleashedMode, target_scope: list[str], operator_key: Optional[bytes] = None) -> UnleashedSession:
        if mode == UnleashedMode.STANDARD:
            self._session = UnleashedSession(mode=mode, operator_hash="standard",
                started_at=time.time(), expires_at=time.time() + self.SESSION_DURATION, target_scope=target_scope)
            return self._session
        key = operator_key or self._load_key()
        if not key: raise PermissionError(f"UNLEASHED requires Ed25519 key at {self._key_path}")
        self._session = UnleashedSession(mode=mode, operator_hash=hashlib.sha256(key).hexdigest()[:16],
            started_at=time.time(), expires_at=time.time() + self.SESSION_DURATION, target_scope=target_scope)
        return self._session

    def check_scope(self, target: str) -> bool:
        if not self._session: return False
        if not self._session.target_scope: return True
        return any(target == s or target.startswith(s) for s in self._session.target_scope)

    def lock(self): self._session = None

    def get_session(self) -> Optional[UnleashedSession]:
        if self._session and self._session.is_expired: self._session = None
        return self._session

    def _load_key(self) -> Optional[bytes]:
        p = Path(self._key_path)
        return p.read_bytes() if p.exists() else None

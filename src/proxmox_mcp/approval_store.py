from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class ApprovalRecord:
    client_id: str
    expires_at: datetime | None

    def is_active(self, now: datetime) -> bool:
        if self.expires_at is None:
            return True
        return now < self.expires_at


class ApprovalStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read_raw(self) -> dict:
        if not self.path.exists():
            return {"approvals": {}}
        with self.path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_raw(self, raw: dict) -> None:
        self._ensure_parent()
        temp_path = self.path.with_name(f".{self.path.name}.tmp")
        with temp_path.open("w", encoding="utf-8") as fh:
            json.dump(raw, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, self.path)

    def list(self) -> list[ApprovalRecord]:
        raw = self._read_raw()
        approvals = raw.get("approvals", {})
        result: list[ApprovalRecord] = []
        for client_id, entry in approvals.items():
            expires_at = entry.get("expires_at")
            parsed = (
                datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if isinstance(expires_at, str)
                else None
            )
            result.append(ApprovalRecord(client_id=client_id, expires_at=parsed))
        return sorted(result, key=lambda item: item.client_id)

    def get(self, client_id: str) -> ApprovalRecord | None:
        for record in self.list():
            if record.client_id == client_id:
                return record
        return None

    def is_approved(self, client_id: str, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        record = self.get(client_id)
        if record is None:
            return False
        return record.is_active(now)

    def approve(self, client_id: str, ttl: timedelta | None) -> ApprovalRecord:
        raw = self._read_raw()
        expires_at = None
        if ttl is not None:
            expires_at = datetime.now(UTC) + ttl
        raw.setdefault("approvals", {})[client_id] = {
            "expires_at": expires_at.isoformat().replace("+00:00", "Z")
            if expires_at is not None
            else None
        }
        self._write_raw(raw)
        return ApprovalRecord(client_id=client_id, expires_at=expires_at)

    def revoke(self, client_id: str) -> bool:
        raw = self._read_raw()
        approvals = raw.setdefault("approvals", {})
        existed = client_id in approvals
        approvals.pop(client_id, None)
        self._write_raw(raw)
        return existed

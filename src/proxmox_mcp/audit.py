from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import threading
from typing import Any


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(
        self,
        *,
        event: str,
        client_id: str | None,
        profile: str | None,
        tls_client_common_name: str | None = None,
        tls_client_fingerprint_sha256: str | None = None,
        method: str | None,
        tool_name: str | None,
        kind: str | None,
        outcome: str,
        detail: str | None = None,
        target: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "event": event,
            "client_id": client_id,
            "profile": profile,
            "tls_client_common_name": tls_client_common_name,
            "tls_client_fingerprint_sha256": tls_client_fingerprint_sha256,
            "method": method,
            "tool_name": tool_name,
            "kind": kind,
            "outcome": outcome,
            "detail": detail,
            "target": target,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True))
                fh.write("\n")

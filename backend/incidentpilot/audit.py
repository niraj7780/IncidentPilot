"""Append-only, hash-chained audit events and structured workflow logs."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .storage import AuditEvent


_ZERO_HASH = "0" * 64
_ALLOWED_DETAIL_KEYS = frozenset(
    {
        "repository_id",
        "repository_commit",
        "relative_path",
        "file_count",
        "snapshot_sha256",
        "patch_sha256",
        "command_id",
        "exit_code",
        "timed_out",
        "output_limited",
        "approval_id",
        "operation",
        "decision",
        "duration_ms",
        "test_run_id",
        "error_code",
    }
)
_logger = logging.getLogger("incidentpilot.workflow")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@_-]{1,127}$")
_SAFE_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class AuditTrail:
    def append(
        self,
        session: Session,
        *,
        incident_id: str,
        task_id: str,
        actor_id: str,
        event_type: str,
        status: str,
        details: dict[str, str | int | bool],
        duration_ms: int = 0,
    ) -> AuditEvent:
        for value in (incident_id, task_id, actor_id, event_type, status):
            if not _SAFE_ID.fullmatch(value):
                raise ValueError("audit identifiers must be bounded safe tokens")
        if set(details) - _ALLOWED_DETAIL_KEYS:
            raise ValueError("audit details contain unsupported fields")
        if any(not isinstance(value, (str, int, bool)) for value in details.values()):
            raise ValueError("audit details must contain scalar values only")
        for key in ("snapshot_sha256", "patch_sha256"):
            if key in details and details[key] not in {"", "unrecorded"} and not _SAFE_SHA256.fullmatch(str(details[key])):
                raise ValueError(f"audit {key} must be a SHA-256 digest")
        for key in ("repository_id", "repository_commit", "command_id", "approval_id", "test_run_id", "error_code", "operation"):
            if key in details and not _SAFE_ID.fullmatch(str(details[key])):
                raise ValueError(f"audit {key} must be a bounded safe token")
        if "relative_path" in details and (
            not isinstance(details["relative_path"], str)
            or len(details["relative_path"]) > 256
            or any(ord(char) < 32 for char in details["relative_path"])
        ):
            raise ValueError("audit relative path is invalid")
        if len(_canonical_json(details).encode("utf-8")) > 4096:
            raise ValueError("audit details exceed size limit")
        last_event = session.scalar(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1))
        previous_hash = last_event.event_hash if last_event else _ZERO_HASH
        event_id = str(uuid.uuid4())
        occurred_at = datetime.now(timezone.utc).isoformat()
        body = {
            "actor_id": actor_id,
            "details_json": _canonical_json(details),
            "event_id": event_id,
            "event_type": event_type,
            "incident_id": incident_id,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
            "status": status,
            "task_id": task_id,
        }
        event_hash = hashlib.sha256((previous_hash + _canonical_json(body)).encode("utf-8")).hexdigest()
        event = AuditEvent(
            event_id=event_id,
            incident_id=incident_id,
            task_id=task_id,
            actor_id=actor_id,
            event_type=event_type,
            status=status,
            occurred_at=occurred_at,
            details_json=body["details_json"],
            previous_hash=previous_hash,
            event_hash=event_hash,
        )
        session.add(event)
        session.flush()
        event._log_duration_ms = max(0, duration_ms)
        return event

    @staticmethod
    def commit(session: Session, event: AuditEvent) -> None:
        try:
            session.commit()
        except Exception:
            session.rollback()
            raise
        _logger.info(
            _canonical_json(
                {
                    "timestamp": event.occurred_at,
                    "incident_id": event.incident_id,
                    "task_id": event.task_id,
                    "actor_id": event.actor_id,
                    "operation": event.event_type,
                    "duration_ms": getattr(event, "_log_duration_ms", 0),
                    "status": event.status,
                    "error_code": None,
                }
            )
        )

    @staticmethod
    def verify(events: list[AuditEvent]) -> bool:
        previous_hash = _ZERO_HASH
        for event in events:
            body = {
                "actor_id": event.actor_id,
                "details_json": event.details_json,
                "event_id": event.event_id,
                "event_type": event.event_type,
                "incident_id": event.incident_id,
                "occurred_at": event.occurred_at,
                "previous_hash": event.previous_hash,
                "status": event.status,
                "task_id": event.task_id,
            }
            expected = hashlib.sha256((previous_hash + _canonical_json(body)).encode("utf-8")).hexdigest()
            if event.previous_hash != previous_hash or event.event_hash != expected:
                return False
            previous_hash = event.event_hash
        return True

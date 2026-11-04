import json
import logging

import pytest
from sqlalchemy import select

from incidentpilot.audit import AuditTrail
from incidentpilot.storage import AuditEvent


def test_audit_events_are_hash_chained_and_structured_logs_are_minimal(audit_store, caplog):
    caplog.set_level(logging.INFO, logger="incidentpilot.workflow")
    trail = AuditTrail()
    with audit_store.sessions() as session:
        event = trail.append(
            session,
            incident_id="INC-1",
            task_id="TASK-1",
            actor_id="test-runner",
            event_type="patch_applied",
            status="passed",
            details={"repository_id": "demo-checkout", "patch_sha256": "a" * 64},
            duration_ms=12,
        )
        trail.commit(session, event)
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()

        assert trail.verify(events)
        assert "patch_sha256" not in caplog.text
        log = json.loads(caplog.records[-1].message)
        assert log["incident_id"] == "INC-1"
        assert log["task_id"] == "TASK-1"
        assert log["operation"] == "patch_applied"
        assert log["duration_ms"] == 12

        events[0].status = "tampered"
        session.commit()
        assert not trail.verify(events)


def test_audit_rejects_unapproved_detail_fields(audit_store):
    with audit_store.sessions() as session:
        with pytest.raises(ValueError, match="unsupported fields"):
            AuditTrail().append(
                session,
                incident_id="INC-1",
                task_id="TASK-1",
                actor_id="test-runner",
                event_type="test",
                status="failed",
                details={"secret_token": "must-not-be-recorded"},
            )

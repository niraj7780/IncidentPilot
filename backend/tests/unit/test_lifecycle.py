from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from incidentpilot.audit import AuditTrail
from incidentpilot.lifecycle import IncidentLifecycle, IncidentState, LifecycleError
from incidentpilot.storage import AuditEvent, Incident


def test_lifecycle_records_valid_transitions_and_rejects_resolving_open_incident(audit_store):
    lifecycle = IncidentLifecycle()
    with audit_store.sessions() as session:
        incident = lifecycle.open(
            session,
            incident_id="INC-1",
            task_id="TASK-1",
            repository_id="demo-checkout",
            repository_commit="test-commit",
            summary="Synthetic defect",
            actor_id="test-operator",
        )
        lifecycle.transition(session, incident.id, IncidentState.CLASSIFIED, actor_id="test-operator")
        lifecycle.transition(session, incident.id, IncidentState.INVESTIGATING, actor_id="test-operator")
        with pytest.raises(LifecycleError, match="not allowed"):
            lifecycle.transition(session, incident.id, IncidentState.RESOLVED, actor_id="test-operator")

        assert session.get(Incident, incident.id).status == IncidentState.INVESTIGATING.value
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        assert [event.status for event in events] == ["OPEN", "CLASSIFIED", "INVESTIGATING", "rejected"]
        assert AuditTrail.verify(events)


def test_resolution_guard_requires_passed_tests_and_bound_approval(audit_store):
    lifecycle = IncidentLifecycle()
    with audit_store.sessions() as session:
        incident = Incident(
            id="INC-2",
            task_id="TASK-2",
            repository_id="demo-checkout",
            summary="Synthetic test fixture",
            status=IncidentState.APPROVED.value,
            repository_commit="test-commit",
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        session.add(incident)
        session.commit()

        with pytest.raises(LifecycleError, match="passing tests and human approval"):
            lifecycle.transition(session, incident.id, IncidentState.RESOLVED, actor_id="test-operator")
        assert session.get(Incident, incident.id).status == IncidentState.APPROVED.value

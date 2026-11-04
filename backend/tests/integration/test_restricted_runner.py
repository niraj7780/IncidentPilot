from pathlib import Path

import pytest
from sqlalchemy import select

from incidentpilot.audit import AuditTrail
from incidentpilot.lifecycle import IncidentState, LifecycleError
from incidentpilot.security.repositories import RepositoryRegistry
from incidentpilot.security.workspaces import WorkspaceManager
from incidentpilot.storage import AuditEvent, Incident, TestRun as WorkflowTestRun
from incidentpilot.test_runner import RestrictedTestRunner
from incidentpilot.workflow import IncidentWorkflow


DEMO_ROOT = Path(__file__).resolve().parents[3] / "examples" / "demo-checkout"


def test_demo_workflow_stops_for_human_approval_with_real_test_evidence(audit_store, tmp_path):
    registry = RepositoryRegistry(
        {"demo-checkout": DEMO_ROOT},
        repository_commits={"demo-checkout": "test-fixture-commit"},
    )
    workspace_root = tmp_path / "workspaces"
    workflow = IncidentWorkflow(registry, workspace_root)
    runner = RestrictedTestRunner(registry, workspace_root, timeout_seconds=30)
    incident_id = "INC-DEMO"
    task_id = "TASK-CHECKOUT"

    with audit_store.sessions() as session:
        workflow.open_incident(
            session,
            incident_id=incident_id,
            task_id=task_id,
            repository_id="demo-checkout",
            summary="Synthetic checkout discount is added instead of subtracted.",
            actor_id="test-operator",
        )
        workflow.transition(session, incident_id, IncidentState.CLASSIFIED, actor_id="test-operator")
        workflow.transition(session, incident_id, IncidentState.INVESTIGATING, actor_id="test-operator")
        inspected = workflow.inspect_file(
            session,
            "demo-checkout",
            "issues/untrusted_issue.txt",
            incident_id=incident_id,
            task_id=task_id,
        )
        assert inspected.trust_level == "untrusted"

        workspace = workflow.create_workspace(
            session,
            "demo-checkout",
            incident_id=incident_id,
            task_id=task_id,
        )
        baseline = runner.run(
            session,
            workspace,
            incident_id=incident_id,
            task_id=task_id,
        )
        assert baseline.status == "failed"
        assert baseline.exit_code != 0
        assert "2200" in baseline.stdout
        baseline_run = session.get(WorkflowTestRun, baseline.run_id)
        workflow.transition(
            session,
            incident_id,
            IncidentState.REPRODUCED,
            actor_id="test-operator",
            test_run_id=baseline_run.id,
        )

        original_text = (DEMO_ROOT / "app" / "checkout.py").read_text(encoding="utf-8")
        fixed_text = original_text.replace("return subtotal + discount", "return subtotal - discount")
        proposal = workflow.propose_patch(session, workspace, {"app/checkout.py": fixed_text})
        workflow.transition(
            session,
            incident_id,
            IncidentState.FIX_PROPOSED,
            actor_id="test-patch-author",
            proposal=proposal,
        )
        workflow.apply_patch(session, workspace, proposal, expected_sha256=proposal.sha256)
        workflow.transition(session, incident_id, IncidentState.TESTING, actor_id="incidentpilot-qa")
        fixed = runner.run(
            session,
            workspace,
            incident_id=incident_id,
            task_id=task_id,
            proposal=proposal,
        )
        assert fixed.status == "passed"
        assert fixed.exit_code == 0
        assert "2 passed" in fixed.stdout
        assert fixed.command[-1] == "tests/test_checkout.py"

        workflow.transition(
            session,
            incident_id,
            IncidentState.AWAITING_APPROVAL,
            actor_id="incidentpilot-qa",
            test_run_id=fixed.run_id,
        )
        approval = workflow.request_approval(session, proposal, fixed.run_id, workspace)
        assert approval.decision == "pending"
        with pytest.raises(LifecycleError, match="approval does not authorize"):
            workflow.transition(
                session,
                incident_id,
                IncidentState.APPROVED,
                actor_id="incidentpilot-release",
                approval_id=approval.id,
                proposal=proposal,
                workspace=workspace,
            )

        incident = session.get(Incident, incident_id)
        assert incident.status == IncidentState.AWAITING_APPROVAL.value
        assert (DEMO_ROOT / "app" / "checkout.py").read_text(encoding="utf-8") == original_text
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        assert AuditTrail.verify(events)
        assert [event.event_type for event in events[:4]] == [
            "incident_opened",
            "incident_state_transition",
            "incident_state_transition",
            "repository_inspected",
        ]
        assert events[-1].event_type == "approval_attempt_rejected"


def test_restricted_runner_caps_output_and_records_failure(audit_store, tmp_path):
    registry = RepositoryRegistry(
        {"demo-checkout": DEMO_ROOT},
        repository_commits={"demo-checkout": "test-fixture-commit"},
    )
    workspace_root = tmp_path / "workspaces"
    workspace = WorkspaceManager(registry, workspace_root).create("demo-checkout", "INC-LIMIT", "TASK-LIMIT")
    runner = RestrictedTestRunner(registry, workspace_root, max_output_bytes=1)
    with audit_store.sessions() as session:
        result = runner.run(
            session,
            workspace,
            incident_id=workspace.incident_id,
            task_id=workspace.task_id,
        )
    assert result.status == "output_limited"
    assert result.output_limited is True
    assert len(result.stdout.encode("utf-8")) <= 1
    assert len(result.stderr.encode("utf-8")) <= 1

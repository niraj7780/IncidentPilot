from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import sys
import threading
import uuid

import pytest
from sqlalchemy import select

import incidentpilot.approvals as approvals_module
from incidentpilot.approvals import ApprovalError, WindowsTokenIdentityProvider
from incidentpilot.audit import AuditTrail
from incidentpilot.lifecycle import IncidentState
from incidentpilot.security.patches import PatchIntegrityError
from incidentpilot.security.repositories import RepositoryRegistry
from incidentpilot.security.workspaces import IsolatedWorkspace
from incidentpilot.storage import (
    Approval,
    ApprovalSecurityRecord,
    AuditEvent,
    AuthorizedOperation,
    Incident,
    TestRun as WorkflowTestRun,
)
from incidentpilot.workflow import IncidentWorkflow


DEMO_ROOT = Path(__file__).resolve().parents[3] / "examples" / "demo-checkout"
TEST_SID = "S-1-5-21-111-222-333-1001"


class FixedIdentityProvider:
    """Test adapter only; the Windows demo uses its process token SID."""

    def __init__(self, sid=TEST_SID):
        self.sid = sid

    def current_sid(self):
        return self.sid


class InterruptOnceBeforeRun:
    def __init__(self, runner):
        self.runner = runner if callable(runner) else runner.run
        self.calls = 0

    def run(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("injected interruption before test runner launch")
        return self.runner(*args, **kwargs)


class InterruptAfterFirstPersistedRun:
    def __init__(self, runner):
        self.runner = runner if callable(runner) else runner.run
        self.calls = 0

    def run(self, *args, **kwargs):
        self.calls += 1
        result = self.runner(*args, **kwargs)
        if self.calls == 1:
            raise RuntimeError("injected interruption after test evidence was committed")
        return result


def identity_config():
    if sys.platform == "win32":
        provider = WindowsTokenIdentityProvider()
        return provider.current_sid(), provider
    return TEST_SID, FixedIdentityProvider()


@pytest.fixture
def ready_demo(audit_store, tmp_path):
    sid, provider = identity_config()
    workspace_root = tmp_path / "workspaces"
    registry = RepositoryRegistry(
        {"demo-checkout": DEMO_ROOT},
        repository_commits={"demo-checkout": "demo-commit-verified-resolution"},
    )
    workflow = IncidentWorkflow(
        registry,
        workspace_root,
        allowed_approver_sids={sid},
        identity_provider=provider,
    )
    runner = workflow.test_runner
    original_source = (DEMO_ROOT / "app" / "checkout.py").read_bytes()
    incident_id = "INC-AUTH-1"
    task_id = "TASK-AUTH-1"
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
        workspace = workflow.create_workspace(
            session,
            "demo-checkout",
            incident_id=incident_id,
            task_id=task_id,
        )
        baseline = runner.run(session, workspace, incident_id=incident_id, task_id=task_id)
        assert baseline.status == "failed"
        workflow.transition(
            session,
            incident_id,
            IncidentState.REPRODUCED,
            actor_id="incidentpilot-qa",
            test_run_id=baseline.run_id,
        )
        original_text = (DEMO_ROOT / "app" / "checkout.py").read_text(encoding="utf-8")
        fixed_text = original_text.replace("return subtotal + discount", "return subtotal - discount")
        proposal = workflow.propose_patch(session, workspace, {"app/checkout.py": fixed_text})
        workflow.transition(
            session,
            incident_id,
            IncidentState.FIX_PROPOSED,
            actor_id="incidentpilot-developer",
            proposal=proposal,
        )
        workflow.apply_patch(session, workspace, proposal, expected_sha256=proposal.sha256)
        workflow.transition(session, incident_id, IncidentState.TESTING, actor_id="incidentpilot-qa")
        preapproval = runner.run(
            session,
            workspace,
            incident_id=incident_id,
            task_id=task_id,
            proposal=proposal,
        )
        assert preapproval.status == "passed"
        workflow.transition(
            session,
            incident_id,
            IncidentState.AWAITING_APPROVAL,
            actor_id="incidentpilot-qa",
            test_run_id=preapproval.run_id,
        )
        approval = workflow.request_approval(session, proposal, preapproval.run_id, workspace)
        yield {
            "session": session,
            "workflow": workflow,
            "runner": runner,
            "workspace": workspace,
            "proposal": proposal,
            "approval": approval,
            "incident_id": incident_id,
            "original_source": original_source,
            "registry": registry,
            "workspace_root": workspace_root,
            "sid": sid,
            "provider": provider,
            "audit_store": audit_store,
        }


def approve_case(case):
    session = case["session"]
    workflow = case["workflow"]
    approval = workflow.approvals.decide(
        session,
        case["approval"].id,
        decision="approved",
        confirmed_patch_sha256=case["proposal"].sha256,
    )
    workflow.transition(
        session,
        case["incident_id"],
        IncidentState.APPROVED,
        actor_id=approval.approver,
        proposal=case["proposal"],
        workspace=case["workspace"],
        approval_id=approval.id,
    )
    return approval


def assert_audit_valid(session):
    events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
    assert AuditTrail.verify(events)
    return events


def test_valid_authenticated_approval_runs_only_isolated_verification_and_resolves(ready_demo):
    case = ready_demo
    session = case["session"]
    workflow = case["workflow"]
    approval = approve_case(case)
    result = workflow.execute_approved_operation(
        session,
        incident_id=case["incident_id"],
        approval_id=approval.id,
        proposal=case["proposal"],
        workspace=case["workspace"],
    )
    assert result.status == "passed"
    assert "2 passed" in result.stdout
    incident = session.get(Incident, case["incident_id"])
    assert incident.status == IncidentState.RESOLVED.value
    operation = session.get(AuthorizedOperation, approval.id)
    assert operation.status == "succeeded"
    assert operation.verification_test_run_id == result.run_id
    assert operation.before_snapshot_sha256 == operation.after_snapshot_sha256
    assert operation.workspace_path == str(case["workspace"].root)
    run = session.get(WorkflowTestRun, result.run_id)
    assert Path(run.working_directory).resolve() == case["workspace"].root.resolve()
    assert (DEMO_ROOT / "app" / "checkout.py").read_bytes() == case["original_source"]

    count_before = len(session.scalars(select(WorkflowTestRun)).all())
    repeated = workflow.execute_approved_operation(
        session,
        incident_id=case["incident_id"],
        approval_id=approval.id,
        proposal=case["proposal"],
        workspace=case["workspace"],
    )
    assert repeated.run_id == result.run_id
    assert len(session.scalars(select(WorkflowTestRun)).all()) == count_before
    events = assert_audit_valid(session)
    assert any(event.event_type == "authorized_operation_succeeded" for event in events)
    assert any(event.status == "RESOLVED" for event in events)


def test_rejected_approval_never_runs_authorized_operation(ready_demo):
    case = ready_demo
    session = case["session"]
    approval = case["workflow"].approvals.decide(
        session,
        case["approval"].id,
        decision="rejected",
        reason="Synthetic rejection for acceptance coverage.",
    )
    case["workflow"].transition(
        session,
        case["incident_id"],
        IncidentState.REJECTED,
        actor_id=approval.approver,
        proposal=case["proposal"],
        workspace=case["workspace"],
        approval_id=approval.id,
    )
    with pytest.raises(ApprovalError, match="does not match the current incident"):
        case["workflow"].execute_approved_operation(
            session,
            incident_id=case["incident_id"],
            approval_id=approval.id,
            proposal=case["proposal"],
            workspace=case["workspace"],
        )
    assert session.get(Incident, case["incident_id"]).status == IncidentState.REJECTED.value
    assert session.get(AuthorizedOperation, approval.id) is None
    assert (DEMO_ROOT / "app" / "checkout.py").read_bytes() == case["original_source"]
    assert_audit_valid(session)


def test_expired_approval_is_blocked_before_operation(ready_demo):
    case = ready_demo
    session = case["session"]
    extra_run = case["runner"].run(
        session,
        case["workspace"],
        incident_id=case["incident_id"],
        task_id="TASK-AUTH-1",
        proposal=case["proposal"],
    )
    assert extra_run.status == "passed"
    approval = case["workflow"].approvals.request(
        session,
        case["proposal"],
        extra_run.run_id,
        case["workspace"],
        expires_in_seconds=1,
        now=datetime(2026, 11, 4, tzinfo=timezone.utc),
    )
    with pytest.raises(ApprovalError, match="expired"):
        case["workflow"].approvals.decide(
            session,
            approval.id,
            decision="approved",
            confirmed_patch_sha256=approval.patch_sha256,
            now=datetime(2026, 11, 4, tzinfo=timezone.utc) + timedelta(seconds=2),
        )
    case["workflow"].transition(
        session,
        case["incident_id"],
        IncidentState.BLOCKED,
        actor_id="incidentpilot-approval-service",
    )
    assert session.get(Incident, case["incident_id"]).status == IncidentState.BLOCKED.value
    assert session.get(AuthorizedOperation, approval.id) is None
    assert (DEMO_ROOT / "app" / "checkout.py").read_bytes() == case["original_source"]
    assert_audit_valid(session)


def test_modified_patch_consumes_approval_and_blocks_resolution(ready_demo):
    case = ready_demo
    session = case["session"]
    approval = approve_case(case)
    source = case["workspace"].root / "app" / "checkout.py"
    source.write_text(source.read_text(encoding="utf-8") + "\n# changed after human review\n", encoding="utf-8")
    with pytest.raises(PatchIntegrityError):
        case["workflow"].execute_approved_operation(
            session,
            incident_id=case["incident_id"],
            approval_id=approval.id,
            proposal=case["proposal"],
            workspace=case["workspace"],
        )
    assert session.get(Incident, case["incident_id"]).status == IncidentState.BLOCKED.value
    assert session.get(AuthorizedOperation, approval.id).status == "failed"
    assert (DEMO_ROOT / "app" / "checkout.py").read_bytes() == case["original_source"]
    assert_audit_valid(session)


def test_interrupted_operation_can_retry_idempotently(ready_demo):
    case = ready_demo
    session = case["session"]
    approval = approve_case(case)
    interrupted = InterruptAfterFirstPersistedRun(case["workflow"].test_runner.run)
    case["workflow"].test_runner.run = interrupted.run
    with pytest.raises(RuntimeError, match="injected interruption"):
        case["workflow"].execute_approved_operation(
            session,
            incident_id=case["incident_id"],
            approval_id=approval.id,
            proposal=case["proposal"],
            workspace=case["workspace"],
        )
    operation = session.get(AuthorizedOperation, approval.id)
    assert operation.status == "retryable"
    result = case["workflow"].execute_approved_operation(
        session,
        incident_id=case["incident_id"],
        approval_id=approval.id,
        proposal=case["proposal"],
        workspace=case["workspace"],
    )
    assert result.status == "passed"
    assert interrupted.calls == 1  # Retry adopted the already committed passing run.
    assert session.get(Incident, case["incident_id"]).status == IncidentState.RESOLVED.value
    assert session.get(AuthorizedOperation, approval.id).attempt_count == 2
    assert_audit_valid(session)


def test_concurrent_operation_replay_runs_the_fixed_test_once(ready_demo):
    case = ready_demo
    approval = approve_case(case)
    barrier = threading.Barrier(2)

    def execute_once():
        with case["audit_store"].sessions() as session:
            barrier.wait(timeout=5)
            try:
                result = case["workflow"].execute_approved_operation(
                    session,
                    incident_id=case["incident_id"],
                    approval_id=approval.id,
                    proposal=case["proposal"],
                    workspace=case["workspace"],
                )
                return (result.status, result.run_id)
            except ApprovalError as exc:
                return (f"rejected:{exc}", "")

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: execute_once(), range(2)))
    assert [value[0] for value in outcomes] == ["passed", "passed"], outcomes
    assert outcomes[0][1] == outcomes[1][1]
    session = case["session"]
    operation = session.get(AuthorizedOperation, approval.id)
    assert operation.status == "succeeded"
    events = assert_audit_valid(session)
    approved_runs = [
        event
        for event in events
        if event.event_type == "test_run"
        and json.loads(event.details_json).get("approval_id") == approval.id
    ]
    assert len(approved_runs) == 1
    assert (DEMO_ROOT / "app" / "checkout.py").read_bytes() == case["original_source"]


def test_restart_key_does_not_reuse_interrupted_approval(ready_demo, monkeypatch):
    case = ready_demo
    session = case["session"]
    approval = approve_case(case)
    case["workflow"].test_runner.run = InterruptOnceBeforeRun(case["workflow"].test_runner.run).run
    with pytest.raises(RuntimeError):
        case["workflow"].execute_approved_operation(
            session,
            incident_id=case["incident_id"],
            approval_id=approval.id,
            proposal=case["proposal"],
            workspace=case["workspace"],
        )
    assert session.get(AuthorizedOperation, approval.id).status == "retryable"
    monkeypatch.setattr(approvals_module, "_PROCESS_HMAC_KEY", b"restart-key" * 4)
    monkeypatch.setattr(approvals_module, "_PROCESS_KEY_ID", "new-process-key")
    restarted = IncidentWorkflow(
        case["registry"],
        case["workspace_root"],
        audit=case["workflow"].audit,
        allowed_approver_sids={case["sid"]},
        identity_provider=case["provider"],
    )
    with pytest.raises(ApprovalError, match="approved operation failed its binding checks"):
        restarted.execute_approved_operation(
            session,
            incident_id=case["incident_id"],
            approval_id=approval.id,
            proposal=case["proposal"],
            workspace=case["workspace"],
        )
    assert session.get(Incident, case["incident_id"]).status == IncidentState.BLOCKED.value
    assert_audit_valid(session)


def test_post_approval_test_failure_blocks_resolution(audit_store, tmp_path):
    source_root = tmp_path / "synthetic-checkout"
    shutil.copytree(DEMO_ROOT, source_root)
    test_path = source_root / "tests" / "test_checkout.py"
    test_path.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "from app.checkout import total_cents\n"
        "marker = Path(os.environ['TEMP']) / 'run-count.txt'\n"
        "run_index = int(marker.read_text()) if marker.exists() else 0\n"
        "marker.write_text(str(run_index + 1))\n"
        "def test_discount():\n"
        "    assert run_index < 2, 'synthetic post-approval failure'\n"
        "    assert total_cents([(1000, 2)], discount_percent=10) == 1800\n",
        encoding="utf-8",
    )
    sid, provider = identity_config()
    workspace_root = tmp_path / "workspaces"
    registry = RepositoryRegistry(
        {"demo-checkout": source_root},
        repository_commits={"demo-checkout": "synthetic-failure-commit"},
    )
    workflow = IncidentWorkflow(
        registry,
        workspace_root,
        allowed_approver_sids={sid},
        identity_provider=provider,
    )
    runner = workflow.test_runner
    workspace_source = (source_root / "app" / "checkout.py").read_bytes()
    with audit_store.sessions() as session:
        workflow.open_incident(
            session,
            incident_id="INC-POSTFAIL",
            task_id="TASK-POSTFAIL",
            repository_id="demo-checkout",
            summary="Synthetic post-approval test failure.",
            actor_id="test-operator",
        )
        workflow.transition(session, "INC-POSTFAIL", IncidentState.CLASSIFIED, actor_id="test-operator")
        workflow.transition(session, "INC-POSTFAIL", IncidentState.INVESTIGATING, actor_id="test-operator")
        workspace = workflow.create_workspace(
            session,
            "demo-checkout",
            incident_id="INC-POSTFAIL",
            task_id="TASK-POSTFAIL",
        )
        baseline = runner.run(session, workspace, incident_id="INC-POSTFAIL", task_id="TASK-POSTFAIL")
        assert baseline.status == "failed"
        workflow.transition(
            session,
            "INC-POSTFAIL",
            IncidentState.REPRODUCED,
            actor_id="incidentpilot-qa",
            test_run_id=baseline.run_id,
        )
        old_source = (source_root / "app" / "checkout.py").read_text(encoding="utf-8")
        proposal = workflow.propose_patch(
            session,
            workspace,
            {"app/checkout.py": old_source.replace("return subtotal + discount", "return subtotal - discount")},
        )
        workflow.transition(
            session,
            "INC-POSTFAIL",
            IncidentState.FIX_PROPOSED,
            actor_id="incidentpilot-developer",
            proposal=proposal,
        )
        workflow.apply_patch(session, workspace, proposal, expected_sha256=proposal.sha256)
        workflow.transition(session, "INC-POSTFAIL", IncidentState.TESTING, actor_id="incidentpilot-qa")
        preapproval = runner.run(
            session,
            workspace,
            incident_id="INC-POSTFAIL",
            task_id="TASK-POSTFAIL",
            proposal=proposal,
        )
        assert preapproval.status == "passed"
        workflow.transition(
            session,
            "INC-POSTFAIL",
            IncidentState.AWAITING_APPROVAL,
            actor_id="incidentpilot-qa",
            test_run_id=preapproval.run_id,
        )
        approval = workflow.request_approval(session, proposal, preapproval.run_id, workspace)
        approved = workflow.approvals.decide(
            session,
            approval.id,
            decision="approved",
            confirmed_patch_sha256=proposal.sha256,
        )
        workflow.transition(
            session,
            "INC-POSTFAIL",
            IncidentState.APPROVED,
            actor_id=approved.approver,
            proposal=proposal,
            workspace=workspace,
            approval_id=approval.id,
        )
        result = workflow.execute_approved_operation(
            session,
            incident_id="INC-POSTFAIL",
            approval_id=approval.id,
            proposal=proposal,
            workspace=workspace,
        )
        assert result.status == "failed"
        assert "synthetic post-approval failure" in result.stdout
        assert session.get(Incident, "INC-POSTFAIL").status == IncidentState.BLOCKED.value
        assert session.get(AuthorizedOperation, approval.id).status == "failed"
        assert (source_root / "app" / "checkout.py").read_bytes() == workspace_source
        assert_audit_valid(session)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows token validation is host-specific")
def test_windows_token_provider_reads_current_account_sid():
    sid = WindowsTokenIdentityProvider().current_sid()
    assert sid.startswith("S-1-")

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import threading
import uuid

import pytest
from sqlalchemy import select

import incidentpilot.approvals as approvals_module
from incidentpilot.approvals import ApprovalContext, ApprovalError, ApprovalService
from incidentpilot.audit import AuditTrail
from incidentpilot.security.patches import PatchService
from incidentpilot.security.repositories import RepositoryRegistry
from incidentpilot.security.workspaces import WorkspaceManager
from incidentpilot.storage import Approval, AuditEvent, TestRun as WorkflowTestRun


APPROVER_SID = "S-1-5-21-111-222-333-1001"
OTHER_SID = "S-1-5-21-111-222-333-1002"


class FixedIdentityProvider:
    def __init__(self, sid=APPROVER_SID):
        self.sid = sid

    def current_sid(self):
        return self.sid


def make_proposal(tmp_path: Path, incident_id="INC-1", task_id="TASK-1"):
    root = tmp_path / f"repo-{incident_id}"
    (root / "app").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "tests" / "test_checkout.py").write_text("def test_placeholder():\n    assert True\n", encoding="utf-8")
    (root / "app" / "checkout.py").write_text("def total():\n    return 2200\n", encoding="utf-8")
    registry = RepositoryRegistry(
        {"demo-checkout": root}, repository_commits={"demo-checkout": "test-commit-1"}
    )
    workspace = WorkspaceManager(registry, tmp_path / f"workspaces-{incident_id}").create(
        "demo-checkout", incident_id, task_id
    )
    patch_service = PatchService(registry, tmp_path / f"workspaces-{incident_id}")
    proposal = patch_service.propose(
        workspace, {"app/checkout.py": "def total():\n    return 1800\n"}
    )
    patch_service.apply(workspace, proposal, proposal.sha256)
    return registry, workspace, proposal


def add_test_run(session, proposal, workspace, *, status="passed", run_id=None, approval_id=None):
    run_id = run_id or str(uuid.uuid4())
    command = [str(Path(sys.executable).resolve()), "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_checkout.py"]
    now = datetime.now(timezone.utc).isoformat()
    run = WorkflowTestRun(
        id=run_id,
        incident_id=proposal.incident_id,
        task_id=proposal.task_id,
        repository_id=proposal.repository_id,
        repository_commit=proposal.repository_commit,
        patch_sha256=proposal.sha256,
        command_json=json.dumps(command, separators=(",", ":")),
        working_directory=str(workspace.root),
        started_at=now,
        finished_at=now,
        duration_ms=1,
        exit_code=0 if status == "passed" else 1,
        timed_out=False,
        output_limited=False,
        stdout="unit-test fixture; not execution evidence",
        stderr="",
        status=status,
    )
    session.add(run)
    trail = AuditTrail()
    event = trail.append(
        session,
        incident_id=proposal.incident_id,
        task_id=proposal.task_id,
        actor_id="incidentpilot-test-runner",
        event_type="test_run",
        status=status,
        details={
            "repository_id": proposal.repository_id,
            "repository_commit": proposal.repository_commit,
            "patch_sha256": proposal.sha256,
            "command_id": "checkout-pytest-v1",
            "exit_code": 0 if status == "passed" else 1,
            "timed_out": False,
            "output_limited": False,
            "duration_ms": 1,
            "test_run_id": run_id,
            **({"approval_id": approval_id} if approval_id else {}),
        },
    )
    trail.commit(session, event)
    return run


def make_service(sid=APPROVER_SID):
    return ApprovalService(
        allowed_approver_sids={APPROVER_SID},
        identity_provider=FixedIdentityProvider(sid),
    )


def request_approval(session, service, proposal, workspace, *, now=None, run_status="passed"):
    run = add_test_run(session, proposal, workspace, status=run_status)
    approval = service.request(session, proposal, run.id, workspace, now=now)
    return run, approval


def approve(session, service, approval):
    return service.decide(
        session,
        approval.id,
        decision="approved",
        confirmed_patch_sha256=approval.patch_sha256,
    )


def test_approval_is_authenticated_bound_to_workspace_and_exact_test_run(audit_store, tmp_path):
    _, workspace, proposal = make_proposal(tmp_path)
    service = make_service()
    with audit_store.sessions() as session:
        run, approval = request_approval(session, service, proposal, workspace)
        approved = approve(session, service, approval)
        assert approved.approver == APPROVER_SID
        context = service.context_for(proposal, workspace, run.id)
        assert service.authorize(session, approval.id, context).id == approval.id

        wrong_contexts = [
            ApprovalContext(**{**context.__dict__, "incident_id": "INC-WRONG"}),
            ApprovalContext(**{**context.__dict__, "repository_id": "repo-wrong"}),
            ApprovalContext(**{**context.__dict__, "repository_commit": "other-commit"}),
            ApprovalContext(**{**context.__dict__, "test_run_id": str(uuid.uuid4())}),
            ApprovalContext(**{**context.__dict__, "workspace_path": str(tmp_path / "other-workspace")}),
            ApprovalContext(**{**context.__dict__, "operation": "apply_patch_to_original"}),
        ]
        for wrong in wrong_contexts:
            with pytest.raises(ApprovalError):
                service.authorize(session, approval.id, wrong)

        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        assert AuditTrail.verify(events)


def test_tampering_with_approval_fields_or_expiry_invalidates_hmac(audit_store, tmp_path):
    _, workspace, proposal = make_proposal(tmp_path)
    service = make_service()
    with audit_store.sessions() as session:
        run, approval = request_approval(session, service, proposal, workspace)
        approve(session, service, approval)
        approval.expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        session.commit()
        with pytest.raises(ApprovalError, match="integrity"):
            service.authorize(session, approval.id, service.context_for(proposal, workspace, run.id))


def test_approval_from_prior_process_key_is_rejected(audit_store, tmp_path, monkeypatch):
    _, workspace, proposal = make_proposal(tmp_path)
    service = make_service()
    with audit_store.sessions() as session:
        run, approval = request_approval(session, service, proposal, workspace)
        approve(session, service, approval)
        monkeypatch.setattr(approvals_module, "_PROCESS_HMAC_KEY", b"x" * 32)
        monkeypatch.setattr(approvals_module, "_PROCESS_KEY_ID", "restarted-process-key")
        restarted = make_service()
        with pytest.raises(ApprovalError, match="another process key"):
            restarted.authorize(session, approval.id, restarted.context_for(proposal, workspace, run.id))


def test_unauthorized_sid_cannot_decide(audit_store, tmp_path):
    _, workspace, proposal = make_proposal(tmp_path)
    service = make_service(OTHER_SID)
    with audit_store.sessions() as session:
        _, approval = request_approval(session, service, proposal, workspace)
        with pytest.raises(ApprovalError, match="not authorized"):
            approve(session, service, approval)
        assert session.get(Approval, approval.id).decision == "pending"
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        assert events[-1].event_type == "approval_attempt_rejected"
        assert AuditTrail.verify(events)


def test_expired_and_rejected_approvals_fail_closed(audit_store, tmp_path):
    _, workspace, proposal = make_proposal(tmp_path)
    service = make_service()
    now = datetime(2026, 11, 4, tzinfo=timezone.utc)
    with audit_store.sessions() as session:
        _, expired = request_approval(session, service, proposal, workspace, now=now)
        with pytest.raises(ApprovalError, match="expired"):
            service.decide(
                session,
                expired.id,
                decision="approved",
                confirmed_patch_sha256=expired.patch_sha256,
                now=now + timedelta(minutes=16),
            )
        assert session.get(Approval, expired.id).decision == "expired"

        _, rejected_workspace, rejected_proposal = make_proposal(tmp_path, "INC-REJECT", "TASK-REJECT")
        _, rejected = request_approval(session, service, rejected_proposal, rejected_workspace, now=now)
        with pytest.raises(ApprovalError, match="requires a reason"):
            service.decide(session, rejected.id, decision="rejected")
        decision = service.decide(
            session,
            rejected.id,
            decision="rejected",
            reason="The patch is not ready.",
            now=now + timedelta(seconds=1),
        )
        assert decision.decision == "rejected"
        with pytest.raises(ApprovalError, match="expired, rejected, pending"):
            service.authorize(
                session,
                rejected.id,
                service.context_for(rejected_proposal, rejected_workspace, rejected.test_run_id),
                now=now + timedelta(seconds=2),
            )

        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        assert AuditTrail.verify(events)


def test_failed_preapproval_tests_and_duplicate_requests_are_rejected(audit_store, tmp_path):
    _, workspace, proposal = make_proposal(tmp_path)
    service = make_service()
    with audit_store.sessions() as session:
        failed_run = add_test_run(session, proposal, workspace, status="failed")
        with pytest.raises(ApprovalError, match="passing test run"):
            service.request(session, proposal, failed_run.id, workspace)

        run = add_test_run(session, proposal, workspace)
        approval = service.request(session, proposal, run.id, workspace)
        with pytest.raises(ApprovalError, match="duplicate approval request"):
            service.request(session, proposal, run.id, workspace)
        approve(session, service, approval)
        with pytest.raises(ApprovalError, match="already consumed"):
            approve(session, service, approval)
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        assert AuditTrail.verify(events)


def test_concurrent_approval_decisions_are_atomic(audit_store, tmp_path):
    _, workspace, proposal = make_proposal(tmp_path)
    service = make_service()
    with audit_store.sessions() as session:
        _, approval = request_approval(session, service, proposal, workspace)

    barrier = threading.Barrier(2)

    def decide_once(decision):
        with audit_store.sessions() as session:
            barrier.wait(timeout=5)
            try:
                service.decide(
                    session,
                    approval.id,
                    decision=decision,
                    confirmed_patch_sha256=approval.patch_sha256,
                    reason="Rejected by concurrent reviewer.",
                )
                return "accepted"
            except ApprovalError:
                return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(decide_once, ("approved", "rejected")))
    assert sorted(outcomes) == ["accepted", "rejected"]
    with audit_store.sessions() as session:
        persisted = session.get(Approval, approval.id)
        assert persisted.decision in {"approved", "rejected"}
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        assert AuditTrail.verify(events)

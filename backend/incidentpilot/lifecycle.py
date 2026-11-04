"""Incident lifecycle transitions with verification and approval gates."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .approvals import ApprovalContext, ApprovalError, ApprovalService
from .audit import AuditTrail
from .security.patches import PatchProposal
from .security.workspaces import IsolatedWorkspace
from .storage import Approval, AuditEvent, AuthorizedOperation, Incident, TestRun


class IncidentState(StrEnum):
    OPEN = "OPEN"
    CLASSIFIED = "CLASSIFIED"
    INVESTIGATING = "INVESTIGATING"
    REPRODUCED = "REPRODUCED"
    FIX_PROPOSED = "FIX_PROPOSED"
    TESTING = "TESTING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


_TRANSITIONS = {
    IncidentState.OPEN: {IncidentState.CLASSIFIED, IncidentState.BLOCKED, IncidentState.FAILED, IncidentState.CANCELLED},
    IncidentState.CLASSIFIED: {IncidentState.INVESTIGATING, IncidentState.BLOCKED, IncidentState.FAILED, IncidentState.CANCELLED},
    IncidentState.INVESTIGATING: {IncidentState.REPRODUCED, IncidentState.BLOCKED, IncidentState.FAILED, IncidentState.CANCELLED},
    IncidentState.REPRODUCED: {IncidentState.FIX_PROPOSED, IncidentState.BLOCKED, IncidentState.FAILED, IncidentState.CANCELLED},
    IncidentState.FIX_PROPOSED: {IncidentState.TESTING, IncidentState.BLOCKED, IncidentState.FAILED, IncidentState.CANCELLED},
    IncidentState.TESTING: {IncidentState.FIX_PROPOSED, IncidentState.AWAITING_APPROVAL, IncidentState.BLOCKED, IncidentState.FAILED, IncidentState.CANCELLED},
    IncidentState.AWAITING_APPROVAL: {IncidentState.APPROVED, IncidentState.REJECTED, IncidentState.BLOCKED, IncidentState.CANCELLED},
    IncidentState.APPROVED: {IncidentState.RESOLVED, IncidentState.BLOCKED, IncidentState.FAILED},
    IncidentState.RESOLVED: {IncidentState.BLOCKED},
}


class LifecycleError(ValueError):
    """Raised when an incident transition is invalid or lacks evidence."""


class IncidentLifecycle:
    def __init__(self, audit: AuditTrail | None = None, approvals: ApprovalService | None = None) -> None:
        self.audit = audit or AuditTrail()
        self.approvals = approvals or ApprovalService(self.audit)

    def open(
        self,
        session: Session,
        *,
        incident_id: str,
        task_id: str,
        repository_id: str,
        repository_commit: str,
        summary: str,
        actor_id: str,
    ) -> Incident:
        if not summary.strip() or len(summary) > 2000:
            raise LifecycleError("incident summary must contain 1-2000 characters")
        now = datetime.now(timezone.utc).isoformat()
        incident = Incident(
            id=incident_id,
            task_id=task_id,
            repository_id=repository_id,
            summary=summary,
            status=IncidentState.OPEN.value,
            repository_commit=repository_commit,
            created_at=now,
            updated_at=now,
        )
        session.add(incident)
        event = self.audit.append(
            session,
            incident_id=incident_id,
            task_id=task_id,
            actor_id=actor_id,
            event_type="incident_opened",
            status=IncidentState.OPEN.value,
            details={"repository_id": repository_id, "repository_commit": repository_commit},
        )
        self.audit.commit(session, event)
        return incident

    def transition(
        self,
        session: Session,
        incident_id: str,
        target: IncidentState,
        *,
        actor_id: str,
        proposal: PatchProposal | None = None,
        workspace: IsolatedWorkspace | None = None,
        test_run_id: str | None = None,
        approval_id: str | None = None,
    ) -> Incident:
        try:
            target = IncidentState(target)
        except ValueError as exc:
            raise LifecycleError("unknown incident state") from exc
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise LifecycleError("incident does not exist")
        current = IncidentState(incident.status)
        transition_actor_id = actor_id
        if target not in _TRANSITIONS.get(current, set()):
            self._rejected(session, incident, actor_id, "invalid_transition")
            raise LifecycleError(f"transition from {current.value} to {target.value} is not allowed")

        if target == IncidentState.FIX_PROPOSED:
            if (
                proposal is None
                or proposal.incident_id != incident.id
                or proposal.task_id != incident.task_id
                or proposal.repository_id != incident.repository_id
                or proposal.repository_commit != incident.repository_commit
            ):
                raise LifecycleError("fix proposal is not bound to this incident and repository")
            incident.base_snapshot_sha256 = proposal.base_snapshot_sha256
            incident.patch_sha256 = proposal.sha256
        elif target == IncidentState.REPRODUCED:
            run = session.get(TestRun, test_run_id) if test_run_id else None
            if (
                run is None
                or run.status != "failed"
                or run.exit_code in {None, 0}
                or run.timed_out
                or run.incident_id != incident.id
                or run.task_id != incident.task_id
                or run.repository_id != incident.repository_id
                or run.repository_commit != incident.repository_commit
                or run.patch_sha256
            ):
                raise LifecycleError("reproduction requires a real failing baseline test run")
            incident.reproduction_run_id = run.id
        elif target == IncidentState.TESTING:
            applied_events = session.scalars(
                select(AuditEvent).where(
                    AuditEvent.incident_id == incident.id,
                    AuditEvent.task_id == incident.task_id,
                    AuditEvent.event_type == "patch_applied",
                    AuditEvent.status == "passed",
                )
            ).all()
            if not any(json.loads(event.details_json).get("patch_sha256") == incident.patch_sha256 for event in applied_events):
                raise LifecycleError("testing requires the current patch applied in an isolated workspace")
        elif target == IncidentState.AWAITING_APPROVAL:
            run = session.get(TestRun, test_run_id) if test_run_id else None
            if (
                run is None
                or run.status != "passed"
                or run.incident_id != incident.id
                or run.task_id != incident.task_id
                or run.repository_id != incident.repository_id
                or run.repository_commit != incident.repository_commit
                or run.patch_sha256 != incident.patch_sha256
            ):
                raise LifecycleError("approval requires a passing test run for the current patch")
            incident.test_run_id = run.id
        elif target == IncidentState.REJECTED:
            approval = session.get(Approval, approval_id) if approval_id else None
            if approval is None or proposal is None or workspace is None or not incident.test_run_id:
                raise LifecycleError("rejection requires the bound approval, patch, workspace, and test run")
            context = self.approvals.context_for(proposal, workspace, incident.test_run_id)
            try:
                self.approvals.verify_decision(session, approval.id, context, decision="rejected")
            except ApprovalError as exc:
                raise LifecycleError("rejection does not match this incident") from exc
            incident.approval_id = approval.id
            transition_actor_id = approval.approver
        elif target == IncidentState.APPROVED:
            approval = session.get(Approval, approval_id) if approval_id else None
            if approval is None or proposal is None or workspace is None or not incident.test_run_id:
                raise LifecycleError("approval, patch, workspace, and pre-approval test evidence are required")
            context = self.approvals.context_for(proposal, workspace, incident.test_run_id)
            if (
                proposal.incident_id != incident.id
                or proposal.task_id != incident.task_id
                or proposal.repository_id != incident.repository_id
                or proposal.repository_commit != incident.repository_commit
                or proposal.sha256 != incident.patch_sha256
            ):
                raise LifecycleError("approval context does not match this incident")
            try:
                self.approvals.authorize(session, approval.id, context)
            except ApprovalError as exc:
                raise LifecycleError("approval does not authorize this incident patch") from exc
            incident.approval_id = approval.id
            transition_actor_id = approval.approver
        elif target == IncidentState.RESOLVED:
            if not incident.test_run_id or not incident.approval_id:
                raise LifecycleError("resolution requires passing tests and human approval")
            approval = session.get(Approval, incident.approval_id)
            operation = session.get(AuthorizedOperation, incident.approval_id)
            run = session.get(TestRun, incident.test_run_id)
            if (
                approval is None
                or operation is None
                or not self.approvals.verify_operation_record(operation)
                or operation.status != "succeeded"
                or operation.operation != "verify_patch_and_resolve_isolated_workspace"
                or operation.incident_id != incident.id
                or operation.task_id != incident.task_id
                or operation.repository_id != incident.repository_id
                or operation.repository_commit != incident.repository_commit
                or operation.patch_sha256 != incident.patch_sha256
                or operation.approval_id != approval.id
                or operation.preapproval_test_run_id != approval.test_run_id
                or operation.verification_test_run_id != incident.test_run_id
                or operation.before_snapshot_sha256 != operation.after_snapshot_sha256
                or run is None
                or run.status != "passed"
                or run.exit_code != 0
                or run.timed_out
                or run.output_limited
                or run.incident_id != incident.id
                or run.task_id != incident.task_id
                or run.repository_id != incident.repository_id
                or run.repository_commit != incident.repository_commit
                or run.patch_sha256 != incident.patch_sha256
            ):
                raise LifecycleError("resolution requires a successful approval-bound isolated verification run")
            context = ApprovalContext(
                incident_id=incident.id,
                task_id=incident.task_id,
                repository_id=incident.repository_id,
                repository_commit=incident.repository_commit,
                base_snapshot_sha256=incident.base_snapshot_sha256,
                patch_sha256=incident.patch_sha256,
                test_run_id=approval.test_run_id,
                workspace_path=operation.workspace_path,
            )
            try:
                self.approvals.authorize(session, incident.approval_id, context)
            except ApprovalError as exc:
                raise LifecycleError("resolution approval is expired or mismatched") from exc

        previous = current.value
        incident.status = target.value
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        event = self.audit.append(
            session,
            incident_id=incident.id,
            task_id=incident.task_id,
            actor_id=transition_actor_id,
            event_type="incident_state_transition",
            status=target.value,
            details={
                "repository_id": incident.repository_id,
                "repository_commit": incident.repository_commit,
                "operation": f"{previous.lower()}_to_{target.value.lower()}",
                "patch_sha256": incident.patch_sha256,
                **({"approval_id": incident.approval_id} if incident.approval_id else {}),
                **({"test_run_id": incident.test_run_id} if incident.test_run_id else {}),
            },
        )
        self.audit.commit(session, event)
        return incident

    def _rejected(self, session: Session, incident: Incident, actor_id: str, code: str) -> None:
        event = self.audit.append(
            session,
            incident_id=incident.id,
            task_id=incident.task_id,
            actor_id=actor_id,
            event_type="incident_transition_rejected",
            status="rejected",
            details={"repository_id": incident.repository_id, "error_code": code},
        )
        self.audit.commit(session, event)

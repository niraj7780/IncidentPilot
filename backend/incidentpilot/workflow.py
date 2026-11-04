"""Coordinates repository review, isolated patching, and evidence recording."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import uuid
from collections.abc import Iterator

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from .approvals import ApprovalContext, ApprovalError, ApprovalService, IdentityProvider
from .audit import AuditTrail
from .lifecycle import IncidentLifecycle, IncidentState, LifecycleError
from .security.patches import PatchIntegrityError, PatchProposal, PatchService
from .security.repositories import RepositoryRegistry, RepositorySafetyError
from .security.workspaces import IsolatedWorkspace, WorkspaceManager, snapshot_sha256
from .storage import Approval, AuditEvent, AuthorizedOperation, Incident, TestRun
from .test_runner import RestrictedTestRunner, TestRunResult


_OPERATION_LOCK_GUARD = threading.Lock()
_OPERATION_LOCKS: dict[str, tuple[threading.Lock, int]] = {}


@contextmanager
def _operation_lock(approval_id: str) -> Iterator[None]:
    with _OPERATION_LOCK_GUARD:
        lock, users = _OPERATION_LOCKS.get(approval_id, (threading.Lock(), 0))
        _OPERATION_LOCKS[approval_id] = (lock, users + 1)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _OPERATION_LOCK_GUARD:
            current_lock, users = _OPERATION_LOCKS[approval_id]
            if users == 1:
                del _OPERATION_LOCKS[approval_id]
            else:
                _OPERATION_LOCKS[approval_id] = (current_lock, users - 1)


class IncidentWorkflow:
    def __init__(
        self,
        registry: RepositoryRegistry,
        workspace_root: Path,
        audit: AuditTrail | None = None,
        *,
        allowed_approver_sids: set[str] | frozenset[str] = frozenset(),
        identity_provider: IdentityProvider | None = None,
    ) -> None:
        self.registry = registry
        self.workspaces = WorkspaceManager(registry, workspace_root)
        self.patches = PatchService(registry, workspace_root)
        self.audit = audit or AuditTrail()
        self.approvals = ApprovalService(
            self.audit,
            allowed_approver_sids=allowed_approver_sids,
            identity_provider=identity_provider,
        )
        self.lifecycle = IncidentLifecycle(self.audit, self.approvals)
        self.test_runner = RestrictedTestRunner(registry, workspace_root)

    def open_incident(
        self,
        session: Session,
        *,
        incident_id: str,
        task_id: str,
        repository_id: str,
        summary: str,
        actor_id: str,
    ) -> Incident:
        return self.lifecycle.open(
            session,
            incident_id=incident_id,
            task_id=task_id,
            repository_id=repository_id,
            repository_commit=self.registry.commit_for(repository_id),
            summary=summary,
            actor_id=actor_id,
        )

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
        return self.lifecycle.transition(
            session,
            incident_id,
            target,
            actor_id=actor_id,
            proposal=proposal,
            workspace=workspace,
            test_run_id=test_run_id,
            approval_id=approval_id,
        )

    def request_approval(
        self,
        session: Session,
        proposal: PatchProposal,
        test_run_id: str,
        workspace: IsolatedWorkspace,
        *,
        expires_in_seconds: int = 900,
        now: datetime | None = None,
    ) -> Approval:
        incident = session.get(Incident, proposal.incident_id)
        if (
            incident is None
            or incident.status != IncidentState.AWAITING_APPROVAL.value
            or incident.test_run_id != test_run_id
            or incident.patch_sha256 != proposal.sha256
        ):
            raise ApprovalError("approval request is not for the incident's current passing test run")
        try:
            self.patches.verify_applied(workspace, proposal)
        except (PatchIntegrityError, RepositorySafetyError) as exc:
            raise ApprovalError("approval request requires the exact patch in its isolated workspace") from exc
        return self.approvals.request(
            session,
            proposal,
            test_run_id,
            workspace,
            expires_in_seconds=expires_in_seconds,
            now=now,
        )

    def decide_approval_interactively(
        self,
        session: Session,
        approval_id: str,
        proposal: PatchProposal,
        workspace: IsolatedWorkspace,
    ) -> Approval:
        incident = session.get(Incident, proposal.incident_id)
        if incident is None or not incident.test_run_id:
            raise ApprovalError("incident has no current test evidence")
        expected = self.approvals.context_for(proposal, workspace, incident.test_run_id)
        try:
            approval = self.approvals.prompt_human(session, approval_id, expected)
            target = IncidentState.APPROVED if approval.decision == "approved" else IncidentState.REJECTED
            self.transition(
                session,
                incident.id,
                target,
                actor_id=approval.approver,
                proposal=proposal,
                workspace=workspace,
                approval_id=approval.id,
            )
            return approval
        except (ApprovalError, LifecycleError):
            incident = session.get(Incident, proposal.incident_id)
            if incident and incident.status == IncidentState.AWAITING_APPROVAL.value:
                self.transition(
                    session,
                    incident.id,
                    IncidentState.BLOCKED,
                    actor_id="incidentpilot-approval-service",
                )
            raise

    def execute_approved_operation(
        self,
        session: Session,
        *,
        incident_id: str,
        approval_id: str,
        proposal: PatchProposal,
        workspace: IsolatedWorkspace,
    ) -> TestRunResult:
        with _operation_lock(approval_id):
            return self._execute_approved_operation_locked(
                session,
                incident_id=incident_id,
                approval_id=approval_id,
                proposal=proposal,
                workspace=workspace,
                actor_id="incidentpilot-approval-service",
            )

    def _execute_approved_operation_locked(
        self,
        session: Session,
        *,
        incident_id: str,
        approval_id: str,
        proposal: PatchProposal,
        workspace: IsolatedWorkspace,
        actor_id: str,
    ) -> TestRunResult:
        """Consume an approval once, reverify its workspace, and rerun fixed tests."""
        incident = session.get(Incident, incident_id)
        approval = session.get(Approval, approval_id)
        existing_operation = session.get(AuthorizedOperation, approval_id)
        if (
            incident is None
            or incident.status not in {IncidentState.APPROVED.value, IncidentState.RESOLVED.value}
            or incident.approval_id != approval_id
            or approval is None
            or proposal.incident_id != incident.id
            or proposal.task_id != incident.task_id
            or proposal.repository_id != incident.repository_id
            or proposal.repository_commit != incident.repository_commit
            or proposal.sha256 != incident.patch_sha256
            or not incident.test_run_id
        ):
            raise ApprovalError("approved operation does not match the current incident")
        if incident.status == IncidentState.RESOLVED.value:
            if existing_operation is None or not self.approvals.verify_operation_record(existing_operation):
                raise ApprovalError("resolved incident has no valid idempotent operation record")
            return self._complete_from_record(
                session, incident, approval, existing_operation, proposal, workspace, actor_id
            )
        if incident.test_run_id != approval.test_run_id:
            self._block_approved_incident(session, incident, "preapproval_test_run_binding_changed")
            raise ApprovalError("incident no longer references its approved pre-approval test run")
        expected = self.approvals.context_for(proposal, workspace, approval.test_run_id)
        try:
            self.approvals.authorize(session, approval_id, expected)
            self._validate_workspace_binding(incident, proposal, workspace)
        except (ApprovalError, RepositorySafetyError) as exc:
            self._block_approved_incident(session, incident, "approval_or_workspace_binding_failed")
            raise ApprovalError("approved operation failed its binding checks") from exc

        operation = session.get(AuthorizedOperation, approval_id)
        if operation is not None:
            if not self.approvals.verify_operation_record(operation):
                self._record(
                    session,
                    incident_id=incident.id,
                    task_id=incident.task_id,
                    actor_id=actor_id,
                    event_type="authorized_operation_rejected",
                    status="rejected",
                    details={"approval_id": approval_id, "error_code": "operation_record_integrity_failed"},
                )
                self._block_approved_incident(session, incident, "operation_record_integrity_failed")
                raise ApprovalError("authorized operation record integrity check failed")
            if operation.status == "succeeded":
                return self._complete_from_record(session, incident, approval, operation, proposal, workspace, actor_id)
            if operation.status == "running":
                self._record(
                    session,
                    incident_id=incident.id,
                    task_id=incident.task_id,
                    actor_id=actor_id,
                    event_type="authorized_operation_rejected",
                    status="rejected",
                    details={"approval_id": approval_id, "error_code": "operation_already_running"},
                )
                raise ApprovalError("the approved operation is already running")
            if operation.status != "retryable":
                raise ApprovalError("the approved operation has already failed or been consumed")
            if operation.process_key_id != self.approvals.process_key_id:
                self._block_approved_incident(session, incident, "approval_process_key_changed")
                raise ApprovalError("operation retry requires the original process-held approval key")
            if operation.attempt_count >= 3:
                self._finish_operation(
                    session,
                    operation,
                    status="failed",
                    error_code="operation_retry_limit_reached",
                    actor_id=actor_id,
                )
                self._block_approved_incident(session, incident, "operation_retry_limit_reached")
                raise ApprovalError("approved operation retry limit reached")
            result = session.execute(
                update(AuthorizedOperation)
                .where(
                    AuthorizedOperation.approval_id == approval_id,
                    AuthorizedOperation.status == "retryable",
                    AuthorizedOperation.record_hmac == operation.record_hmac,
                )
                .values(status="running", attempt_count=operation.attempt_count + 1, updated_at=self._now())
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                session.rollback()
                raise ApprovalError("operation retry was claimed by another request")
            session.refresh(operation)
            operation.error_code = None
            self.approvals.sign_operation_record(operation)
            self._record_operation_event(session, operation, actor_id, "authorized_operation_retry_started", "running")
        else:
            operation = AuthorizedOperation(
                approval_id=approval.id,
                incident_id=incident.id,
                task_id=incident.task_id,
                repository_id=incident.repository_id,
                repository_commit=incident.repository_commit,
                workspace_path=expected.workspace_path,
                operation=approval.operation,
                patch_sha256=approval.patch_sha256,
                preapproval_test_run_id=approval.test_run_id,
                process_key_id=self.approvals.process_key_id,
                status="running",
                attempt_count=1,
                verification_test_run_id=None,
                before_snapshot_sha256="",
                after_snapshot_sha256="",
                error_code=None,
                started_at=self._now(),
                updated_at=self._now(),
                record_hmac="",
            )
            self.approvals.sign_operation_record(operation)
            session.add(operation)
            try:
                session.flush()
                self._record_operation_event(session, operation, actor_id, "authorized_operation_started", "running")
            except (IntegrityError, OperationalError) as exc:
                session.rollback()
                existing = session.get(AuthorizedOperation, approval_id)
                if existing is not None:
                    self._record(
                        session,
                        incident_id=incident.id,
                        task_id=incident.task_id,
                        actor_id=actor_id,
                        event_type="authorized_operation_rejected",
                        status="rejected",
                        details={"approval_id": approval_id, "error_code": "operation_already_claimed"},
                    )
                raise ApprovalError("this approval has already been consumed or concurrently claimed") from exc

        try:
            before_files = self._workspace_snapshot(workspace)
            before_hash = snapshot_sha256(before_files)
            if operation.before_snapshot_sha256 and operation.before_snapshot_sha256 != before_hash:
                raise PatchIntegrityError("isolated workspace changed between operation attempts")
            operation.before_snapshot_sha256 = before_hash
            operation.updated_at = self._now()
            self.approvals.sign_operation_record(operation)
            self._record_operation_event(
                session,
                operation,
                actor_id,
                "authorized_operation_snapshot_verified",
                "passed",
                snapshot_sha256_value=before_hash,
            )
            self.patches.verify_applied(workspace, proposal)
            prior_run = self._find_prior_approved_run(session, approval, workspace, proposal)
            if prior_run is not None:
                operation.verification_test_run_id = prior_run.id
                operation.after_snapshot_sha256 = before_hash
                if prior_run.status == "passed" and prior_run.exit_code == 0 and not prior_run.timed_out and not prior_run.output_limited:
                    self._finish_operation(
                        session,
                        operation,
                        status="succeeded",
                        actor_id=actor_id,
                        snapshot_sha256_value=before_hash,
                        test_run_id=prior_run.id,
                    )
                    return self._complete_from_record(session, incident, approval, operation, proposal, workspace, actor_id)
                self._finish_operation(
                    session,
                    operation,
                    status="failed",
                    error_code="post_approval_tests_failed",
                    actor_id=actor_id,
                    snapshot_sha256_value=before_hash,
                    test_run_id=prior_run.id,
                )
                self._block_approved_incident(session, incident, "post_approval_tests_failed")
                return self._test_run_result(prior_run)
            result = self.test_runner.run(
                session,
                workspace,
                incident_id=incident.id,
                task_id=incident.task_id,
                proposal=proposal,
                approval_id=approval.id,
                actor_id=actor_id,
            )
            after_files = self._workspace_snapshot(workspace)
            after_hash = snapshot_sha256(after_files)
            self.patches.verify_applied(workspace, proposal)
            if before_hash != after_hash:
                raise PatchIntegrityError("approved operation changed the isolated workspace")
            if result.status != "passed" or result.exit_code != 0 or result.timed_out or result.output_limited:
                operation.verification_test_run_id = result.run_id
                operation.after_snapshot_sha256 = after_hash
                self._finish_operation(
                    session,
                    operation,
                    status="failed",
                    error_code="post_approval_tests_failed",
                    actor_id=actor_id,
                    snapshot_sha256_value=after_hash,
                )
                self._block_approved_incident(session, incident, "post_approval_tests_failed")
                return result

            operation.verification_test_run_id = result.run_id
            operation.after_snapshot_sha256 = after_hash
            self._finish_operation(
                session,
                operation,
                status="succeeded",
                actor_id=actor_id,
                snapshot_sha256_value=after_hash,
                test_run_id=result.run_id,
            )
            return self._complete_from_record(session, incident, approval, operation, proposal, workspace, actor_id)
        except BaseException as exc:
            if operation.status == "running":
                code = "isolated_workspace_integrity_failed" if isinstance(
                    exc, (PatchIntegrityError, RepositorySafetyError)
                ) else "operation_interrupted"
                terminal = code != "operation_interrupted"
                after_hash = ""
                try:
                    after_hash = snapshot_sha256(self._workspace_snapshot(workspace))
                    self.patches.verify_applied(workspace, proposal)
                    if operation.before_snapshot_sha256 and after_hash != operation.before_snapshot_sha256:
                        terminal = True
                        code = "isolated_workspace_changed_during_interruption"
                except (PatchIntegrityError, RepositorySafetyError):
                    terminal = True
                    code = "isolated_workspace_integrity_failed"
                operation.after_snapshot_sha256 = after_hash
                self._finish_operation(
                    session,
                    operation,
                    status="failed" if terminal else "retryable",
                    error_code=code,
                    actor_id=actor_id,
                    snapshot_sha256_value=after_hash,
                )
                if terminal:
                    self._block_approved_incident(session, incident, code)
            raise

    def _validate_workspace_binding(self, incident, proposal: PatchProposal, workspace: IsolatedWorkspace) -> None:
        if (
            workspace.repository_id != incident.repository_id
            or workspace.repository_commit != incident.repository_commit
            or workspace.incident_id != incident.id
            or workspace.task_id != incident.task_id
            or workspace.base_snapshot_sha256 != incident.base_snapshot_sha256
            or workspace.original_root.resolve(strict=True) != self.registry.root_for(incident.repository_id)
        ):
            raise RepositorySafetyError("workspace is not bound to this incident's allowlisted repository")
        if str(workspace.root.resolve(strict=True)) != str(workspace.root):
            raise RepositorySafetyError("workspace path is not canonical")
        if proposal.repository_id != workspace.repository_id or proposal.sha256 != incident.patch_sha256:
            raise RepositorySafetyError("patch is not bound to the approved workspace")

    def _workspace_snapshot(self, workspace: IsolatedWorkspace) -> dict[str, bytes]:
        scoped = RepositoryRegistry(
            {workspace.repository_id: workspace.root},
            repository_commits={workspace.repository_id: workspace.repository_commit},
            allowed_extensions=self.registry.allowed_extensions,
            max_file_bytes=self.registry.max_file_bytes,
            max_total_bytes=self.registry.max_total_bytes,
        )
        return scoped.snapshot(workspace.repository_id)

    def _find_prior_approved_run(
        self,
        session: Session,
        approval: Approval,
        workspace: IsolatedWorkspace,
        proposal: PatchProposal,
    ) -> TestRun | None:
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence.desc())).all()
        ascending = list(reversed(events))
        if not self.audit.verify(ascending):
            raise ApprovalError("audit chain failed before operation recovery")
        for event in events:
            if event.event_type != "test_run" or event.status not in {"passed", "failed", "timeout", "output_limited"}:
                continue
            details = json.loads(event.details_json)
            if details.get("approval_id") != approval.id:
                continue
            run_id = details.get("test_run_id")
            run = session.get(TestRun, run_id) if run_id else None
            if (
                run is not None
                and event.incident_id == approval.incident_id
                and event.task_id == approval.task_id
                and run.incident_id == approval.incident_id
                and run.task_id == approval.task_id
                and run.repository_id == approval.repository_id
                and run.repository_commit == approval.repository_commit
                and run.patch_sha256 == proposal.sha256
                and str(Path(run.working_directory).resolve(strict=True)) == str(workspace.root.resolve(strict=True))
            ):
                return run
        return None

    def _record_operation_event(
        self,
        session: Session,
        operation: AuthorizedOperation,
        actor_id: str,
        event_type: str,
        status: str,
        *,
        snapshot_sha256_value: str | None = None,
        test_run_id: str | None = None,
    ) -> None:
        self.approvals.sign_operation_record(operation)
        details = {
            "approval_id": operation.approval_id,
            "repository_id": operation.repository_id,
            "repository_commit": operation.repository_commit,
            "patch_sha256": operation.patch_sha256,
            "operation": operation.operation,
        }
        if operation.error_code:
            details["error_code"] = operation.error_code
        if snapshot_sha256_value:
            details["snapshot_sha256"] = snapshot_sha256_value
        if test_run_id:
            details["test_run_id"] = test_run_id
        event = self.audit.append(
            session,
            incident_id=operation.incident_id,
            task_id=operation.task_id,
            actor_id=actor_id,
            event_type=event_type,
            status=status,
            details=details,
        )
        self.audit.commit(session, event)

    def _finish_operation(
        self,
        session: Session,
        operation: AuthorizedOperation,
        *,
        status: str,
        error_code: str | None = None,
        actor_id: str,
        snapshot_sha256_value: str = "",
        test_run_id: str | None = None,
    ) -> None:
        operation.status = status
        operation.error_code = error_code
        operation.after_snapshot_sha256 = snapshot_sha256_value
        operation.updated_at = self._now()
        event_type = {
            "succeeded": "authorized_operation_succeeded",
            "failed": "authorized_operation_failed",
            "retryable": "authorized_operation_interrupted",
        }[status]
        self._record_operation_event(
            session,
            operation,
            actor_id,
            event_type,
            status,
            snapshot_sha256_value=snapshot_sha256_value or None,
            test_run_id=test_run_id or operation.verification_test_run_id,
        )

    def _complete_from_record(
        self,
        session: Session,
        incident: Incident,
        approval: Approval,
        operation: AuthorizedOperation,
        proposal: PatchProposal,
        workspace: IsolatedWorkspace,
        actor_id: str,
    ) -> TestRunResult:
        expected = self.approvals.context_for(proposal, workspace, approval.test_run_id)
        try:
            self.approvals.verify_decision(session, approval.id, expected, decision="approved")
        except ApprovalError as exc:
            self._block_approved_incident(session, incident, "approval_record_integrity_failed")
            raise ApprovalError("completed operation has no valid approval") from exc
        if (
            not self.approvals.verify_operation_record(operation)
            or operation.status != "succeeded"
            or operation.approval_id != approval.id
            or operation.operation != "verify_patch_and_resolve_isolated_workspace"
            or operation.preapproval_test_run_id != approval.test_run_id
            or operation.workspace_path != expected.workspace_path
            or operation.patch_sha256 != proposal.sha256
        ):
            raise ApprovalError("approved operation has no valid successful record")
        if (
            incident.status == IncidentState.APPROVED.value
            and incident.test_run_id != approval.test_run_id
        ) or (
            incident.status == IncidentState.RESOLVED.value
            and incident.test_run_id != operation.verification_test_run_id
        ):
            self._block_approved_incident(session, incident, "incident_test_run_reference_mismatch")
            raise ApprovalError("incident test-run reference does not match the approval operation")
        self._validate_workspace_binding(incident, proposal, workspace)
        self.patches.verify_applied(workspace, proposal)
        current_hash = snapshot_sha256(self._workspace_snapshot(workspace))
        if current_hash != operation.after_snapshot_sha256 or current_hash != operation.before_snapshot_sha256:
            self._block_approved_incident(session, incident, "workspace_snapshot_changed_after_operation")
            raise ApprovalError("isolated workspace changed after approved verification")
        run = session.get(TestRun, operation.verification_test_run_id)
        if (
            run is None
            or run.status != "passed"
            or run.exit_code != 0
            or run.timed_out
            or run.output_limited
            or run.incident_id != incident.id
            or run.task_id != incident.task_id
            or run.repository_id != incident.repository_id
            or run.repository_commit != incident.repository_commit
            or run.patch_sha256 != proposal.sha256
        ):
            self._block_approved_incident(session, incident, "post_approval_test_evidence_invalid")
            raise ApprovalError("approval-bound verification evidence is missing or invalid")
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        if not self.audit.verify(events) or not any(
            event.event_type == "test_run"
            and event.event_id is not None
            and event.incident_id == incident.id
            and event.task_id == incident.task_id
            and event.status == "passed"
            and (details := json.loads(event.details_json)).get("test_run_id") == run.id
            and details.get("approval_id") == approval.id
            and details.get("patch_sha256") == proposal.sha256
            for event in events
        ):
            self._block_approved_incident(session, incident, "post_approval_test_audit_invalid")
            raise ApprovalError("post-approval test is not linked to the consumed approval")
        incident.test_run_id = run.id
        if incident.status == IncidentState.APPROVED.value:
            self.lifecycle.transition(session, incident.id, IncidentState.RESOLVED, actor_id=actor_id)
        elif incident.status != IncidentState.RESOLVED.value:
            raise ApprovalError("incident cannot resolve from its current state")
        return self._test_run_result(run)

    @staticmethod
    def _test_run_result(run: TestRun) -> TestRunResult:
        return TestRunResult(
            run_id=run.id,
            status=run.status,
            exit_code=run.exit_code,
            timed_out=run.timed_out,
            output_limited=run.output_limited,
            stdout=run.stdout,
            stderr=run.stderr,
            command=tuple(json.loads(run.command_json)),
            started_at=run.started_at,
            finished_at=run.finished_at,
            duration_ms=run.duration_ms,
        )

    def _block_approved_incident(self, session: Session, incident: Incident, code: str) -> None:
        current = session.get(Incident, incident.id)
        if current and current.status in {
            IncidentState.APPROVED.value,
            IncidentState.AWAITING_APPROVAL.value,
            IncidentState.RESOLVED.value,
        }:
            self.transition(
                session,
                current.id,
                IncidentState.BLOCKED,
                actor_id="incidentpilot-approval-service",
            )
        self._record(
            session,
            incident_id=incident.id,
            task_id=incident.task_id,
            actor_id="incidentpilot-approval-service",
            event_type="incident_resolution_blocked",
            status="blocked",
            details={
                "repository_id": incident.repository_id,
                "error_code": code,
                "approval_id": incident.approval_id or "unknown-approval",
            },
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _record(
        self,
        session: Session,
        *,
        incident_id: str,
        task_id: str,
        actor_id: str,
        event_type: str,
        status: str,
        details: dict,
    ) -> None:
        event = self.audit.append(
            session,
            incident_id=incident_id,
            task_id=task_id,
            actor_id=actor_id,
            event_type=event_type,
            status=status,
            details=details,
        )
        self.audit.commit(session, event)

    def inspect_file(
        self,
        session: Session,
        repository_id: str,
        relative_path: str,
        *,
        incident_id: str,
        task_id: str,
        actor_id: str = "incidentpilot-inspector",
    ):
        inspected = self.registry.inspect_file(repository_id, relative_path)
        self._record(
            session,
            incident_id=incident_id,
            task_id=task_id,
            actor_id=actor_id,
            event_type="repository_inspected",
            status="passed",
            details={"repository_id": repository_id, "relative_path": inspected.relative_path},
        )
        return inspected

    def create_workspace(
        self,
        session: Session,
        repository_id: str,
        *,
        incident_id: str,
        task_id: str,
        actor_id: str = "incidentpilot-workspace",
    ) -> IsolatedWorkspace:
        workspace = self.workspaces.create(repository_id, incident_id, task_id)
        self._record(
            session,
            incident_id=incident_id,
            task_id=task_id,
            actor_id=actor_id,
            event_type="workspace_created",
            status="passed",
            details={
                "repository_id": repository_id,
                "repository_commit": workspace.repository_commit,
                "snapshot_sha256": workspace.base_snapshot_sha256,
                "file_count": len(workspace.base_manifest),
            },
        )
        return workspace

    def propose_patch(
        self,
        session: Session,
        workspace: IsolatedWorkspace,
        changes: dict[str, str],
        *,
        actor_id: str = "incidentpilot-patch-proposer",
    ) -> PatchProposal:
        proposal = self.patches.propose(workspace, changes)
        self._record(
            session,
            incident_id=proposal.incident_id,
            task_id=proposal.task_id,
            actor_id=actor_id,
            event_type="patch_proposed",
            status="pending",
            details={
                "repository_id": proposal.repository_id,
                "repository_commit": proposal.repository_commit,
                "patch_sha256": proposal.sha256,
                "operation": "accept_patch_for_review",
            },
        )
        return proposal

    def apply_patch(
        self,
        session: Session,
        workspace: IsolatedWorkspace,
        proposal: PatchProposal,
        *,
        expected_sha256: str,
        actor_id: str = "incidentpilot-patch-applier",
    ) -> None:
        try:
            self.patches.apply(workspace, proposal, expected_sha256)
        except Exception as exc:
            self._record(
                session,
                incident_id=workspace.incident_id,
                task_id=workspace.task_id,
                actor_id=actor_id,
                event_type="patch_apply_failed",
                status="failed",
                details={
                    "repository_id": workspace.repository_id,
                    "error_code": type(exc).__name__,
                    "operation": "apply_isolated_patch",
                },
            )
            raise
        self._record(
            session,
            incident_id=proposal.incident_id,
            task_id=proposal.task_id,
            actor_id=actor_id,
            event_type="patch_applied",
            status="passed",
            details={"repository_id": proposal.repository_id, "patch_sha256": proposal.sha256},
        )

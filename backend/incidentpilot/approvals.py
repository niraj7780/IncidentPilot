"""Authenticated, single-use approvals for the local IncidentPilot demo."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
import uuid
from typing import Protocol

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from .audit import AuditTrail
from .security.patches import PatchProposal
from .security.workspaces import IsolatedWorkspace
from .storage import Approval, ApprovalSecurityRecord, AuditEvent, TestRun


_OPERATION = "verify_patch_and_resolve_isolated_workspace"
_SID = re.compile(r"^S-\d-\d+(?:-\d+)+$")
_PROCESS_HMAC_KEY = secrets.token_bytes(32)
_PROCESS_KEY_ID = hashlib.sha256(_PROCESS_HMAC_KEY).hexdigest()
_TEST_COMMAND_SUFFIX = ["-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_checkout.py"]


class ApprovalError(ValueError):
    """Raised when identity, approval integrity, or execution binding fails."""


class WindowsTokenIdentityProvider:
    """Return the SID in this process's Windows access token.

    This identifies the local OS account. It is not enterprise or multi-user
    application authentication.
    """

    def current_sid(self) -> str:
        if sys.platform != "win32":
            raise ApprovalError("Windows token identity is unavailable on this platform")

        class _SidAndAttributes(ctypes.Structure):
            _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

        class _TokenUser(ctypes.Structure):
            _fields_ = [("user", _SidAndAttributes)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree.restype = wintypes.HLOCAL
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        token = wintypes.HANDLE()
        process = kernel32.GetCurrentProcess()
        if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            raise ApprovalError("cannot read the current Windows process identity")
        sid_text = wintypes.LPWSTR()
        try:
            required = wintypes.DWORD()
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
            if not required.value:
                raise ApprovalError("Windows did not return a process identity")
            buffer = ctypes.create_string_buffer(required.value)
            if not advapi32.GetTokenInformation(
                token, 1, ctypes.byref(buffer), required.value, ctypes.byref(required)
            ):
                raise ApprovalError("cannot read the Windows process identity")
            token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
            if not advapi32.ConvertSidToStringSidW(token_user.user.sid, ctypes.byref(sid_text)):
                raise ApprovalError("cannot format the Windows process identity")
            sid = sid_text.value
        finally:
            if sid_text:
                kernel32.LocalFree(ctypes.cast(sid_text, wintypes.HLOCAL))
            kernel32.CloseHandle(token)
        if not sid or not _SID.fullmatch(sid):
            raise ApprovalError("Windows returned an invalid process identity")
        return sid

class IdentityProvider(Protocol):
    def current_sid(self) -> str: ...


@dataclass(frozen=True)
class ApprovalContext:
    incident_id: str
    task_id: str
    repository_id: str
    repository_commit: str
    base_snapshot_sha256: str
    patch_sha256: str
    test_run_id: str
    workspace_path: str
    operation: str = _OPERATION


class ApprovalService:
    def __init__(
        self,
        audit: AuditTrail | None = None,
        *,
        allowed_approver_sids: set[str] | frozenset[str] = frozenset(),
        identity_provider: IdentityProvider | None = None,
    ) -> None:
        if any(not _SID.fullmatch(sid) for sid in allowed_approver_sids):
            raise ValueError("approver allowlist entries must be Windows SIDs")
        self.audit = audit or AuditTrail()
        self.allowed_approver_sids = frozenset(allowed_approver_sids)
        self.identity_provider = identity_provider or WindowsTokenIdentityProvider()
        # This key exists only in this process. A new process gets a new key,
        # so persisted approvals from a prior run fail verification closed.
        self._key = _PROCESS_HMAC_KEY
        self._key_id = _PROCESS_KEY_ID

    @property
    def process_key_id(self) -> str:
        return self._key_id

    @staticmethod
    def context_for(
        proposal: PatchProposal,
        workspace: IsolatedWorkspace,
        test_run_id: str,
    ) -> ApprovalContext:
        return ApprovalContext(
            incident_id=proposal.incident_id,
            task_id=proposal.task_id,
            repository_id=proposal.repository_id,
            repository_commit=proposal.repository_commit,
            base_snapshot_sha256=proposal.base_snapshot_sha256,
            patch_sha256=proposal.sha256,
            test_run_id=test_run_id,
            workspace_path=str(workspace.root.resolve(strict=True)),
        )

    def current_sid(self) -> str:
        sid = self.identity_provider.current_sid()
        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            raise ApprovalError("authenticated identity provider returned an invalid SID")
        if sid not in self.allowed_approver_sids:
            raise ApprovalError("authenticated SID is not authorized to approve incidents")
        return sid

    def request(
        self,
        session: Session,
        proposal: PatchProposal,
        test_run_id: str,
        workspace: IsolatedWorkspace,
        *,
        expires_in_seconds: int = 900,
        now: datetime | None = None,
    ) -> Approval:
        if not 1 <= expires_in_seconds <= 86_400:
            raise ApprovalError("approval expiry must be between 1 second and 24 hours")
        try:
            workspace_path = str(workspace.root.resolve(strict=True))
        except OSError as exc:
            raise ApprovalError("isolated workspace no longer exists") from exc
        if (
            proposal.repository_id != workspace.repository_id
            or proposal.repository_commit != workspace.repository_commit
            or proposal.incident_id != workspace.incident_id
            or proposal.task_id != workspace.task_id
            or proposal.base_snapshot_sha256 != workspace.base_snapshot_sha256
            or proposal.repository_commit == "unrecorded"
            or not hmac.compare_digest(hashlib.sha256(proposal.diff).hexdigest(), proposal.sha256)
        ):
            raise ApprovalError("approval request is not bound to this isolated patch")
        test_run = session.get(TestRun, test_run_id)
        if not self._preapproval_run_matches(session, test_run, proposal, workspace):
            raise ApprovalError("approval requires the real passing test run for this exact patch")

        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expires = current + timedelta(seconds=expires_in_seconds)
        approval = Approval(
            id=str(uuid.uuid4()),
            incident_id=proposal.incident_id,
            task_id=proposal.task_id,
            patch_sha256=proposal.sha256,
            patch_diff=proposal.diff.decode("utf-8"),
            repository_id=proposal.repository_id,
            repository_commit=proposal.repository_commit,
            base_snapshot_sha256=proposal.base_snapshot_sha256,
            operation=_OPERATION,
            test_run_id=test_run_id,
            approver="pending",
            decision="pending",
            reason=None,
            created_at=current.isoformat(),
            expires_at=expires.isoformat(),
            decided_at=None,
        )
        security = ApprovalSecurityRecord(
            approval_id=approval.id,
            workspace_path=workspace_path,
            process_key_id=self._key_id,
            dedupe_key=self._dedupe_key(approval, workspace_path),
            request_hmac="",
            decision_hmac=None,
        )
        security.request_hmac = self._request_hmac(approval, security)
        session.add(approval)
        session.add(security)
        try:
            session.flush()
        except IntegrityError as exc:
            session.rollback()
            duplicate = session.scalar(
                select(ApprovalSecurityRecord).where(
                    ApprovalSecurityRecord.dedupe_key == security.dedupe_key
                )
            )
            if duplicate:
                existing = session.get(Approval, duplicate.approval_id)
                if existing:
                    self._record_attempt(session, existing, "incidentpilot-approval-service", "duplicate_approval_request")
            raise ApprovalError("duplicate approval request for this exact operation") from exc
        event = self.audit.append(
            session,
            incident_id=approval.incident_id,
            task_id=approval.task_id,
            actor_id="incidentpilot-approval-service",
            event_type="approval_requested",
            status="pending",
            details={
                "approval_id": approval.id,
                "repository_id": approval.repository_id,
                "repository_commit": approval.repository_commit,
                "patch_sha256": approval.patch_sha256,
                "operation": approval.operation,
                "test_run_id": test_run_id,
                "snapshot_sha256": proposal.base_snapshot_sha256,
            },
        )
        self.audit.commit(session, event)
        return approval

    def decide(
        self,
        session: Session,
        approval_id: str,
        *,
        decision: str,
        confirmed_patch_sha256: str = "",
        reason: str = "",
        now: datetime | None = None,
    ) -> Approval:
        approval = session.get(Approval, approval_id)
        if approval is None:
            raise ApprovalError("approval does not exist")
        security = session.get(ApprovalSecurityRecord, approval_id)
        try:
            self._verify_request_record(approval, security)
        except ApprovalError:
            self._record_attempt(session, approval, "incidentpilot-approval-service", "approval_integrity_or_key_invalid")
            raise
        try:
            sid = self.current_sid()
        except ApprovalError:
            self._record_attempt(session, approval, "incidentpilot-approval-service", "unauthorized_approver")
            raise
        if decision not in {"approved", "rejected"}:
            raise ApprovalError("decision must be approved or rejected")
        if decision == "approved" and not hmac.compare_digest(confirmed_patch_sha256, approval.patch_sha256):
            self._record_attempt(session, approval, sid, "patch_checksum_mismatch")
            raise ApprovalError("typed checksum does not match the approved patch")
        if decision == "rejected" and not reason.strip():
            raise ApprovalError("rejection requires a reason")

        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expires = datetime.fromisoformat(approval.expires_at)
        actual_decision = "expired" if current >= expires else decision
        actual_approver = "incidentpilot-approval-service" if actual_decision == "expired" else sid
        actual_reason = "" if actual_decision != "rejected" else reason.strip()[:1000]
        actual_decided_at = current.isoformat()
        try:
            result = session.execute(
                update(Approval)
                .where(Approval.id == approval_id, Approval.decision == "pending")
                .values(
                    approver=actual_approver,
                    decision=actual_decision,
                    reason=actual_reason or None,
                    decided_at=actual_decided_at,
                )
                .execution_options(synchronize_session=False)
            )
        except OperationalError as exc:
            session.rollback()
            raise ApprovalError("approval decision was concurrently claimed") from exc
        if result.rowcount != 1:
            session.rollback()
            current_approval = session.get(Approval, approval_id)
            if current_approval:
                self._record_attempt(session, current_approval, sid, "duplicate_approval_decision")
            raise ApprovalError("approval decision was already consumed")
        session.refresh(approval)
        security.decision_hmac = self._decision_hmac(approval, security)
        self._record_decision(session, approval, actual_approver, actual_decision)
        if actual_decision == "expired":
            raise ApprovalError("approval expired")
        return approval

    def _preapproval_run_matches(
        self,
        session: Session,
        run: TestRun | None,
        proposal: PatchProposal,
        workspace: IsolatedWorkspace,
    ) -> bool:
        try:
            workspace_path = str(workspace.root.resolve(strict=True))
            working_directory = str(Path(run.working_directory).resolve(strict=True)) if run else ""
        except OSError:
            return False
        if (
            run is None
            or run.status != "passed"
            or run.exit_code != 0
            or run.timed_out
            or run.output_limited
            or run.incident_id != proposal.incident_id
            or run.task_id != proposal.task_id
            or run.repository_id != proposal.repository_id
            or run.repository_commit != proposal.repository_commit
            or run.patch_sha256 != proposal.sha256
            or working_directory != workspace_path
        ):
            return False
        try:
            command = json.loads(run.command_json)
        except (TypeError, json.JSONDecodeError):
            return False
        if not self._command_matches(command):
            return False
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        if not self.audit.verify(events):
            return False
        for event in events:
            if event.event_type != "test_run" or event.event_id is None:
                continue
            if (event.incident_id, event.task_id, event.status) != (run.incident_id, run.task_id, "passed"):
                continue
            details = json.loads(event.details_json)
            if (
                details.get("test_run_id") == run.id
                and details.get("repository_id") == run.repository_id
                and details.get("repository_commit") == run.repository_commit
                and details.get("patch_sha256") == proposal.sha256
                and details.get("command_id") == "checkout-pytest-v1"
                and details.get("exit_code") == 0
                and details.get("timed_out") is False
                and details.get("output_limited") is False
                and not details.get("approval_id")
            ):
                return True
        return False

    @staticmethod
    def _command_matches(command: object) -> bool:
        if not isinstance(command, list) or len(command) != len(_TEST_COMMAND_SUFFIX) + 1:
            return False
        try:
            executable = Path(command[0]).resolve(strict=True)
            current_executable = Path(sys.executable).resolve(strict=True)
        except (OSError, TypeError):
            return False
        return executable == current_executable and command[1:] == _TEST_COMMAND_SUFFIX

    def _request_payload(self, approval: Approval, security: ApprovalSecurityRecord) -> dict[str, str]:
        return {
            "approval_id": approval.id,
            "base_snapshot_sha256": approval.base_snapshot_sha256,
            "created_at": approval.created_at,
            "dedupe_key": security.dedupe_key,
            "expires_at": approval.expires_at,
            "incident_id": approval.incident_id,
            "operation": approval.operation,
            "patch_diff_sha256": hashlib.sha256(approval.patch_diff.encode("utf-8")).hexdigest(),
            "patch_sha256": approval.patch_sha256,
            "process_key_id": security.process_key_id,
            "repository_commit": approval.repository_commit,
            "repository_id": approval.repository_id,
            "task_id": approval.task_id,
            "test_run_id": approval.test_run_id,
            "workspace_path": security.workspace_path,
        }

    def _request_hmac(self, approval: Approval, security: ApprovalSecurityRecord) -> str:
        payload = json.dumps(self._request_payload(approval, security), sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _decision_hmac(self, approval: Approval, security: ApprovalSecurityRecord) -> str:
        payload = {
            "approver": approval.approver,
            "decision": approval.decision,
            "decided_at": approval.decided_at or "",
            "reason": approval.reason or "",
            "request_hmac": security.request_hmac,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, encoded, hashlib.sha256).hexdigest()

    @staticmethod
    def _dedupe_key(approval: Approval, workspace_path: str) -> str:
        payload = {
            "incident_id": approval.incident_id,
            "operation": approval.operation,
            "patch_sha256": approval.patch_sha256,
            "repository_commit": approval.repository_commit,
            "repository_id": approval.repository_id,
            "task_id": approval.task_id,
            "test_run_id": approval.test_run_id,
            "workspace_path": workspace_path,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def _verify_request_record(
        self,
        approval: Approval,
        security: ApprovalSecurityRecord | None,
    ) -> ApprovalSecurityRecord:
        if security is None or security.process_key_id != self._key_id:
            raise ApprovalError("approval belongs to another process key; request a new approval")
        if not hmac.compare_digest(self._dedupe_key(approval, security.workspace_path), security.dedupe_key):
            raise ApprovalError("approval de-duplication binding was modified")
        expected = self._request_hmac(approval, security)
        if not hmac.compare_digest(expected, security.request_hmac):
            raise ApprovalError("approval record integrity check failed")
        if approval.decision != "pending":
            expected_decision = self._decision_hmac(approval, security)
            if not security.decision_hmac or not hmac.compare_digest(expected_decision, security.decision_hmac):
                raise ApprovalError("approval decision integrity check failed")
        return security

    def authorize(
        self,
        session: Session,
        approval_id: str,
        expected: ApprovalContext,
        *,
        now: datetime | None = None,
    ) -> Approval:
        approval = session.get(Approval, approval_id)
        if approval is None:
            raise ApprovalError("approval does not exist")
        security = session.get(ApprovalSecurityRecord, approval_id)
        try:
            self._verify_request_record(approval, security)
        except ApprovalError:
            self._record_attempt(session, approval, "incidentpilot-approval-service", "approval_integrity_or_key_invalid")
            raise
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expires = datetime.fromisoformat(approval.expires_at)
        expected_fields = {
            "incident_id": expected.incident_id,
            "task_id": expected.task_id,
            "repository_id": expected.repository_id,
            "repository_commit": expected.repository_commit,
            "base_snapshot_sha256": expected.base_snapshot_sha256,
            "patch_sha256": expected.patch_sha256,
            "test_run_id": expected.test_run_id,
            "operation": expected.operation,
        }
        matches = all(getattr(approval, field) == value for field, value in expected_fields.items())
        workspace_matches = security.workspace_path == expected.workspace_path
        test_run = session.get(TestRun, approval.test_run_id)
        test_matches = self._preapproval_run_matches_from_record(session, approval, test_run, security)
        diff_matches = hmac.compare_digest(
            hashlib.sha256(approval.patch_diff.encode("utf-8")).hexdigest(), approval.patch_sha256
        )
        if (
            approval.decision != "approved"
            or current >= expires
            or approval.operation != _OPERATION
            or not matches
            or not workspace_matches
            or not test_matches
            or not diff_matches
        ):
            self._record_attempt(session, approval, "incidentpilot-approval-service", "approval_binding_mismatch")
            raise ApprovalError("approval is expired, rejected, pending, or bound to different work")
        return approval

    def verify_decision(
        self,
        session: Session,
        approval_id: str,
        expected: ApprovalContext,
        *,
        decision: str,
    ) -> Approval:
        approval = session.get(Approval, approval_id)
        if approval is None:
            raise ApprovalError("approval does not exist")
        security = session.get(ApprovalSecurityRecord, approval_id)
        self._verify_request_record(approval, security)
        if approval.decision != decision or decision not in {"approved", "rejected"}:
            raise ApprovalError("approval decision does not match the requested lifecycle transition")
        if approval.approver not in self.allowed_approver_sids:
            raise ApprovalError("approval decision was made by an unauthorized identity")
        if any(
            getattr(approval, field) != getattr(expected, field)
            for field in (
                "incident_id",
                "task_id",
                "repository_id",
                "repository_commit",
                "base_snapshot_sha256",
                "patch_sha256",
                "test_run_id",
                "operation",
            )
        ) or security.workspace_path != expected.workspace_path:
            raise ApprovalError("approval decision is bound to different work")
        return approval

    def _preapproval_run_matches_from_record(
        self,
        session: Session,
        approval: Approval,
        run: TestRun | None,
        security: ApprovalSecurityRecord,
    ) -> bool:
        try:
            working_directory = str(Path(run.working_directory).resolve(strict=True)) if run else ""
        except OSError:
            working_directory = ""
        if (
            run is None
            or run.status != "passed"
            or run.exit_code != 0
            or run.timed_out
            or run.output_limited
            or run.incident_id != approval.incident_id
            or run.task_id != approval.task_id
            or run.repository_id != approval.repository_id
            or run.repository_commit != approval.repository_commit
            or run.patch_sha256 != approval.patch_sha256
            or working_directory != security.workspace_path
        ):
            return False
        try:
            command = json.loads(run.command_json)
        except (TypeError, json.JSONDecodeError):
            return False
        if not self._command_matches(command):
            return False
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        if not self.audit.verify(events):
            return False
        return any(
            event.event_type == "test_run"
            and event.incident_id == approval.incident_id
            and event.task_id == approval.task_id
            and event.status == "passed"
            and (details := json.loads(event.details_json)).get("test_run_id") == run.id
            and details.get("repository_id") == approval.repository_id
            and details.get("repository_commit") == approval.repository_commit
            and details.get("patch_sha256") == approval.patch_sha256
            and details.get("command_id") == "checkout-pytest-v1"
            and details.get("exit_code") == 0
            and details.get("timed_out") is False
            and details.get("output_limited") is False
            and not details.get("approval_id")
            for event in events
        )

    def sign_operation_record(self, record) -> None:
        record.record_hmac = self._operation_hmac(record)

    def verify_operation_record(self, record) -> bool:
        if record is None or record.process_key_id != self._key_id:
            return False
        return hmac.compare_digest(self._operation_hmac(record), record.record_hmac)

    def _operation_hmac(self, record) -> str:
        payload = {
            "after_snapshot_sha256": record.after_snapshot_sha256,
            "approval_id": record.approval_id,
            "attempt_count": record.attempt_count,
            "before_snapshot_sha256": record.before_snapshot_sha256,
            "error_code": record.error_code or "",
            "incident_id": record.incident_id,
            "operation": record.operation,
            "patch_sha256": record.patch_sha256,
            "preapproval_test_run_id": record.preapproval_test_run_id,
            "process_key_id": record.process_key_id,
            "repository_commit": record.repository_commit,
            "repository_id": record.repository_id,
            "status": record.status,
            "started_at": record.started_at,
            "task_id": record.task_id,
            "updated_at": record.updated_at,
            "verification_test_run_id": record.verification_test_run_id or "",
            "workspace_path": record.workspace_path,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, encoded, hashlib.sha256).hexdigest()

    def _record_decision(self, session: Session, approval: Approval, actor_id: str, decision: str) -> None:
        event = self.audit.append(
            session,
            incident_id=approval.incident_id,
            task_id=approval.task_id,
            actor_id=actor_id,
            event_type="approval_decided",
            status=decision,
            details={
                "approval_id": approval.id,
                "repository_id": approval.repository_id,
                "repository_commit": approval.repository_commit,
                "patch_sha256": approval.patch_sha256,
                "operation": approval.operation,
                "decision": decision,
                "test_run_id": approval.test_run_id,
            },
        )
        self.audit.commit(session, event)

    def _record_attempt(self, session: Session, approval: Approval, actor_id: str, code: str) -> None:
        event = self.audit.append(
            session,
            incident_id=approval.incident_id,
            task_id=approval.task_id,
            actor_id=actor_id,
            event_type="approval_attempt_rejected",
            status="rejected",
            details={"approval_id": approval.id, "error_code": code},
        )
        self.audit.commit(session, event)

    def expire_pending(self, session: Session, *, now: datetime | None = None) -> int:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        approvals = session.scalars(select(Approval).where(Approval.decision == "pending")).all()
        expired = 0
        for approval in approvals:
            security = session.get(ApprovalSecurityRecord, approval.id)
            self._verify_request_record(approval, security)
            if current < datetime.fromisoformat(approval.expires_at):
                continue
            result = session.execute(
                update(Approval)
                .where(Approval.id == approval.id, Approval.decision == "pending")
                .values(
                    approver="incidentpilot-approval-service",
                    decision="expired",
                    reason=None,
                    decided_at=current.isoformat(),
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                continue
            session.refresh(approval)
            security.decision_hmac = self._decision_hmac(approval, security)
            self._record_decision(session, approval, "incidentpilot-approval-service", "expired")
            expired += 1
        return expired

    def prompt_human(
        self,
        session: Session,
        approval_id: str,
        expected: ApprovalContext,
    ) -> Approval:
        if not sys.stdin.isatty():
            raise ApprovalError("human approval requires an interactive terminal")
        approval = session.get(Approval, approval_id)
        if approval is None or approval.decision != "pending":
            raise ApprovalError("approval is not pending")
        security = session.get(ApprovalSecurityRecord, approval_id)
        self._verify_request_record(approval, security)
        context_matches = all(
            getattr(approval, field) == getattr(expected, field)
            for field in (
                "incident_id",
                "task_id",
                "repository_id",
                "repository_commit",
                "base_snapshot_sha256",
                "patch_sha256",
                "test_run_id",
                "operation",
            )
        ) and security.workspace_path == expected.workspace_path
        test_run = session.get(TestRun, approval.test_run_id)
        if (
            not context_matches
            or approval.operation != _OPERATION
            or datetime.now(timezone.utc) >= datetime.fromisoformat(approval.expires_at)
            or not self._preapproval_run_matches_from_record(session, approval, test_run, security)
            or not hmac.compare_digest(
                hashlib.sha256(approval.patch_diff.encode("utf-8")).hexdigest(), approval.patch_sha256
            )
        ):
            self._record_attempt(session, approval, "incidentpilot-approval-service", "prompt_binding_mismatch")
            raise ApprovalError("approval request is expired or bound to different work")
        sid = self.current_sid()
        print(f"Authenticated Windows SID: {sid}")
        print(f"Incident: {approval.incident_id}")
        print(f"Repository: {approval.repository_id} @ {approval.repository_commit}")
        print(f"Task: {approval.task_id}")
        print(f"Test run: {approval.test_run_id}")
        print(f"Workspace: {expected.workspace_path}")
        print(f"Patch SHA-256: {approval.patch_sha256}")
        print(f"Operation: {approval.operation}")
        print(f"Expires: {approval.expires_at}")
        print("Patch diff:")
        print(approval.patch_diff)
        decision = input("Type approve or reject: ").strip().lower()
        if decision == "approve":
            checksum = input("Type the full patch SHA-256 to approve: ").strip()
            return self.decide(
                session,
                approval_id,
                decision="approved",
                confirmed_patch_sha256=checksum,
            )
        if decision == "reject":
            reason = input("Reason for rejection: ").strip()
            return self.decide(session, approval_id, decision="rejected", reason=reason)
        raise ApprovalError("no approval decision was recorded")

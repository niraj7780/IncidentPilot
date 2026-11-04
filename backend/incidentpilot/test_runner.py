"""Run only the synthetic checkout's fixed pytest command in its copy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import subprocess
import sys
import threading
import time
import uuid

from sqlalchemy.orm import Session

from .approvals import ApprovalService
from .audit import AuditTrail
from .security.patches import PatchIntegrityError, PatchProposal, PatchService
from .security.repositories import RepositoryRegistry, RepositorySafetyError
from .security.workspaces import IsolatedWorkspace, snapshot_manifest
from .storage import AuthorizedOperation, TestRun


@dataclass(frozen=True)
class TestRunResult:
    run_id: str
    status: str
    exit_code: int | None
    timed_out: bool
    output_limited: bool
    stdout: str
    stderr: str
    command: tuple[str, ...]
    started_at: str
    finished_at: str
    duration_ms: int


class RestrictedTestRunner:
    COMMANDS = {"demo-checkout": "checkout-pytest-v1"}

    def __init__(
        self,
        registry: RepositoryRegistry,
        workspace_root: Path,
        *,
        timeout_seconds: int = 30,
        max_output_bytes: int = 65_536,
    ) -> None:
        if not 1 <= timeout_seconds <= 300 or not 1 <= max_output_bytes <= 1_048_576:
            raise ValueError("test limits must be within the configured safe range")
        self.registry = registry
        self.workspace_root = Path(workspace_root).resolve()
        self.python_executable = Path(sys.executable).resolve(strict=True)
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def _validate(
        self,
        session: Session,
        workspace: IsolatedWorkspace,
        proposal: PatchProposal | None,
        approval_id: str | None,
    ) -> tuple[str, ...]:
        if workspace.repository_id not in self.COMMANDS:
            raise RepositorySafetyError("no test command is allowlisted for this repository")
        if (
            workspace.original_root.resolve(strict=True) != self.registry.root_for(workspace.repository_id)
            or workspace.repository_commit != self.registry.commit_for(workspace.repository_id)
        ):
            raise RepositorySafetyError("workspace does not match the configured repository allowlist")
        root = workspace.root.resolve(strict=True)
        if root == self.workspace_root or not root.is_relative_to(self.workspace_root):
            raise RepositorySafetyError("test directory is outside the configured isolated workspace")
        if root == workspace.original_root or root.is_relative_to(workspace.original_root):
            raise RepositorySafetyError("tests may run only in an isolated copy")
        if not (root / "tests" / "test_checkout.py").is_file():
            raise RepositorySafetyError("allowlisted test entrypoint is missing")
        files = RepositoryRegistry(
            {workspace.repository_id: workspace.root},
            repository_commits={workspace.repository_id: workspace.repository_commit},
        ).snapshot(workspace.repository_id)
        if proposal is None:
            if snapshot_manifest(files) != workspace.base_manifest:
                raise RepositorySafetyError("baseline workspace changed before test execution")
        else:
            if (
                proposal.repository_id != workspace.repository_id
                or proposal.repository_commit != workspace.repository_commit
                or proposal.incident_id != workspace.incident_id
                or proposal.task_id != workspace.task_id
                or proposal.base_snapshot_sha256 != workspace.base_snapshot_sha256
                or proposal.base_manifest != workspace.base_manifest
            ):
                raise RepositorySafetyError("test proposal is bound to a different task")
            try:
                PatchService(self.registry, self.workspace_root).verify_applied(workspace, proposal)
            except (PatchIntegrityError, RepositorySafetyError) as exc:
                raise RepositorySafetyError("tests require the exact checksum-bound patch") from exc
        if approval_id:
            operation = session.get(AuthorizedOperation, approval_id)
            if (
                operation is None
                or operation.status != "running"
                or operation.operation != "verify_patch_and_resolve_isolated_workspace"
                or operation.approval_id != approval_id
                or operation.incident_id != workspace.incident_id
                or operation.task_id != workspace.task_id
                or operation.repository_id != workspace.repository_id
                or operation.repository_commit != workspace.repository_commit
                or operation.workspace_path != str(workspace.root.resolve(strict=True))
                or not proposal
                or operation.patch_sha256 != proposal.sha256
                or not ApprovalService().verify_operation_record(operation)
            ):
                raise RepositorySafetyError("post-approval tests require the live checksum-bound operation")
        return (
            str(self.python_executable),
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/test_checkout.py",
        )

    def run(
        self,
        session: Session,
        workspace: IsolatedWorkspace,
        *,
        incident_id: str,
        task_id: str,
        proposal: PatchProposal | None = None,
        approval_id: str | None = None,
        actor_id: str = "incidentpilot-test-runner",
    ) -> TestRunResult:
        command = self._validate(session, workspace, proposal, approval_id)
        workdir = workspace.root.resolve(strict=True)
        runtime_temp = workdir / "__incidentpilot_runtime__"
        runtime_temp.mkdir(exist_ok=True)
        environment = {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "WINDIR")
            if key in os.environ
        }
        environment.update(
            {
                "TEMP": str(runtime_temp),
                "TMP": str(runtime_temp),
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        started = datetime.now(timezone.utc)
        start_clock = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=workdir,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        output = {"stdout": bytearray(), "stderr": bytearray()}
        output_limited = threading.Event()

        def drain(name: str, pipe) -> None:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    return
                remaining = self.max_output_bytes - len(output[name])
                if remaining > 0:
                    output[name].extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    output_limited.set()
                    try:
                        process.kill()
                    except OSError:
                        pass

        readers = [
            threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
            threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            process.wait(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        finally:
            for reader in readers:
                reader.join(timeout=3)
            for pipe in (process.stdout, process.stderr):
                if pipe:
                    pipe.close()

        finished = datetime.now(timezone.utc)
        duration_ms = max(0, round((time.monotonic() - start_clock) * 1000))
        exit_code = process.returncode
        output_limited_value = output_limited.is_set()
        if timed_out:
            status = "timeout"
        elif output_limited_value:
            status = "output_limited"
        elif exit_code == 0:
            status = "passed"
        else:
            status = "failed"
        stdout = bytes(output["stdout"]).decode("utf-8", errors="replace")
        stderr = bytes(output["stderr"]).decode("utf-8", errors="replace")
        run_id = str(uuid.uuid4())
        run = TestRun(
            id=run_id,
            incident_id=incident_id,
            task_id=task_id,
            repository_id=workspace.repository_id,
            repository_commit=workspace.repository_commit,
            patch_sha256=proposal.sha256 if proposal else None,
            command_json=json.dumps(list(command), separators=(",", ":")),
            working_directory=workdir.as_posix(),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_ms=duration_ms,
            exit_code=exit_code,
            timed_out=timed_out,
            output_limited=output_limited_value,
            stdout=stdout,
            stderr=stderr,
            status=status,
        )
        session.add(run)
        audit = AuditTrail()
        event = audit.append(
            session,
            incident_id=incident_id,
            task_id=task_id,
            actor_id=actor_id,
            event_type="test_run",
            status=status,
            details={
                "repository_id": workspace.repository_id,
                "repository_commit": workspace.repository_commit,
                "patch_sha256": proposal.sha256 if proposal else "",
                "command_id": self.COMMANDS[workspace.repository_id],
                "exit_code": exit_code if exit_code is not None else -1,
                "timed_out": timed_out,
                "output_limited": output_limited_value,
                "duration_ms": duration_ms,
                "test_run_id": run_id,
                **({"approval_id": approval_id} if approval_id else {}),
            },
            duration_ms=duration_ms,
        )
        audit.commit(session, event)
        return TestRunResult(
            run_id=run_id,
            status=status,
            exit_code=exit_code,
            timed_out=timed_out,
            output_limited=output_limited_value,
            stdout=stdout,
            stderr=stderr,
            command=command,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_ms=duration_ms,
        )

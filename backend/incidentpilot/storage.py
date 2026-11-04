"""SQLite-backed workflow records; schema creation is explicit, never automatic."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Boolean, Integer, String, Text, URL, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_commit: Mapped[str] = mapped_column(String(128), nullable=False)
    base_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    patch_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    reproduction_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    test_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[str] = mapped_column(String(40), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


class TestRun(Base):
    __tablename__ = "test_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_commit: Mapped[str] = mapped_column(String(128), nullable=False)
    patch_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    command_json: Mapped[str] = mapped_column(Text, nullable=False)
    working_directory: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    finished_at: Mapped[str] = mapped_column(String(40), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timed_out: Mapped[bool] = mapped_column(Boolean, nullable=False)
    output_limited: Mapped[bool] = mapped_column(Boolean, nullable=False)
    stdout: Mapped[str] = mapped_column(Text, nullable=False)
    stderr: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    patch_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    patch_diff: Mapped[str] = mapped_column(Text, nullable=False)
    repository_id: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_commit: Mapped[str] = mapped_column(String(128), nullable=False)
    base_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    test_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    approver: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(40), nullable=False)
    decided_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


class ApprovalSecurityRecord(Base):
    """Process-key-bound integrity and de-duplication data for an approval."""

    __tablename__ = "approval_security"

    approval_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_path: Mapped[str] = mapped_column(Text, nullable=False)
    process_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    request_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuthorizedOperation(Base):
    """Single-use, idempotent execution record bound to one approval."""

    __tablename__ = "authorized_operations"

    approval_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_commit: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_path: Mapped[str] = mapped_column(Text, nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    patch_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    preapproval_test_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    process_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    verification_test_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    before_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    after_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)
    record_hmac: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path).resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            URL.create("sqlite", database=str(self.database_path)),
            connect_args={"check_same_thread": False},
        )
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        """Explicit schema creation for disposable demo/test stores only."""
        Base.metadata.create_all(self.engine)

    def close(self) -> None:
        self.engine.dispose()

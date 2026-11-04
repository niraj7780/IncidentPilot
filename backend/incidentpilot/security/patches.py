"""Generate and apply checksum-bound text patches only in isolated copies."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path
import hashlib
import os
import tempfile

from .repositories import RepositoryRegistry, RepositorySafetyError
from .workspaces import IsolatedWorkspace, snapshot_manifest, snapshot_sha256


class PatchIntegrityError(ValueError):
    """Raised when a patch is stale, malformed, or has a mismatched checksum."""


@dataclass(frozen=True)
class ProposedFileChange:
    relative_path: str
    expected_sha256: str
    old_content: bytes
    new_content: bytes
    new_sha256: str


@dataclass(frozen=True)
class PatchProposal:
    repository_id: str
    repository_commit: str
    incident_id: str
    task_id: str
    base_snapshot_sha256: str
    base_manifest: tuple[tuple[str, str], ...]
    diff: bytes
    sha256: str
    changes: tuple[ProposedFileChange, ...]


class PatchService:
    def __init__(
        self,
        registry: RepositoryRegistry,
        workspace_root: Path,
        *,
        max_patch_bytes: int = 131_072,
    ) -> None:
        self.registry = registry
        self.workspace_root = Path(workspace_root).resolve()
        if max_patch_bytes < 1:
            raise ValueError("patch size limit must be positive")
        self.max_patch_bytes = max_patch_bytes

    def _validate_workspace(self, workspace: IsolatedWorkspace) -> None:
        root = workspace.root.resolve(strict=True)
        original_root = self.registry.root_for(workspace.repository_id)
        if (
            self.workspace_root == original_root
            or original_root.is_relative_to(self.workspace_root)
            or self.workspace_root.is_relative_to(original_root)
            or root == self.workspace_root
            or not root.is_relative_to(self.workspace_root)
            or root == original_root
            or root.is_relative_to(original_root)
        ):
            raise RepositorySafetyError("patch target is not inside the configured isolated workspace")

    def _workspace_snapshot(self, workspace: IsolatedWorkspace) -> dict[str, bytes]:
        self._validate_workspace(workspace)
        workspace_registry = RepositoryRegistry(
            {workspace.repository_id: workspace.root},
            allowed_extensions=self.registry.allowed_extensions,
            max_file_bytes=self.registry.max_file_bytes,
            max_total_bytes=self.registry.max_total_bytes,
        )
        return workspace_registry.snapshot(workspace.repository_id)

    def _workspace_file(self, workspace: IsolatedWorkspace, relative_path: str) -> Path:
        self._validate_workspace(workspace)
        original = RepositoryRegistry(
            {workspace.repository_id: workspace.original_root},
            allowed_extensions=self.registry.allowed_extensions,
            max_file_bytes=self.registry.max_file_bytes,
            max_total_bytes=self.registry.max_total_bytes,
        )
        original.resolve_file(workspace.repository_id, relative_path)
        parts = relative_path.replace("\\", "/").split("/")
        candidate = workspace.root.joinpath(*parts)
        current = workspace.root
        for part in parts:
            current = current / part
            if current.is_symlink():
                raise RepositorySafetyError("symbolic links are not patchable")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(workspace.root) or not resolved.is_file():
            raise RepositorySafetyError("patch path escapes the isolated workspace")
        return resolved

    def propose(self, workspace: IsolatedWorkspace, changes: dict[str, str]) -> PatchProposal:
        if not changes:
            raise PatchIntegrityError("patch must contain at least one change")
        base_files = self._workspace_snapshot(workspace)
        if snapshot_sha256(base_files) != workspace.base_snapshot_sha256:
            raise PatchIntegrityError("workspace changed before patch proposal")
        file_changes: list[ProposedFileChange] = []
        diff_lines: list[str] = []
        for relative_path in sorted(changes):
            if not relative_path.replace("\\", "/").startswith("app/"):
                raise PatchIntegrityError("demo patches may modify only application source under app/")
            path = self._workspace_file(workspace, relative_path)
            old_bytes = path.read_bytes()
            try:
                old_text = old_bytes.decode("utf-8")
                new_text = changes[relative_path]
                new_bytes = new_text.encode("utf-8")
            except (UnicodeDecodeError, UnicodeEncodeError) as exc:
                raise PatchIntegrityError("patches must be UTF-8 text") from exc
            if len(new_bytes) > self.registry.max_file_bytes:
                raise PatchIntegrityError("patched file exceeds size limit")
            if old_bytes == new_bytes:
                raise PatchIntegrityError("patch contains no effective change")
            diff_lines.extend(
                unified_diff(
                    old_text.splitlines(keepends=True),
                    new_text.splitlines(keepends=True),
                    fromfile=f"a/{relative_path}",
                    tofile=f"b/{relative_path}",
                    lineterm="\n",
                )
            )
            file_changes.append(
                ProposedFileChange(
                    relative_path=relative_path,
                    expected_sha256=hashlib.sha256(old_bytes).hexdigest(),
                    old_content=old_bytes,
                    new_content=new_bytes,
                    new_sha256=hashlib.sha256(new_bytes).hexdigest(),
                )
            )
        diff = "".join(diff_lines).encode("utf-8")
        if len(diff) > self.max_patch_bytes:
            raise PatchIntegrityError("patch exceeds size limit")
        return PatchProposal(
            repository_id=workspace.repository_id,
            repository_commit=workspace.repository_commit,
            incident_id=workspace.incident_id,
            task_id=workspace.task_id,
            base_snapshot_sha256=workspace.base_snapshot_sha256,
            base_manifest=workspace.base_manifest,
            diff=diff,
            sha256=hashlib.sha256(diff).hexdigest(),
            changes=tuple(file_changes),
        )

    def apply(self, workspace: IsolatedWorkspace, proposal: PatchProposal, expected_sha256: str) -> None:
        if proposal.sha256 != expected_sha256 or hashlib.sha256(proposal.diff).hexdigest() != expected_sha256:
            raise PatchIntegrityError("patch checksum mismatch")
        if (
            proposal.repository_id != workspace.repository_id
            or proposal.repository_commit != workspace.repository_commit
            or proposal.incident_id != workspace.incident_id
            or proposal.task_id != workspace.task_id
            or proposal.base_snapshot_sha256 != workspace.base_snapshot_sha256
        ):
            raise PatchIntegrityError("patch is bound to a different repository task")

        paths = [change.relative_path for change in proposal.changes]
        if paths != sorted(set(paths)):
            raise PatchIntegrityError("patch file list is duplicated or out of order")
        current_snapshot = self._workspace_snapshot(workspace)
        if (
            snapshot_sha256(current_snapshot) != proposal.base_snapshot_sha256
            or snapshot_manifest(current_snapshot) != proposal.base_manifest
        ):
            raise PatchIntegrityError("workspace changed after patch proposal")

        targets: list[tuple[Path, bytes, bytes]] = []
        rendered_diff: list[str] = []
        for change in proposal.changes:
            if not change.relative_path.replace("\\", "/").startswith("app/"):
                raise PatchIntegrityError("demo patches may modify only application source under app/")
            path = self._workspace_file(workspace, change.relative_path)
            old_bytes = path.read_bytes()
            if hashlib.sha256(old_bytes).hexdigest() != change.expected_sha256:
                raise PatchIntegrityError("workspace changed after patch proposal")
            if hashlib.sha256(change.new_content).hexdigest() != change.new_sha256:
                raise PatchIntegrityError("proposed content checksum mismatch")
            try:
                old_text = old_bytes.decode("utf-8")
                new_text = change.new_content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PatchIntegrityError("patches must be UTF-8 text") from exc
            rendered_diff.extend(
                unified_diff(
                    old_text.splitlines(keepends=True),
                    new_text.splitlines(keepends=True),
                    fromfile=f"a/{change.relative_path}",
                    tofile=f"b/{change.relative_path}",
                    lineterm="\n",
                )
            )
            targets.append((path, old_bytes, change.new_content))
        if "".join(rendered_diff).encode("utf-8") != proposal.diff:
            raise PatchIntegrityError("diff does not match the proposed file contents")

        written: list[tuple[Path, bytes]] = []
        try:
            for path, old_bytes, new_bytes in targets:
                fd, temporary_name = tempfile.mkstemp(prefix=".incidentpilot-", dir=path.parent)
                try:
                    with os.fdopen(fd, "wb") as temporary:
                        temporary.write(new_bytes)
                        temporary.flush()
                        os.fsync(temporary.fileno())
                    os.replace(temporary_name, path)
                except Exception:
                    if os.path.exists(temporary_name):
                        os.unlink(temporary_name)
                    raise
                written.append((path, old_bytes))
            expected_snapshot = dict(current_snapshot)
            for change in proposal.changes:
                expected_snapshot[change.relative_path] = change.new_content
            if self._workspace_snapshot(workspace) != expected_snapshot:
                raise PatchIntegrityError("post-apply workspace differs from proposed patch")
        except Exception:
            for path, old_bytes in reversed(written):
                path.write_bytes(old_bytes)
            raise

    def verify_applied(self, workspace: IsolatedWorkspace, proposal: PatchProposal) -> None:
        if (
            hashlib.sha256(proposal.diff).hexdigest() != proposal.sha256
            or proposal.repository_id != workspace.repository_id
            or proposal.repository_commit != workspace.repository_commit
            or proposal.incident_id != workspace.incident_id
            or proposal.task_id != workspace.task_id
            or proposal.base_snapshot_sha256 != workspace.base_snapshot_sha256
            or proposal.base_manifest != workspace.base_manifest
        ):
            raise PatchIntegrityError("patch is not bound to this workspace")
        paths = [change.relative_path for change in proposal.changes]
        if paths != sorted(set(paths)):
            raise PatchIntegrityError("patch file list is duplicated or out of order")
        diff_lines: list[str] = []
        for change in proposal.changes:
            if not change.relative_path.replace("\\", "/").startswith("app/"):
                raise PatchIntegrityError("demo patches may modify only application source under app/")
            self._workspace_file(workspace, change.relative_path)
            if hashlib.sha256(change.old_content).hexdigest() != change.expected_sha256:
                raise PatchIntegrityError("patch source checksum is invalid")
            if hashlib.sha256(change.new_content).hexdigest() != change.new_sha256:
                raise PatchIntegrityError("patch result checksum is invalid")
            try:
                old_text = change.old_content.decode("utf-8")
                new_text = change.new_content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PatchIntegrityError("patches must be UTF-8 text") from exc
            diff_lines.extend(
                unified_diff(
                    old_text.splitlines(keepends=True),
                    new_text.splitlines(keepends=True),
                    fromfile=f"a/{change.relative_path}",
                    tofile=f"b/{change.relative_path}",
                    lineterm="\n",
                )
            )
        if "".join(diff_lines).encode("utf-8") != proposal.diff:
            raise PatchIntegrityError("patch diff does not match its file changes")
        current = self._workspace_snapshot(workspace)
        expected = dict(workspace.base_manifest)
        expected.update({change.relative_path: change.new_sha256 for change in proposal.changes})
        if snapshot_manifest(current) != tuple(sorted(expected.items())):
            raise PatchIntegrityError("isolated workspace does not contain the approved patch")

"""Create non-destructive working copies for proposed changes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os
import re

from .repositories import RepositoryRegistry, RepositorySafetyError


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


@dataclass(frozen=True)
class IsolatedWorkspace:
    repository_id: str
    repository_commit: str
    incident_id: str
    task_id: str
    original_root: Path
    root: Path
    base_snapshot_sha256: str
    base_manifest: tuple[tuple[str, str], ...]


def snapshot_sha256(files: dict[str, bytes]) -> str:
    manifest = [{"path": name, "sha256": digest} for name, digest in snapshot_manifest(files)]
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def snapshot_manifest(files: dict[str, bytes]) -> tuple[tuple[str, str], ...]:
    return tuple((name, hashlib.sha256(data).hexdigest()) for name, data in sorted(files.items()))


class WorkspaceManager:
    def __init__(self, registry: RepositoryRegistry, workspace_root: Path) -> None:
        self.registry = registry
        self.workspace_root = Path(workspace_root).resolve()

    def create(self, repository_id: str, incident_id: str, task_id: str) -> IsolatedWorkspace:
        if not _SAFE_ID.fullmatch(incident_id) or not _SAFE_ID.fullmatch(task_id):
            raise RepositorySafetyError("incident and task identifiers must be safe path components")
        original_root = self.registry.root_for(repository_id)
        if (
            self.workspace_root == original_root
            or original_root.is_relative_to(self.workspace_root)
            or self.workspace_root.is_relative_to(original_root)
        ):
            raise RepositorySafetyError("workspace and original repository must be separate trees")
        snapshot = self.registry.snapshot(repository_id)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        if self.workspace_root.is_symlink():
            raise RepositorySafetyError("workspace root cannot be a symbolic link")
        destination = self.workspace_root / repository_id / incident_id / task_id
        current = self.workspace_root
        for part in (repository_id, incident_id, task_id):
            current = current / part
            if current.is_symlink():
                raise RepositorySafetyError("workspace path cannot contain symbolic links")
        if destination.exists():
            raise RepositorySafetyError("workspace already exists; refusing to overwrite it")
        destination.mkdir(parents=True, exist_ok=False)
        if not destination.resolve(strict=True).is_relative_to(self.workspace_root):
            raise RepositorySafetyError("workspace escaped its configured root")

        try:
            for relative, content in snapshot.items():
                target = destination.joinpath(*relative.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() or target.is_symlink():
                    raise RepositorySafetyError("unexpected file in new workspace")
                target.write_bytes(content)
        except Exception:
            # Keep the incomplete workspace for inspection; never clean up user data automatically.
            raise

        return IsolatedWorkspace(
            repository_id=repository_id,
            repository_commit=self.registry.commit_for(repository_id),
            incident_id=incident_id,
            task_id=task_id,
            original_root=original_root,
            root=destination.resolve(strict=True),
            base_snapshot_sha256=snapshot_sha256(snapshot),
            base_manifest=snapshot_manifest(snapshot),
        )

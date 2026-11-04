"""Allowlisted, read-only repository inspection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
import hashlib
import os
import re
import stat


class RepositorySafetyError(ValueError):
    """Raised when repository input violates the inspection policy."""


@dataclass(frozen=True)
class InspectedFile:
    repository_id: str
    relative_path: str
    content: str
    sha256: str
    trust_level: str = "untrusted"


class RepositoryRegistry:
    def __init__(
        self,
        repositories: dict[str, Path],
        *,
        repository_commits: dict[str, str] | None = None,
        allowed_extensions: frozenset[str] = frozenset({".py", ".md", ".txt", ".log"}),
        max_file_bytes: int = 1_048_576,
        max_total_bytes: int = 5_242_880,
    ) -> None:
        if not repositories:
            raise RepositorySafetyError("repository allowlist cannot be empty")
        if max_file_bytes < 1 or max_total_bytes < 1:
            raise RepositorySafetyError("repository size limits must be positive")
        self.allowed_extensions = allowed_extensions
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self._roots: dict[str, Path] = {}
        self._commits: dict[str, str] = {}
        for repository_id, path in repositories.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", repository_id):
                raise RepositorySafetyError("invalid repository identifier")
            root = Path(path).resolve(strict=True)
            if not root.is_dir():
                raise RepositorySafetyError("repository root must be a directory")
            self._roots[repository_id] = root
            commit = (repository_commits or {}).get(repository_id, "unrecorded")
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", commit):
                raise RepositorySafetyError("invalid repository commit identifier")
            self._commits[repository_id] = commit

    @property
    def repository_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._roots))

    def root_for(self, repository_id: str) -> Path:
        try:
            return self._roots[repository_id]
        except KeyError as exc:
            raise RepositorySafetyError("repository is not allowlisted") from exc

    def commit_for(self, repository_id: str) -> str:
        self.root_for(repository_id)
        return self._commits[repository_id]

    def resolve_file(self, repository_id: str, relative_path: str) -> Path:
        root = self.root_for(repository_id)
        if not relative_path or "\0" in relative_path:
            raise RepositorySafetyError("invalid relative path")
        normalized = relative_path.replace("\\", "/")
        windows_path = PureWindowsPath(relative_path)
        parts = normalized.split("/")
        if (
            normalized.startswith("/")
            or windows_path.is_absolute()
            or windows_path.drive
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise RepositorySafetyError("path must be a normalized relative path")
        pure_path = PurePosixPath(normalized)
        if pure_path.suffix.lower() not in self.allowed_extensions:
            raise RepositorySafetyError("file extension is not allowlisted")
        if any(part.lower() in {".git", "node_modules", "__pycache__", ".pytest_cache", "__incidentpilot_runtime__"} for part in pure_path.parts):
            raise RepositorySafetyError("restricted repository path")
        if pure_path.name.lower().startswith(".env"):
            raise RepositorySafetyError("environment files are not inspectable")

        candidate = root.joinpath(*pure_path.parts)
        current = root
        for part in pure_path.parts:
            current = current / part
            try:
                info = current.lstat()
            except OSError as exc:
                raise RepositorySafetyError("file does not exist") from exc
            if stat.S_ISLNK(info.st_mode):
                raise RepositorySafetyError("symbolic links are not inspectable")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise RepositorySafetyError("path escapes the allowlisted repository")
        info = resolved.stat()
        if info.st_size > self.max_file_bytes:
            raise RepositorySafetyError("file exceeds inspection size limit")
        return resolved

    def inspect_file(self, repository_id: str, relative_path: str) -> InspectedFile:
        path = self.resolve_file(repository_id, relative_path)
        raw = path.read_bytes()
        if len(raw) > self.max_file_bytes:
            raise RepositorySafetyError("file grew beyond inspection size limit")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepositorySafetyError("only UTF-8 text files can be inspected") from exc
        return InspectedFile(
            repository_id=repository_id,
            relative_path=path.relative_to(self.root_for(repository_id)).as_posix(),
            content=content,
            sha256=hashlib.sha256(raw).hexdigest(),
        )

    def list_files(self, repository_id: str) -> tuple[str, ...]:
        root = self.root_for(repository_id)
        files: list[str] = []
        total_size = 0
        pending = [root]
        while pending:
            directory = pending.pop()
            for entry in os.scandir(directory):
                if entry.name.lower() in {".git", "node_modules", "__pycache__", ".pytest_cache", "__incidentpilot_runtime__"}:
                    continue
                if entry.is_symlink():
                    raise RepositorySafetyError("symbolic links are not copyable")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                path = Path(entry.path)
                if path.name.lower().startswith(".env") or path.suffix.lower() not in self.allowed_extensions:
                    continue
                size = entry.stat(follow_symlinks=False).st_size
                if size > self.max_file_bytes:
                    raise RepositorySafetyError("file exceeds inspection size limit")
                total_size += size
                if total_size > self.max_total_bytes:
                    raise RepositorySafetyError("repository exceeds inspection size limit")
                files.append(path.relative_to(root).as_posix())
        return tuple(sorted(files))

    def snapshot(self, repository_id: str) -> dict[str, bytes]:
        root = self.root_for(repository_id)
        result: dict[str, bytes] = {}
        total_size = 0
        for name in self.list_files(repository_id):
            path = self.resolve_file(repository_id, name)
            content = path.read_bytes()
            if len(content) > self.max_file_bytes:
                raise RepositorySafetyError("file grew beyond inspection size limit")
            total_size += len(content)
            if total_size > self.max_total_bytes:
                raise RepositorySafetyError("repository grew beyond inspection size limit")
            result[path.relative_to(root).as_posix()] = content
        return result

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from incidentpilot.security.patches import PatchIntegrityError, PatchService
from incidentpilot.security.repositories import RepositoryRegistry, RepositorySafetyError
from incidentpilot.security.workspaces import WorkspaceManager


def test_patch_is_applied_only_to_isolated_workspace_and_checksum_is_verified(tmp_path):
    original = tmp_path / "demo-checkout"
    (original / "app").mkdir(parents=True)
    source = original / "app" / "checkout.py"
    original_text = "def total():\n    return 2200\n"
    fixed_text = "def total():\n    return 1800\n"
    source.write_text(original_text, encoding="utf-8")
    registry = RepositoryRegistry({"demo-checkout": original})
    workspace_root = tmp_path / "workspaces"
    workspace = WorkspaceManager(registry, workspace_root).create("demo-checkout", "INC-1", "TASK-1")
    service = PatchService(registry, workspace_root)
    proposal = service.propose(workspace, {"app/checkout.py": fixed_text})

    assert proposal.sha256 == hashlib.sha256(proposal.diff).hexdigest()
    service.apply(workspace, proposal, proposal.sha256)

    assert (workspace.root / "app" / "checkout.py").read_text(encoding="utf-8") == fixed_text
    assert source.read_text(encoding="utf-8") == original_text


def test_patch_rejects_changed_checksum_without_writing(tmp_path):
    original = tmp_path / "demo-checkout"
    (original / "app").mkdir(parents=True)
    source = original / "app" / "checkout.py"
    source.write_text("def total():\n    return 2200\n", encoding="utf-8")
    registry = RepositoryRegistry({"demo-checkout": original})
    workspace_root = tmp_path / "workspaces"
    workspace = WorkspaceManager(registry, workspace_root).create("demo-checkout", "INC-2", "TASK-2")
    service = PatchService(registry, workspace_root)
    proposal = service.propose(workspace, {"app/checkout.py": "def total():\n    return 1800\n"})

    with pytest.raises(PatchIntegrityError, match="checksum mismatch"):
        service.apply(workspace, proposal, "0" * 64)

    assert (workspace.root / "app" / "checkout.py").read_text(encoding="utf-8") == "def total():\n    return 2200\n"
    assert source.read_text(encoding="utf-8") == "def total():\n    return 2200\n"


def test_checkout_fix_proposal_changes_only_the_isolated_copy(tmp_path):
    demo_root = Path(__file__).resolve().parents[3] / "examples" / "demo-checkout"
    registry = RepositoryRegistry({"demo-checkout": demo_root})
    workspace_root = tmp_path / "workspaces"
    workspace = WorkspaceManager(registry, workspace_root).create("demo-checkout", "INC-DEMO", "TASK-FIX")
    service = PatchService(registry, workspace_root)
    original_text = (demo_root / "app" / "checkout.py").read_text(encoding="utf-8")
    fixed_text = original_text.replace("return subtotal + discount", "return subtotal - discount")

    proposal = service.propose(workspace, {"app/checkout.py": fixed_text})
    service.apply(workspace, proposal, proposal.sha256)

    assert "return subtotal - discount" in (workspace.root / "app" / "checkout.py").read_text(encoding="utf-8")
    assert (demo_root / "app" / "checkout.py").read_text(encoding="utf-8") == original_text


def test_patch_rejects_a_forged_diff_even_when_change_object_is_present(tmp_path):
    original = tmp_path / "demo-checkout"
    (original / "app").mkdir(parents=True)
    (original / "app" / "checkout.py").write_text("def total():\n    return 2200\n", encoding="utf-8")
    registry = RepositoryRegistry({"demo-checkout": original})
    workspace_root = tmp_path / "workspaces"
    workspace = WorkspaceManager(registry, workspace_root).create("demo-checkout", "INC-3", "TASK-3")
    service = PatchService(registry, workspace_root)
    proposal = service.propose(workspace, {"app/checkout.py": "def total():\n    return 1800\n"})
    forged = replace(proposal, diff=b"forged diff")

    with pytest.raises(PatchIntegrityError, match="checksum mismatch"):
        service.apply(workspace, forged, proposal.sha256)


def test_patch_rejects_workspace_outside_configured_root(tmp_path):
    original = tmp_path / "demo-checkout"
    (original / "app").mkdir(parents=True)
    (original / "app" / "checkout.py").write_text("def total():\n    return 2200\n", encoding="utf-8")
    registry = RepositoryRegistry({"demo-checkout": original})
    allowed_workspace_root = tmp_path / "workspaces"
    workspace = WorkspaceManager(registry, allowed_workspace_root).create("demo-checkout", "INC-4", "TASK-4")
    service = PatchService(registry, allowed_workspace_root)

    with pytest.raises(RepositorySafetyError, match="configured isolated workspace"):
        service.propose(replace(workspace, root=original), {"app/checkout.py": "return 1800"})

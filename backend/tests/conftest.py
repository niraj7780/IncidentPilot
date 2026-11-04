from pathlib import Path

import pytest

from incidentpilot.storage import AuditStore


@pytest.fixture
def audit_store(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.create_schema()
    yield store
    store.close()

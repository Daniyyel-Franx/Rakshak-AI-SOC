from __future__ import annotations

import os
import tempfile

import pytest

# Use an isolated temp SQLite DB per test session.
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    from app.database import init_db
    init_db()
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)

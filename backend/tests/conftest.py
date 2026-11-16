import os
import sys
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="sentrix-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmp, 'test.db').as_posix()}"
os.environ["APP_ENV"] = "test"
os.environ["LLM_PROVIDER"] = "none"
os.environ["API_KEY"] = ""
os.environ["SOAR_WEBHOOK_URL"] = ""
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from sentrix.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        c.headers["X-Actor"] = "pytest-analyst"
        yield c


@pytest.fixture(scope="session")
def demo(client):
    r = client.post("/api/demo/setup")
    assert r.status_code == 200, r.text
    return r.json()

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Fuerza SQLite temporal (los tests no tocan Supabase) antes de importar la app.
os.environ["SUPABASE_URL"] = ""
os.environ["SQLITE_PATH"] = str(Path(tempfile.mkdtemp()) / "test.db")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session", autouse=True)
def prefect_harness():
    # Servidor Prefect efímero y aislado para los tests.
    from prefect.testing.utilities import prefect_test_harness

    with prefect_test_harness():
        yield


@pytest.fixture(autouse=True)
def clean_state():
    from app.infrastructure.anti_replay import anti_replay_cache
    from app.infrastructure.pre_auth_store import pre_auth_store

    anti_replay_cache.clear()
    pre_auth_store.clear()
    yield

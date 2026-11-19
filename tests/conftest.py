import os
from pathlib import Path

import pytest

from x64dbg_automate import X64DbgClient

TEST_BITNESS = int(os.getenv("TEST_BITNESS", "64"))
X64DBG_PATH = os.getenv("X64DBG_PATH", f"C:\\re\\x64dbg_dev\\release\\x{TEST_BITNESS}\\x{TEST_BITNESS}dbg.exe")

# Integration tests launch a real debugger. CI runners and clean dev boxes only
# have the mocked unit tests available, so skip instead of erroring: a red suite
# that is red for environmental reasons trains everyone to ignore it.
X64DBG_AVAILABLE = Path(X64DBG_PATH).is_file()

requires_debugger = pytest.mark.skipif(
    not X64DBG_AVAILABLE,
    reason=f"x64dbg not found at {X64DBG_PATH}; set X64DBG_PATH to run integration tests",
)


@pytest.fixture
def client():
    if not X64DBG_AVAILABLE:
        pytest.skip(f"x64dbg not found at {X64DBG_PATH}; set X64DBG_PATH to run integration tests")
    client = X64DbgClient(x64dbg_path=X64DBG_PATH)
    yield client
    client.terminate_session()

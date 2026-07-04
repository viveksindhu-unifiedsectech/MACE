"""Backend pytest config — provisions env vars before app imports."""
import os
import sys
from pathlib import Path

_here = Path(__file__).resolve()
_backend_root = _here.parent.parent
_repo_root = _here.parents[3]  # .../UnifiedSec_MACE_Complete

# Make `app` importable and locate MACE core
sys.path.insert(0, str(_backend_root))
_core_candidate = _repo_root / "UnifiedSec_MACE_v2"
if (_core_candidate / "core" / "mace.py").exists():
    sys.path.insert(0, str(_core_candidate))
    os.environ.setdefault("MACE_CORE_PATH", str(_core_candidate))

# Test-mode defaults — the SECRET_KEY validator allows synthesis when ENVIRONMENT=test
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "SECRET_KEY",
    "test-mode-key-must-be-at-least-32-bytes-but-also-stable-across-tests-okay",
)
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

"""Pytest config — make the MACE core importable from anywhere."""
import os
import sys
from pathlib import Path

# Add the UnifiedSec_MACE_v2 root (parent of `core/`) to sys.path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

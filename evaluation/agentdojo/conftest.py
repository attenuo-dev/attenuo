"""Put this directory and the Python SDK on the path, so the tests run from the repository root
without PYTHONPATH."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for path in (HERE, HERE.parents[1] / "sdk" / "python" / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

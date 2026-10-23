"""Register the marker the SDK tests use, so ``-m integration`` works here too."""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "integration: runs the real attenuo-server (set ATTENUO_INTEGRATION=1)"
    )

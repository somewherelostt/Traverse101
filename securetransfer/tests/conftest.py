"""Pytest configuration for securetransfer tests."""

import pytest

pytest_plugins = ["pytest_asyncio"]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "asyncio: mark test as async (pytest-asyncio).")

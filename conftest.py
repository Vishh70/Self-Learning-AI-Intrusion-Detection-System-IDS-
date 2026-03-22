from __future__ import annotations

from pathlib import Path
import shutil
import uuid

import pytest

_BASE_TMP = Path(".pytest_local_tmp")


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """Ensure the built-in tmpdir plugin is disabled to avoid Windows ACL issues."""
    plugin = config.pluginmanager.get_plugin("tmpdir")
    if plugin is not None:
        config.pluginmanager.unregister(plugin)


class _LocalTmpFactory:
    def __init__(self, base: Path) -> None:
        self._base = base

    def mktemp(self, basename: str, numbered: bool = True) -> Path:
        name = f"{basename}_{uuid.uuid4().hex}" if numbered else basename
        path = self._base / name
        path.mkdir(parents=True, exist_ok=False)
        return path


@pytest.fixture(scope="session")
def tmp_path_factory() -> _LocalTmpFactory:
    _BASE_TMP.mkdir(exist_ok=True)
    return _LocalTmpFactory(_BASE_TMP)


@pytest.fixture
def tmp_path(tmp_path_factory: _LocalTmpFactory):
    path = tmp_path_factory.mktemp("tmp")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)

import shutil
import subprocess

import pytest


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=20)  # noqa: S607
    except (subprocess.SubprocessError, OSError):
        return False
    return True


DOCKER_AVAILABLE = _docker_available()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    skip = pytest.mark.skip(reason="Docker 데몬이 없어 샌드박스 시험을 건너뜀")
    for item in items:
        if "docker" in item.keywords and not DOCKER_AVAILABLE:
            item.add_marker(skip)

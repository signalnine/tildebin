"""Fixtures for baremetal integration tests."""

import os
import subprocess
from pathlib import Path

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


def path_exists(path: str) -> bool:
    """Check if a path exists."""
    return Path(path).exists()


def command_available(cmd: str) -> bool:
    """Check if a command is available."""
    try:
        subprocess.run(
            ["which", cmd], capture_output=True, check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


@pytest.fixture(scope="session")
def is_linux():
    """Skip if not running on Linux."""
    import platform
    if platform.system() != "Linux":
        pytest.skip("Not running on Linux")
    return True


@pytest.fixture(scope="session")
def has_proc(is_linux):
    """Skip if /proc is not available."""
    if not path_exists("/proc"):
        pytest.skip("/proc not available")
    return True


@pytest.fixture(scope="session")
def has_sys(is_linux):
    """Skip if /sys is not available."""
    if not path_exists("/sys"):
        pytest.skip("/sys not available")
    return True


@pytest.fixture(scope="session")
def has_thermal(has_sys):
    """Skip if thermal zones not available."""
    if not path_exists("/sys/class/thermal"):
        pytest.skip("Thermal zones not available")
    return True


@pytest.fixture(scope="session")
def has_numa(has_sys):
    """Skip if NUMA not available."""
    if not path_exists("/sys/devices/system/node/node0"):
        pytest.skip("NUMA not available")
    return True


@pytest.fixture(scope="session")
def has_block_devices(has_sys):
    """Skip if no block devices."""
    if not path_exists("/sys/block"):
        pytest.skip("No block devices")
    return True


@pytest.fixture(scope="session")
def has_nvme(has_block_devices):
    """Skip if no NVMe devices."""
    nvme_devices = list(Path("/sys/block").glob("nvme*"))
    if not nvme_devices:
        pytest.skip("No NVMe devices")
    return True


@pytest.fixture(scope="session")
def has_network(has_sys):
    """Skip if no network interfaces."""
    if not path_exists("/sys/class/net"):
        pytest.skip("No network interfaces")
    return True


@pytest.fixture(scope="session")
def has_cgroups(has_sys):
    """Skip if cgroups not available."""
    if not (path_exists("/sys/fs/cgroup") or path_exists("/proc/cgroups")):
        pytest.skip("Cgroups not available")
    return True


@pytest.fixture(scope="session")
def has_systemd():
    """Skip if systemd not available."""
    if not command_available("systemctl"):
        pytest.skip("Systemd not available")
    return True


@pytest.fixture
def real_context():
    """Provide a real Context for running scripts."""
    return Context()


@pytest.fixture
def output():
    """Provide a fresh Output instance."""
    return Output()

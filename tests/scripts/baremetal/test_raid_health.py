#!/usr/bin/env python3
"""Tests for scripts/baremetal/raid_health.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.raid_health import run


class MockContext(Context):
    """Mock context for testing."""

    def __init__(self, mdstat_content=None, tools=None):
        super().__init__()
        self._mdstat = mdstat_content
        self._tools = tools or set()
        self._files = {}
        if mdstat_content is not None:
            self._files["/proc/mdstat"] = mdstat_content

    def file_exists(self, path: str) -> bool:
        return path in self._files

    def read_file(self, path: str) -> str:
        if path not in self._files:
            raise FileNotFoundError(path)
        return self._files[path]

    def check_tool(self, name: str) -> bool:
        return name in self._tools


class TestRaidHealth:
    """Tests for raid_health script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = MockContext()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_no_raid_arrays(self):
        """Test when no RAID arrays are present."""
        output = Output()
        context = MockContext(mdstat_content=None)

        result = run([], output, context)

        assert result == 0
        assert output.has_warnings()

    def test_healthy_raid1_array(self):
        """Test detection of healthy RAID1 array."""
        mdstat = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run([], output, context)

        assert result == 0
        data = output.get_data()
        assert "arrays" in data
        assert len(data["arrays"]) == 1
        assert data["arrays"][0]["status"] == "healthy"
        assert data["arrays"][0]["name"] == "md0"
        assert data["arrays"][0]["level"] == "raid1"

    def test_degraded_raid_array(self):
        """Test detection of degraded RAID array."""
        mdstat = """Personalities : [raid1]
md0 : inactive raid1 sdb1[1]
      1048512 blocks super 1.2 [2/1] [_U]

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run([], output, context)

        assert result == 1
        data = output.get_data()
        assert len(data["arrays"]) == 1
        assert data["arrays"][0]["status"] == "degraded"

    def test_rebuilding_raid_array(self):
        """Test detection of rebuilding RAID array."""
        mdstat = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]
      [==>..................]  recovery = 13.0% (136384/1048512) finish=0.7min speed=20456K/sec

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run([], output, context)

        assert result == 1
        data = output.get_data()
        assert len(data["arrays"]) == 1
        assert data["arrays"][0]["status"] == "rebuilding"

    def test_multiple_arrays(self):
        """Test detection of multiple RAID arrays."""
        mdstat = """Personalities : [raid1] [raid5]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

md1 : active raid5 sde1[2] sdd1[1] sdc1[0]
      2097024 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/3] [UUU]

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run([], output, context)

        assert result == 0
        data = output.get_data()
        assert len(data["arrays"]) == 2
        assert all(a["status"] == "healthy" for a in data["arrays"])

    def test_warn_only_mode(self):
        """Test --warn-only only shows unhealthy arrays."""
        mdstat = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

md1 : inactive raid1 sdd1[1]
      1048512 blocks super 1.2 [2/1] [_U]

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run(["--warn-only"], output, context)

        assert result == 1
        data = output.get_data()
        assert len(data["arrays"]) == 1
        assert data["arrays"][0]["name"] == "md1"
        assert data["arrays"][0]["status"] == "degraded"

    def test_verbose_mode(self):
        """Test --verbose includes device information."""
        mdstat = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run(["--verbose"], output, context)

        assert result == 0
        data = output.get_data()
        assert len(data["arrays"]) == 1
        assert "devices" in data["arrays"][0]

    def test_software_only_filter(self):
        """Test --type software only checks mdadm arrays."""
        mdstat = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run(["--type", "software"], output, context)

        assert result == 0
        data = output.get_data()
        assert len(data["arrays"]) == 1
        assert data["arrays"][0]["type"] == "software"

    def test_format_json(self):
        """Test --format json produces valid JSON."""
        mdstat = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""
        output = Output()
        context = MockContext(mdstat_content=mdstat)

        result = run(["--format", "json"], output, context)

        assert result == 0
        data = output.get_data()
        # Verify data can be serialized to JSON
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        assert "arrays" in parsed

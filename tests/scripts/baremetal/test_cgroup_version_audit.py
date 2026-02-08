"""Tests for cgroup_version_audit script."""

import pytest

from boxctl.core.output import Output


MOUNTS_V2 = """sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
"""

MOUNTS_NO_V2 = """sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
"""

CGROUPS_V1_ACTIVE = """#subsys_name\thierarchy\tnum_cgroups\tenabled
cpuset\t1\t1\t1
cpu\t2\t45\t1
memory\t3\t89\t1
"""

CGROUPS_NO_V1 = """#subsys_name\thierarchy\tnum_cgroups\tenabled
cpuset\t0\t1\t1
cpu\t0\t45\t1
memory\t0\t89\t1
"""


class TestCgroupVersionAudit:
    """Tests for cgroup_version_audit script."""

    def test_no_cgroup_info(self, mock_context):
        """Returns 2 when /proc/cgroups not found."""
        from scripts.baremetal.cgroup_version_audit import run

        ctx = mock_context(file_contents={})
        output = Output()

        assert run([], output, ctx) == 2

    def test_pure_v2(self, mock_context):
        """Returns 0 when system uses pure cgroup v2."""
        from scripts.baremetal.cgroup_version_audit import run

        ctx = mock_context(file_contents={
            '/proc/cgroups': CGROUPS_NO_V1,
            '/proc/mounts': MOUNTS_V2,
            '/sys/fs/cgroup/cgroup.controllers': 'cpuset cpu io memory hugetlb pids',
        })
        output = Output()

        assert run([], output, ctx) == 0
        assert output.data['mode'] == 'v2'

    def test_hybrid_mode(self, mock_context):
        """Returns 1 when both v1 and v2 are active."""
        from scripts.baremetal.cgroup_version_audit import run

        ctx = mock_context(file_contents={
            '/proc/cgroups': CGROUPS_V1_ACTIVE,
            '/proc/mounts': MOUNTS_V2,
            '/sys/fs/cgroup/cgroup.controllers': 'cpuset cpu io memory',
        })
        output = Output()

        assert run([], output, ctx) == 1
        assert output.data['mode'] == 'hybrid'
        assert any(i['type'] == 'hybrid_mode' for i in output.data['issues'])

    def test_v1_only(self, mock_context):
        """Returns 0 with INFO when system uses v1 only."""
        from scripts.baremetal.cgroup_version_audit import run

        ctx = mock_context(file_contents={
            '/proc/cgroups': CGROUPS_V1_ACTIVE,
            '/proc/mounts': MOUNTS_NO_V2,
        })
        output = Output()

        assert run([], output, ctx) == 0
        assert output.data['mode'] == 'v1'
        assert any(i['type'] == 'v1_only' for i in output.data['issues'])

    def test_json_output(self, mock_context):
        """Verify JSON data structure."""
        from scripts.baremetal.cgroup_version_audit import run

        ctx = mock_context(file_contents={
            '/proc/cgroups': CGROUPS_NO_V1,
            '/proc/mounts': MOUNTS_V2,
            '/sys/fs/cgroup/cgroup.controllers': 'cpu memory',
        })
        output = Output()

        run(["--format", "json"], output, ctx)

        assert 'mode' in output.data
        assert 'v1_controllers' in output.data
        assert 'v2_controllers' in output.data
        assert 'issues' in output.data

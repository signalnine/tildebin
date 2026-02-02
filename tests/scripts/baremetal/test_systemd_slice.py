"""Tests for systemd_slice script."""

import pytest

from boxctl.core.output import Output


MOUNTS_CGROUP_V2 = """cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
"""

MOUNTS_NO_CGROUP_V2 = """cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
"""

SLICES_LIST = """system.slice
user.slice
machine.slice
init.scope
"""

MEMORY_CURRENT_HEALTHY = "536870912"  # 512 MB
MEMORY_CURRENT_HIGH = "9663676416"    # 9 GB (90% of 10GB, above 85% threshold)
MEMORY_MAX = "10737418240"            # 10 GB
MEMORY_MAX_UNLIMITED = "max"

CPU_STAT_HEALTHY = """usage_usec 1000000
user_usec 600000
system_usec 400000
nr_periods 100
nr_throttled 0
throttled_usec 0
"""

CPU_STAT_THROTTLED = """usage_usec 5000000
user_usec 3000000
system_usec 2000000
nr_periods 100
nr_throttled 20
throttled_usec 100000
"""

PSI_HEALTHY = """some avg10=0.00 avg60=0.00 avg300=0.00 total=0
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
"""

PSI_WARNING = """some avg10=30.00 avg60=25.00 avg300=20.00 total=1000000
full avg10=15.00 avg60=10.00 avg300=5.00 total=500000
"""


class TestSystemdSlice:
    """Tests for systemd_slice script."""

    def test_no_cgroup_v2_returns_error(self, mock_context):
        """Returns exit code 2 when cgroup v2 not available."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            file_contents={
                '/proc/mounts': MOUNTS_NO_CGROUP_V2,
            }
        )
        output = Output()

        exit_code = systemd_slice.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("cgroup" in e.lower() for e in output.errors)

    def test_healthy_slices(self, mock_context):
        """Returns 0 when all slices are healthy."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
                '/sys/fs/cgroup/system.slice': '',  # exists
                '/sys/fs/cgroup/system.slice/memory.current': MEMORY_CURRENT_HEALTHY,
                '/sys/fs/cgroup/system.slice/memory.max': MEMORY_MAX,
                '/sys/fs/cgroup/system.slice/cpu.stat': CPU_STAT_HEALTHY,
            },
            command_outputs={
                ("ls", "/sys/fs/cgroup"): "system.slice\nuser.slice\n",
            }
        )
        output = Output()

        exit_code = systemd_slice.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert output.data['summary']['warning_count'] == 0

    def test_high_memory_warning(self, mock_context):
        """Returns 1 when slice memory usage is high."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
                '/sys/fs/cgroup/system.slice': '',
                '/sys/fs/cgroup/system.slice/memory.current': MEMORY_CURRENT_HIGH,
                '/sys/fs/cgroup/system.slice/memory.max': MEMORY_MAX,
                '/sys/fs/cgroup/system.slice/cpu.stat': CPU_STAT_HEALTHY,
            },
            command_outputs={
                ("ls", "/sys/fs/cgroup"): "system.slice\n",
            }
        )
        output = Output()

        exit_code = systemd_slice.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['warning_count'] > 0

    def test_cpu_throttling_warning(self, mock_context):
        """Returns 1 when slice is CPU throttled."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
                '/sys/fs/cgroup/system.slice': '',
                '/sys/fs/cgroup/system.slice/memory.current': MEMORY_CURRENT_HEALTHY,
                '/sys/fs/cgroup/system.slice/cpu.stat': CPU_STAT_THROTTLED,
            },
            command_outputs={
                ("ls", "/sys/fs/cgroup"): "system.slice\n",
            }
        )
        output = Output()

        exit_code = systemd_slice.run([], output, ctx)

        assert exit_code == 1
        slices = output.data.get('slices', [])
        warnings = [w for s in slices for w in s.get('warnings', [])]
        assert any('throttl' in w.lower() for w in warnings)

    def test_psi_warning(self, mock_context):
        """Returns 1 when PSI pressure is high."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
                '/sys/fs/cgroup/system.slice': '',
                '/sys/fs/cgroup/system.slice/memory.current': MEMORY_CURRENT_HEALTHY,
                '/sys/fs/cgroup/system.slice/cpu.stat': CPU_STAT_HEALTHY,
                '/sys/fs/cgroup/system.slice/cpu.pressure': PSI_WARNING,
            },
            command_outputs={
                ("ls", "/sys/fs/cgroup"): "system.slice\n",
            }
        )
        output = Output()

        exit_code = systemd_slice.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['warning_count'] > 0

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds can be specified."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
                '/sys/fs/cgroup/system.slice': '',
                '/sys/fs/cgroup/system.slice/memory.current': MEMORY_CURRENT_HEALTHY,
                '/sys/fs/cgroup/system.slice/memory.max': MEMORY_MAX,
                '/sys/fs/cgroup/system.slice/cpu.stat': CPU_STAT_HEALTHY,
            },
            command_outputs={
                ("ls", "/sys/fs/cgroup"): "system.slice\n",
            }
        )
        output = Output()

        # With lower memory threshold, should trigger warning
        exit_code = systemd_slice.run(['--warn-memory', '1'], output, ctx)

        assert exit_code == 1

    def test_no_slices_found(self, mock_context):
        """Returns 0 when no slices found."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
            },
            command_outputs={
                ("ls", "/sys/fs/cgroup"): "",
            }
        )
        output = Output()

        exit_code = systemd_slice.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_slices'] == 0

    def test_verbose_output(self, mock_context):
        """--verbose includes detailed slice information."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
                '/sys/fs/cgroup/system.slice': '',
                '/sys/fs/cgroup/system.slice/memory.current': MEMORY_CURRENT_HEALTHY,
                '/sys/fs/cgroup/system.slice/memory.max': MEMORY_MAX,
                '/sys/fs/cgroup/system.slice/cpu.stat': CPU_STAT_HEALTHY,
                '/sys/fs/cgroup/system.slice/cpu.pressure': PSI_HEALTHY,
            },
            command_outputs={
                ("ls", "/sys/fs/cgroup"): "system.slice\n",
            }
        )
        output = Output()

        exit_code = systemd_slice.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'slices' in output.data
        assert len(output.data['slices']) > 0
        # Verbose should include more details
        slice_data = output.data['slices'][0]
        assert 'cpu' in slice_data or 'memory' in slice_data

    def test_invalid_threshold_returns_error(self, mock_context):
        """Returns 2 for invalid threshold values."""
        from scripts.baremetal import systemd_slice

        ctx = mock_context(
            file_contents={
                '/proc/mounts': MOUNTS_CGROUP_V2,
                '/sys/fs/cgroup/cgroup.controllers': 'cpu memory io',
            }
        )
        output = Output()

        exit_code = systemd_slice.run(['--warn-psi', '150'], output, ctx)

        assert exit_code == 2

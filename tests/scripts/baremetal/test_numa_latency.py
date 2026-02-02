"""Tests for numa_latency script."""

import pytest

from boxctl.core.output import Output


class TestNumaLatency:
    """Tests for numa_latency script."""

    def test_uma_system_returns_zero(self, mock_context):
        """Single NUMA node (UMA) system returns 0."""
        from scripts.baremetal import numa_latency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',  # directory exists
                '/sys/devices/system/node/node0/distance': '10',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 8000000 kB\n',
            }
        )
        # Mock glob to return only one node
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_latency.run([], output, ctx)

        assert exit_code == 0
        assert output.data['topology']['is_uma'] is True

    def test_numa_not_available_returns_error(self, mock_context):
        """Returns 2 when NUMA information not available."""
        from scripts.baremetal import numa_latency

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = numa_latency.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_multi_node_healthy(self, mock_context):
        """Multi-node NUMA system with healthy topology returns 0."""
        from scripts.baremetal import numa_latency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/distance': '10 20',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node1/distance': '20 10',
                '/sys/devices/system/node/node1/meminfo': 'Node 1 MemTotal: 16000000 kB\nNode 1 MemFree: 8000000 kB\n',
                '/proc/vmstat': 'numa_hit 1000\nnuma_miss 10\npgmigrate_success 100\npgmigrate_fail 1\n',
                '/proc/sys/kernel/numa_balancing': '1',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0', '/sys/devices/system/node/node1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_latency.run([], output, ctx)

        assert exit_code == 0
        assert output.data['topology']['node_count'] == 2
        assert output.data['topology']['is_symmetric'] is True

    def test_asymmetric_topology_detected(self, mock_context):
        """Detects asymmetric NUMA topology and returns 1."""
        from scripts.baremetal import numa_latency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/distance': '10 20',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node1/distance': '30 10',  # Asymmetric: 20 vs 30
                '/sys/devices/system/node/node1/meminfo': 'Node 1 MemTotal: 16000000 kB\nNode 1 MemFree: 8000000 kB\n',
                '/proc/vmstat': 'numa_hit 1000\nnuma_miss 10\n',
                '/proc/sys/kernel/numa_balancing': '1',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0', '/sys/devices/system/node/node1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_latency.run([], output, ctx)

        assert exit_code == 1
        assert output.data['topology']['is_symmetric'] is False
        assert len(output.data['issues']) > 0

    def test_high_memory_usage_warning(self, mock_context):
        """Detects high memory usage on a node."""
        from scripts.baremetal import numa_latency

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/distance': '10 20',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 500000 kB\n',  # 97% used
                '/sys/devices/system/node/node1/distance': '20 10',
                '/sys/devices/system/node/node1/meminfo': 'Node 1 MemTotal: 16000000 kB\nNode 1 MemFree: 8000000 kB\n',
                '/proc/vmstat': 'numa_hit 1000\nnuma_miss 10\n',
                '/proc/sys/kernel/numa_balancing': '1',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0', '/sys/devices/system/node/node1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_latency.run([], output, ctx)

        assert exit_code == 1
        issues = [i for i in output.data['issues'] if i['type'] == 'node_memory_pressure']
        assert len(issues) > 0

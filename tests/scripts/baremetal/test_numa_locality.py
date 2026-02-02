"""Tests for numa_locality script."""

import pytest

from boxctl.core.output import Output


class TestNumaLocality:
    """Tests for numa_locality script."""

    def test_not_numa_system_returns_error(self, mock_context):
        """Returns 2 when not a NUMA system."""
        from scripts.baremetal import numa_locality

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = numa_locality.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_single_node_system_returns_healthy(self, mock_context):
        """Single NUMA node system returns 0."""
        from scripts.baremetal import numa_locality

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node0/cpulist': '0-7',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_locality.run([], output, ctx)

        assert exit_code == 0
        assert output.data['healthy'] is True

    def test_multi_node_healthy_locality(self, mock_context):
        """Multi-node with good locality returns 0."""
        from scripts.baremetal import numa_locality

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node0/cpulist': '0-7',
                '/sys/devices/system/node/node0/numastat': 'numa_hit 10000\nnuma_miss 100\nnuma_foreign 50\n',
                '/sys/devices/system/node/node1/meminfo': 'Node 1 MemTotal: 16000000 kB\nNode 1 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node1/cpulist': '8-15',
                '/sys/devices/system/node/node1/numastat': 'numa_hit 10000\nnuma_miss 100\nnuma_foreign 50\n',
                '/proc/vmstat': 'numa_hit 20000\nnuma_miss 200\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0', '/sys/devices/system/node/node1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_locality.run([], output, ctx)

        assert exit_code == 0
        assert output.data['numa_nodes'] == 2
        assert output.data['healthy'] is True

    def test_poor_hit_ratio_detected(self, mock_context):
        """Detects poor NUMA hit ratio."""
        from scripts.baremetal import numa_locality

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node0/cpulist': '0-7',
                '/sys/devices/system/node/node0/numastat': 'numa_hit 5000\nnuma_miss 5000\nnuma_foreign 0\n',  # 50% hit
                '/sys/devices/system/node/node1/meminfo': 'Node 1 MemTotal: 16000000 kB\nNode 1 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node1/cpulist': '8-15',
                '/sys/devices/system/node/node1/numastat': 'numa_hit 5000\nnuma_miss 5000\nnuma_foreign 0\n',
                '/proc/vmstat': 'numa_hit 10000\nnuma_miss 10000\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0', '/sys/devices/system/node/node1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_locality.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data['issues']) > 0

    def test_high_node_memory_usage_warning(self, mock_context):
        """Detects high memory usage on a node."""
        from scripts.baremetal import numa_locality

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 500000 kB\n',  # ~97% used
                '/sys/devices/system/node/node0/cpulist': '0-7',
                '/sys/devices/system/node/node0/numastat': 'numa_hit 10000\nnuma_miss 100\nnuma_foreign 0\n',
                '/sys/devices/system/node/node1/meminfo': 'Node 1 MemTotal: 16000000 kB\nNode 1 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node1/cpulist': '8-15',
                '/sys/devices/system/node/node1/numastat': 'numa_hit 10000\nnuma_miss 100\nnuma_foreign 0\n',
                '/proc/vmstat': 'numa_hit 20000\nnuma_miss 200\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0', '/sys/devices/system/node/node1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = numa_locality.run([], output, ctx)

        assert exit_code == 1
        assert 'critical' in output.data['issues'][0].lower() or len(output.data['issues']) > 0

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds are respected."""
        from scripts.baremetal import numa_locality

        ctx = mock_context(
            file_contents={
                '/sys/devices/system/node': '',
                '/sys/devices/system/node/node0/meminfo': 'Node 0 MemTotal: 16000000 kB\nNode 0 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node0/cpulist': '0-7',
                '/sys/devices/system/node/node0/numastat': 'numa_hit 8500\nnuma_miss 1500\nnuma_foreign 0\n',  # 85% hit
                '/sys/devices/system/node/node1/meminfo': 'Node 1 MemTotal: 16000000 kB\nNode 1 MemFree: 8000000 kB\n',
                '/sys/devices/system/node/node1/cpulist': '8-15',
                '/sys/devices/system/node/node1/numastat': 'numa_hit 8500\nnuma_miss 1500\nnuma_foreign 0\n',
                '/proc/vmstat': 'numa_hit 17000\nnuma_miss 3000\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/sys/devices/system/node' and pattern.startswith('node'):
                return ['/sys/devices/system/node/node0', '/sys/devices/system/node/node1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        # With default thresholds (90% warning), 85% should warn
        exit_code = numa_locality.run(['--hit-ratio-warning', '90'], output, ctx)

        assert exit_code == 1  # 85% < 90% threshold

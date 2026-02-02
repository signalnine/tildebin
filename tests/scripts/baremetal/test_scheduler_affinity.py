"""Tests for scheduler_affinity script."""

import pytest

from boxctl.core.output import Output


class TestSchedulerAffinity:
    """Tests for scheduler_affinity script."""

    def test_proc_not_found_returns_error(self, mock_context, monkeypatch):
        """Returns exit code 2 when /proc not found."""
        from scripts.baremetal import scheduler_affinity

        monkeypatch.setattr("os.path.exists", lambda p: False if p == "/proc" else True)

        ctx = mock_context()
        output = Output()

        exit_code = scheduler_affinity.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_processes_found(self, mock_context, monkeypatch):
        """Returns 0 when no processes match criteria."""
        from scripts.baremetal import scheduler_affinity

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr(scheduler_affinity, "scan_processes", lambda **kw: ([], 4))
        monkeypatch.setattr(scheduler_affinity, "get_isolated_cpus", lambda: [])

        ctx = mock_context()
        output = Output()

        exit_code = scheduler_affinity.run([], output, ctx)

        assert exit_code == 0
        assert output.data["total_processes"] == 0

    def test_healthy_system(self, mock_context, monkeypatch):
        """Returns 0 for a healthy system with no issues."""
        from scripts.baremetal import scheduler_affinity

        mock_processes = [
            {
                'pid': 1000,
                'name': 'myapp',
                'cmdline': '/usr/bin/myapp',
                'policy': 0,
                'policy_name': 'SCHED_OTHER',
                'priority': 120,
                'affinity_mask': 'f',
                'allowed_cpus': [0, 1, 2, 3],
            }
        ]

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr(
            scheduler_affinity,
            "scan_processes",
            lambda **kw: (mock_processes, 4)
        )
        monkeypatch.setattr(scheduler_affinity, "get_isolated_cpus", lambda: [])

        ctx = mock_context()
        output = Output()

        exit_code = scheduler_affinity.run([], output, ctx)

        assert exit_code == 0
        assert output.data["total_processes"] == 1
        assert output.data["warning_count"] == 0

    def test_high_priority_rt_detection(self, mock_context, monkeypatch):
        """Detects high-priority real-time processes."""
        from scripts.baremetal import scheduler_affinity

        mock_processes = [
            {
                'pid': 1000,
                'name': 'rtapp',
                'cmdline': '/usr/bin/rtapp',
                'policy': 1,  # SCHED_FIFO
                'policy_name': 'SCHED_FIFO',
                'priority': 99,  # High priority
                'affinity_mask': '1',
                'allowed_cpus': [0],
            }
        ]

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr(
            scheduler_affinity,
            "scan_processes",
            lambda **kw: (mock_processes, 4)
        )
        monkeypatch.setattr(scheduler_affinity, "get_isolated_cpus", lambda: [])

        ctx = mock_context()
        output = Output()

        exit_code = scheduler_affinity.run([], output, ctx)

        assert exit_code == 0  # INFO severity doesn't trigger exit 1
        assert output.data["rt_process_count"] == 1
        assert any(i["type"] == "high_priority_rt" for i in output.data["issues"])

    def test_isolation_violation_detection(self, mock_context, monkeypatch):
        """Detects processes pinned to isolated CPUs."""
        from scripts.baremetal import scheduler_affinity

        mock_processes = [
            {
                'pid': 1000,
                'name': 'badapp',
                'cmdline': '/usr/bin/badapp',
                'policy': 0,  # SCHED_OTHER
                'policy_name': 'SCHED_OTHER',
                'priority': 120,
                'affinity_mask': '4',  # Pinned to CPU 2
                'allowed_cpus': [2],
            }
        ]

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr(
            scheduler_affinity,
            "scan_processes",
            lambda **kw: (mock_processes, 4)
        )
        monkeypatch.setattr(scheduler_affinity, "get_isolated_cpus", lambda: [2, 3])

        ctx = mock_context()
        output = Output()

        exit_code = scheduler_affinity.run([], output, ctx)

        assert exit_code == 1  # WARNING triggers exit 1
        assert any(i["type"] == "isolation_violation" for i in output.data["issues"])

    def test_parse_cpu_mask(self, mock_context):
        """Test CPU mask parsing."""
        from scripts.baremetal.scheduler_affinity import parse_cpu_mask

        # Simple masks
        assert parse_cpu_mask("1", 8) == [0]
        assert parse_cpu_mask("3", 8) == [0, 1]
        assert parse_cpu_mask("f", 8) == [0, 1, 2, 3]
        assert parse_cpu_mask("ff", 8) == [0, 1, 2, 3, 4, 5, 6, 7]

        # Mask with comma (large systems)
        assert parse_cpu_mask("ff,ff", 16) == list(range(16))

        # Invalid mask
        assert parse_cpu_mask("xyz", 8) is None

    def test_parse_cpu_list(self, mock_context):
        """Test CPU list parsing."""
        from scripts.baremetal.scheduler_affinity import parse_cpu_list

        assert parse_cpu_list("0") == [0]
        assert parse_cpu_list("0,1,2") == [0, 1, 2]
        assert parse_cpu_list("0-3") == [0, 1, 2, 3]
        assert parse_cpu_list("0,2-4,6") == [0, 2, 3, 4, 6]

    def test_policy_distribution(self, mock_context, monkeypatch):
        """Output includes policy distribution."""
        from scripts.baremetal import scheduler_affinity

        mock_processes = [
            {'pid': 1, 'name': 'a', 'cmdline': 'a', 'policy': 0,
             'policy_name': 'SCHED_OTHER', 'priority': 120,
             'affinity_mask': 'f', 'allowed_cpus': [0, 1, 2, 3]},
            {'pid': 2, 'name': 'b', 'cmdline': 'b', 'policy': 0,
             'policy_name': 'SCHED_OTHER', 'priority': 120,
             'affinity_mask': 'f', 'allowed_cpus': [0, 1, 2, 3]},
            {'pid': 3, 'name': 'c', 'cmdline': 'c', 'policy': 1,
             'policy_name': 'SCHED_FIFO', 'priority': 50,
             'affinity_mask': '1', 'allowed_cpus': [0]},
        ]

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr(
            scheduler_affinity,
            "scan_processes",
            lambda **kw: (mock_processes, 4)
        )
        monkeypatch.setattr(scheduler_affinity, "get_isolated_cpus", lambda: [])

        ctx = mock_context()
        output = Output()

        exit_code = scheduler_affinity.run([], output, ctx)

        assert exit_code == 0
        assert "policy_distribution" in output.data
        assert output.data["policy_distribution"]["SCHED_OTHER"] == 2
        assert output.data["policy_distribution"]["SCHED_FIFO"] == 1

    def test_verbose_includes_rt_processes(self, mock_context, monkeypatch):
        """Verbose mode includes RT process details."""
        from scripts.baremetal import scheduler_affinity

        mock_processes = [
            {'pid': 100, 'name': 'rtapp', 'cmdline': 'rtapp', 'policy': 1,
             'policy_name': 'SCHED_FIFO', 'priority': 50,
             'affinity_mask': '1', 'allowed_cpus': [0]},
        ]

        monkeypatch.setattr("os.path.exists", lambda p: True)
        monkeypatch.setattr(
            scheduler_affinity,
            "scan_processes",
            lambda **kw: (mock_processes, 4)
        )
        monkeypatch.setattr(scheduler_affinity, "get_isolated_cpus", lambda: [])

        ctx = mock_context()
        output = Output()

        exit_code = scheduler_affinity.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "rt_processes" in output.data
        assert len(output.data["rt_processes"]) == 1
        assert output.data["rt_processes"][0]["pid"] == 100

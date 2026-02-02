"""Tests for run_queue script."""

import pytest

from boxctl.core.output import Output


class TestRunQueue:
    """Tests for run_queue script."""

    def test_no_proc_data_returns_error(self, mock_context, monkeypatch):
        """Returns exit code 2 when /proc data unavailable."""
        from scripts.baremetal import run_queue

        monkeypatch.setattr(run_queue, "parse_stat", lambda: None)
        monkeypatch.setattr(run_queue, "parse_loadavg", lambda: None)

        ctx = mock_context()
        output = Output()

        exit_code = run_queue.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_system(self, mock_context, monkeypatch):
        """Returns 0 for a healthy system."""
        from scripts.baremetal import run_queue

        mock_stat = {
            'cpus': {
                0: {'busy_pct': 30.0},
                1: {'busy_pct': 35.0},
            },
            'context_switches': 100000,
            'processes_running': 2,
            'processes_blocked': 0
        }
        mock_loadavg = {
            'load_1min': 0.5,
            'load_5min': 0.4,
            'load_15min': 0.3,
            'running': 2,
            'total_tasks': 100
        }

        monkeypatch.setattr(run_queue, "parse_stat", lambda: mock_stat)
        monkeypatch.setattr(run_queue, "parse_loadavg", lambda: mock_loadavg)
        monkeypatch.setattr(run_queue, "parse_sched_debug", lambda: None)
        monkeypatch.setattr(run_queue, "get_cpu_count", lambda: 2)

        ctx = mock_context()
        output = Output()

        exit_code = run_queue.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "healthy"
        assert output.data["cpu_count"] == 2

    def test_high_queue_depth_warning(self, mock_context, monkeypatch):
        """Warns when queue depth exceeds warning threshold."""
        from scripts.baremetal import run_queue

        mock_stat = {
            'cpus': {0: {'busy_pct': 50.0}},
            'context_switches': 100000,
            'processes_running': 3,
            'processes_blocked': 0
        }
        mock_loadavg = {
            'load_1min': 1.5,
            'load_5min': 1.2,
            'load_15min': 1.0,
            'running': 3,  # 3 running on 2 CPUs = 1.5 per CPU
            'total_tasks': 100
        }

        monkeypatch.setattr(run_queue, "parse_stat", lambda: mock_stat)
        monkeypatch.setattr(run_queue, "parse_loadavg", lambda: mock_loadavg)
        monkeypatch.setattr(run_queue, "parse_sched_debug", lambda: None)
        monkeypatch.setattr(run_queue, "get_cpu_count", lambda: 2)

        ctx = mock_context()
        output = Output()

        exit_code = run_queue.run([], output, ctx)

        # Queue depth 1.5 > warning threshold 1.0, but < critical 2.0
        # So status is warning, not critical (exit 0 for warnings)
        assert exit_code == 0
        assert output.data["status"] == "warning"
        assert any(w["type"] == "queue_warning" for w in output.data["warnings"])

    def test_cpu_imbalance_detection(self, mock_context, monkeypatch):
        """Detects CPU utilization imbalance."""
        from scripts.baremetal import run_queue

        mock_stat = {
            'cpus': {
                0: {'busy_pct': 90.0},
                1: {'busy_pct': 20.0},  # 70% spread
            },
            'context_switches': 100000,
            'processes_running': 2,
            'processes_blocked': 0
        }
        mock_loadavg = {
            'load_1min': 0.5,
            'load_5min': 0.4,
            'load_15min': 0.3,
            'running': 2,
            'total_tasks': 100
        }

        monkeypatch.setattr(run_queue, "parse_stat", lambda: mock_stat)
        monkeypatch.setattr(run_queue, "parse_loadavg", lambda: mock_loadavg)
        monkeypatch.setattr(run_queue, "parse_sched_debug", lambda: None)
        monkeypatch.setattr(run_queue, "get_cpu_count", lambda: 2)

        ctx = mock_context()
        output = Output()

        exit_code = run_queue.run([], output, ctx)

        # 70% imbalance > critical threshold of 50%
        assert exit_code == 1
        assert output.data["status"] == "critical"
        assert any(i["type"] == "imbalance_critical" for i in output.data["issues"])

    def test_blocked_processes_warning(self, mock_context, monkeypatch):
        """Warns when many processes are blocked."""
        from scripts.baremetal import run_queue

        mock_stat = {
            'cpus': {0: {'busy_pct': 50.0}},
            'context_switches': 100000,
            'processes_running': 2,
            'processes_blocked': 3  # > cpu_count (2) threshold
        }
        mock_loadavg = {
            'load_1min': 0.5,
            'load_5min': 0.4,
            'load_15min': 0.3,
            'running': 2,
            'total_tasks': 100
        }

        monkeypatch.setattr(run_queue, "parse_stat", lambda: mock_stat)
        monkeypatch.setattr(run_queue, "parse_loadavg", lambda: mock_loadavg)
        monkeypatch.setattr(run_queue, "parse_sched_debug", lambda: None)
        monkeypatch.setattr(run_queue, "get_cpu_count", lambda: 2)

        ctx = mock_context()
        output = Output()

        exit_code = run_queue.run([], output, ctx)

        assert output.data["blocked_tasks"] == 3

    def test_verbose_includes_details(self, mock_context, monkeypatch):
        """Verbose mode includes per-CPU details."""
        from scripts.baremetal import run_queue

        mock_stat = {
            'cpus': {
                0: {'busy_pct': 30.0},
                1: {'busy_pct': 35.0},
            },
            'context_switches': 123456,
            'processes_running': 2,
            'processes_blocked': 0
        }
        mock_loadavg = {
            'load_1min': 0.5,
            'load_5min': 0.4,
            'load_15min': 0.3,
            'running': 2,
            'total_tasks': 100
        }

        monkeypatch.setattr(run_queue, "parse_stat", lambda: mock_stat)
        monkeypatch.setattr(run_queue, "parse_loadavg", lambda: mock_loadavg)
        monkeypatch.setattr(run_queue, "parse_sched_debug", lambda: None)
        monkeypatch.setattr(run_queue, "get_cpu_count", lambda: 2)

        ctx = mock_context()
        output = Output()

        exit_code = run_queue.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "per_cpu_busy_pct" in output.data
        assert "context_switches" in output.data
        assert output.data["context_switches"] == 123456

    def test_load_averages_in_output(self, mock_context, monkeypatch):
        """Load averages are included in output."""
        from scripts.baremetal import run_queue

        mock_stat = {
            'cpus': {0: {'busy_pct': 30.0}},
            'context_switches': 100000,
            'processes_running': 1,
            'processes_blocked': 0
        }
        mock_loadavg = {
            'load_1min': 1.23,
            'load_5min': 1.45,
            'load_15min': 1.67,
            'running': 1,
            'total_tasks': 100
        }

        monkeypatch.setattr(run_queue, "parse_stat", lambda: mock_stat)
        monkeypatch.setattr(run_queue, "parse_loadavg", lambda: mock_loadavg)
        monkeypatch.setattr(run_queue, "parse_sched_debug", lambda: None)
        monkeypatch.setattr(run_queue, "get_cpu_count", lambda: 1)

        ctx = mock_context()
        output = Output()

        exit_code = run_queue.run([], output, ctx)

        assert exit_code == 0
        assert "load_averages" in output.data
        assert output.data["load_averages"]["1min"] == 1.23
        assert output.data["load_averages"]["5min"] == 1.45
        assert output.data["load_averages"]["15min"] == 1.67

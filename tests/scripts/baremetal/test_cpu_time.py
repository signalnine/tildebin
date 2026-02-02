"""Tests for cpu_time script."""

import pytest

from boxctl.core.output import Output


PROC_STAT_HEALTHY = """cpu  10000 500 2000 80000 500 100 50 0 0 0
cpu0 2500 125 500 20000 125 25 12 0 0 0
cpu1 2500 125 500 20000 125 25 13 0 0 0
cpu2 2500 125 500 20000 125 25 12 0 0 0
cpu3 2500 125 500 20000 125 25 13 0 0 0
intr 12345678
"""

PROC_STAT_HIGH_STEAL = """cpu  10000 500 2000 60000 500 100 50 20000 0 0
cpu0 2500 125 500 15000 125 25 12 5000 0 0
cpu1 2500 125 500 15000 125 25 13 5000 0 0
cpu2 2500 125 500 15000 125 25 12 5000 0 0
cpu3 2500 125 500 15000 125 25 13 5000 0 0
intr 12345678
"""

PROC_STAT_HIGH_IOWAIT = """cpu  10000 500 2000 50000 30000 100 50 0 0 0
cpu0 2500 125 500 12500 7500 25 12 0 0 0
cpu1 2500 125 500 12500 7500 25 13 0 0 0
cpu2 2500 125 500 12500 7500 25 12 0 0 0
cpu3 2500 125 500 12500 7500 25 13 0 0 0
intr 12345678
"""

PROC_STAT_IMBALANCED = """cpu  10000 500 2000 80000 500 100 50 0 0 0
cpu0 8000 400 1600 10000 100 80 40 0 0 0
cpu1 1000 50 200 35000 200 10 5 0 0 0
cpu2 500 25 100 17500 100 5 2 0 0 0
cpu3 500 25 100 17500 100 5 3 0 0 0
intr 12345678
"""


class TestCpuTime:
    """Tests for cpu_time script."""

    def test_missing_proc_stat(self, mock_context):
        """Returns exit code 2 when /proc/stat not available."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = cpu_time.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_cpu(self, mock_context):
        """Returns 0 when CPU is healthy."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_HEALTHY,
            }
        )
        output = Output()

        exit_code = cpu_time.run([], output, ctx)

        assert exit_code == 0
        assert "aggregate" in output.data
        assert output.data["cpu_count"] == 4
        # Low steal and iowait
        assert output.data["aggregate"]["steal"] < 5
        assert output.data["aggregate"]["iowait"] < 10

    def test_high_steal_time(self, mock_context):
        """Returns 1 when steal time is high."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_HIGH_STEAL,
            }
        )
        output = Output()

        exit_code = cpu_time.run([], output, ctx)

        assert exit_code == 1
        assert output.data["aggregate"]["steal"] > 15
        assert any("steal" in i["message"].lower() for i in output.data["issues"])

    def test_high_iowait(self, mock_context):
        """Returns 1 when I/O wait is high."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_HIGH_IOWAIT,
            }
        )
        output = Output()

        exit_code = cpu_time.run([], output, ctx)

        assert exit_code == 1
        assert output.data["aggregate"]["iowait"] > 25
        assert any("i/o" in i["message"].lower() or "iowait" in i["message"].lower()
                  for i in output.data["issues"])

    def test_cpu_imbalance(self, mock_context):
        """Returns 1 when CPUs are imbalanced."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_IMBALANCED,
            }
        )
        output = Output()

        exit_code = cpu_time.run([], output, ctx)

        assert exit_code == 1
        assert any("imbalance" in i["message"].lower() for i in output.data["issues"])

    def test_verbose_shows_per_cpu(self, mock_context):
        """--verbose includes per-CPU breakdown."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_HEALTHY,
            }
        )
        output = Output()

        exit_code = cpu_time.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "per_cpu" in output.data
        assert "cpu0" in output.data["per_cpu"]
        assert "cpu1" in output.data["per_cpu"]

    def test_custom_steal_threshold(self, mock_context):
        """Custom steal threshold is respected."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_HIGH_STEAL,
            }
        )
        output = Output()

        # Set threshold higher than actual to make it pass
        exit_code = cpu_time.run(["--steal-warn", "50", "--steal-crit", "60"], output, ctx)

        # Should still have iowait issues potentially, but not steal
        steal_issues = [i for i in output.data["issues"] if "steal" in i["message"].lower()]
        assert len(steal_issues) == 0

    def test_custom_iowait_threshold(self, mock_context):
        """Custom iowait threshold is respected."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_HIGH_IOWAIT,
            }
        )
        output = Output()

        # Set threshold higher than actual
        exit_code = cpu_time.run(["--iowait-warn", "50", "--iowait-crit", "60"], output, ctx)

        iowait_issues = [i for i in output.data["issues"] if "i/o" in i["message"].lower()]
        assert len(iowait_issues) == 0

    def test_aggregate_metrics(self, mock_context):
        """Correctly calculates aggregate metrics."""
        from scripts.baremetal import cpu_time

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/stat": PROC_STAT_HEALTHY,
            }
        )
        output = Output()

        exit_code = cpu_time.run([], output, ctx)

        assert exit_code == 0
        agg = output.data["aggregate"]
        # Check total_busy is calculated
        assert "total_busy" in agg
        assert agg["total_busy"] == round(100 - agg["idle"], 2)
        # Check interrupt total is calculated
        assert "total_interrupt" in agg
        assert agg["total_interrupt"] == round(agg["irq"] + agg["softirq"], 2)

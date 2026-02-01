"""Tests for thermal_throttle script."""

import pytest

from boxctl.core.output import Output


def make_cpu_throttle_files(cpus: list[dict]) -> dict[str, str]:
    """Build file_contents dict for MockContext with CPU throttle data."""
    files = {}

    for i, cpu in enumerate(cpus):
        base = f"/sys/devices/system/cpu/cpu{i}"
        throttle_base = f"{base}/thermal_throttle"
        files[base] = ""  # Directory marker
        files[throttle_base] = ""  # Directory marker

        files[f"{throttle_base}/core_throttle_count"] = str(cpu.get("core", 0))
        files[f"{throttle_base}/package_throttle_count"] = str(cpu.get("package", 0))

        if "core_time" in cpu:
            files[f"{throttle_base}/core_throttle_total_time_ms"] = str(cpu["core_time"])
        if "package_time" in cpu:
            files[f"{throttle_base}/package_throttle_total_time_ms"] = str(cpu["package_time"])

    return files


class TestThermalThrottle:
    """Tests for thermal_throttle script."""

    def test_missing_interface_returns_error(self, mock_context):
        """Returns exit code 2 when thermal throttle interface unavailable."""
        from scripts.baremetal import thermal_throttle

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = thermal_throttle.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("thermal throttle" in e.lower() for e in output.errors)

    def test_no_throttling_returns_zero(self, mock_context):
        """Returns 0 when no throttling detected."""
        from scripts.baremetal import thermal_throttle

        files = make_cpu_throttle_files([
            {"core": 0, "package": 0},
            {"core": 0, "package": 0},
            {"core": 0, "package": 0},
            {"core": 0, "package": 0},
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_throttle.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["status"] == "OK"
        assert output.data["summary"]["total_core_throttles"] == 0
        assert output.data["summary"]["total_package_throttles"] == 0

    def test_core_throttling_detected(self, mock_context):
        """Returns 1 when core throttling detected."""
        from scripts.baremetal import thermal_throttle

        files = make_cpu_throttle_files([
            {"core": 10, "package": 0},
            {"core": 5, "package": 0},
            {"core": 0, "package": 0},
            {"core": 0, "package": 0},
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_throttle.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["status"] == "WARNING"
        assert output.data["summary"]["total_core_throttles"] == 15
        assert output.data["summary"]["cpus_with_throttles"] == 2

    def test_package_throttling_detected(self, mock_context):
        """Returns 1 when package throttling detected."""
        from scripts.baremetal import thermal_throttle

        files = make_cpu_throttle_files([
            {"core": 0, "package": 25},
            {"core": 0, "package": 25},
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_throttle.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["total_package_throttles"] == 50

    def test_critical_status_high_throttle_count(self, mock_context):
        """Returns CRITICAL status when throttle count > 100."""
        from scripts.baremetal import thermal_throttle

        files = make_cpu_throttle_files([
            {"core": 150, "package": 0},
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_throttle.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["status"] == "CRITICAL"

    def test_threshold_option(self, mock_context):
        """--threshold filters minor throttling."""
        from scripts.baremetal import thermal_throttle

        files = make_cpu_throttle_files([
            {"core": 5, "package": 0},  # Below threshold
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        # With threshold=10, 5 throttles should be OK
        exit_code = thermal_throttle.run(["--threshold", "10"], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["status"] == "OK"

    def test_warn_only_filters_output(self, mock_context):
        """--warn-only filters to only CPUs with throttles."""
        from scripts.baremetal import thermal_throttle

        files = make_cpu_throttle_files([
            {"core": 10, "package": 0},  # Throttled
            {"core": 0, "package": 0},   # Clean
            {"core": 0, "package": 0},   # Clean
            {"core": 5, "package": 2},   # Throttled
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_throttle.run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # Only 2 CPUs should be in output
        assert len(output.data["cpus"]) == 2
        assert all(
            c["core_throttle_count"] > 0 or c["package_throttle_count"] > 0
            for c in output.data["cpus"]
        )

    def test_affected_cpus_list(self, mock_context):
        """affected_cpus lists CPUs with throttle events."""
        from scripts.baremetal import thermal_throttle

        files = make_cpu_throttle_files([
            {"core": 10, "package": 0},  # CPU 0 throttled
            {"core": 0, "package": 0},   # CPU 1 clean
            {"core": 0, "package": 5},   # CPU 2 throttled
            {"core": 0, "package": 0},   # CPU 3 clean
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = thermal_throttle.run([], output, ctx)

        assert exit_code == 1
        assert 0 in output.data["summary"]["affected_cpus"]
        assert 2 in output.data["summary"]["affected_cpus"]
        assert 1 not in output.data["summary"]["affected_cpus"]
        assert 3 not in output.data["summary"]["affected_cpus"]

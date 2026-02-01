"""Tests for entropy_monitor script."""

import pytest

from boxctl.core.output import Output


def make_entropy_files(entropy_avail: int, poolsize: int = 4096,
                       read_wakeup: int = 64, write_wakeup: int = 896,
                       hw_rng: bool = False, daemons: list = None) -> dict[str, str]:
    """Build file_contents dict for MockContext with entropy data."""
    files = {
        "/proc/sys/kernel/random": "",  # Directory marker
        "/proc/sys/kernel/random/entropy_avail": str(entropy_avail),
        "/proc/sys/kernel/random/poolsize": str(poolsize),
        "/proc/sys/kernel/random/read_wakeup_threshold": str(read_wakeup),
        "/proc/sys/kernel/random/write_wakeup_threshold": str(write_wakeup),
    }

    if hw_rng:
        files["/dev/hwrng"] = ""
        files["/sys/class/misc/hw_random/rng_current"] = "tpm-rng-0"

    # Add proc directories for daemon detection
    if daemons:
        files["/proc"] = ""
        for i, daemon in enumerate(daemons):
            pid = str(1000 + i)
            files[f"/proc/{pid}"] = ""
            files[f"/proc/{pid}/comm"] = daemon

    return files


class TestEntropyMonitor:
    """Tests for entropy_monitor script."""

    def test_missing_proc_returns_error(self, mock_context):
        """Returns exit code 2 when /proc filesystem not available."""
        from scripts.baremetal import entropy_monitor

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = entropy_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_entropy(self, mock_context):
        """Returns 0 when entropy is healthy."""
        from scripts.baremetal import entropy_monitor

        files = make_entropy_files(entropy_avail=3000, poolsize=4096)

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = entropy_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["entropy"]["available"] == 3000
        assert len(output.data["issues"]) == 0

    def test_low_entropy_warning(self, mock_context):
        """Returns 1 when entropy below warning threshold."""
        from scripts.baremetal import entropy_monitor

        files = make_entropy_files(entropy_avail=200, poolsize=4096)

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = entropy_monitor.run([], output, ctx)

        assert exit_code == 1
        assert any(i["severity"] == "WARNING" for i in output.data["issues"])

    def test_critical_entropy(self, mock_context):
        """Returns 1 when entropy below critical threshold."""
        from scripts.baremetal import entropy_monitor

        files = make_entropy_files(entropy_avail=50, poolsize=4096)

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = entropy_monitor.run([], output, ctx)

        assert exit_code == 1
        assert any(i["severity"] == "CRITICAL" for i in output.data["issues"])

    def test_below_read_wakeup_threshold(self, mock_context):
        """Returns warning when entropy below read wakeup threshold."""
        from scripts.baremetal import entropy_monitor

        # Entropy at 50, read_wakeup at 64
        files = make_entropy_files(entropy_avail=50, read_wakeup=64)

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = entropy_monitor.run([], output, ctx)

        assert exit_code == 1
        # Should have issue about read wakeup
        read_wakeup_issues = [
            i for i in output.data["issues"]
            if i["metric"] == "read_wakeup"
        ]
        assert len(read_wakeup_issues) > 0

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds affect severity levels."""
        from scripts.baremetal import entropy_monitor

        # 150 bits with default thresholds (warn=256, crit=100) is warning
        files = make_entropy_files(entropy_avail=150, poolsize=4096)

        ctx = mock_context(file_contents=files)
        output = Output()

        # With default thresholds, should be warning
        exit_code = entropy_monitor.run([], output, ctx)
        assert exit_code == 1

        # With lower thresholds (warn=100, crit=50), should be OK
        output2 = Output()
        exit_code2 = entropy_monitor.run(["--warn", "100", "--crit", "50"], output2, ctx)
        assert exit_code2 == 0

    def test_invalid_threshold_order(self, mock_context):
        """Returns error when crit >= warn."""
        from scripts.baremetal import entropy_monitor

        files = make_entropy_files(entropy_avail=3000)

        ctx = mock_context(file_contents=files)
        output = Output()

        # crit must be less than warn
        exit_code = entropy_monitor.run(["--warn", "100", "--crit", "200"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_verbose_shows_rng_info(self, mock_context):
        """--verbose includes RNG source information."""
        from scripts.baremetal import entropy_monitor

        files = make_entropy_files(
            entropy_avail=3000,
            hw_rng=True,
            daemons=["rngd"]
        )

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = entropy_monitor.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "rng" in output.data
        assert output.data["rng"]["hw_rng_available"] is True
        assert output.data["rng"]["rngd_running"] is True

    def test_percentage_calculation(self, mock_context):
        """Correctly calculates entropy percentage."""
        from scripts.baremetal import entropy_monitor

        # 2048 out of 4096 = 50%
        files = make_entropy_files(entropy_avail=2048, poolsize=4096)

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = entropy_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["entropy"]["percent"] == 50.0

"""Tests for container_runtime_health script."""

import json
import subprocess
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestContainerRuntimeHealth:
    """Tests for container_runtime_health."""

    def test_docker_healthy(self, capsys):
        """Healthy Docker runtime returns exit code 0."""
        from scripts.baremetal.container_runtime_health import run

        context = MockContext(
            tools_available=["docker"],
            command_outputs={
                ("systemctl", "is-active", "docker"): "active",
                ("systemctl", "is-enabled", "docker"): "enabled",
                ("docker", "info", "--format", "{{.ServerVersion}}"): "24.0.7",
                ("docker", "ps", "-a", "--format", "{{.State}}"): "running\nrunning\nexited",
                ("docker", "images", "-q"): "abc123\ndef456\nghi789",
                ("docker", "images", "-f", "dangling=true", "-q"): "jkl012",
                ("df", "-B1", "/var/lib/docker"): "Filesystem     1B-blocks      Used Available Use% Mounted on\n/dev/sda1  100000000000 40000000000 60000000000  40% /var/lib/docker",
            },
            file_contents={
                "/var/lib/docker": "",  # Just needs to exist
            },
        )
        output = Output()

        result = run(["--runtime", "docker"], output, context)

        assert result == 0

    def test_docker_not_running(self, capsys):
        """Docker not running returns exit code 1."""
        from scripts.baremetal.container_runtime_health import run

        # Create a context where is-active fails
        context = MockContext(
            tools_available=["docker"],
        )
        # Override run method to handle specific cases
        original_run = context.run

        def mock_run(cmd, **kwargs):
            cmd_tuple = tuple(cmd)
            if cmd_tuple == ("systemctl", "is-active", "docker"):
                return subprocess.CompletedProcess(cmd, 3, "inactive", "")
            if cmd_tuple == ("systemctl", "is-enabled", "docker"):
                return subprocess.CompletedProcess(cmd, 0, "enabled", "")
            if cmd_tuple == ("docker", "info", "--format", "{{.ServerVersion}}"):
                return subprocess.CompletedProcess(cmd, 1, "", "Cannot connect to the Docker daemon")
            raise KeyError(f"No mock for {cmd}")

        context.run = mock_run
        output = Output()

        result = run(["--runtime", "docker"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out or "not running" in captured.out.lower() or "not responsive" in captured.out.lower()

    def test_docker_high_storage(self, capsys):
        """High Docker storage usage returns exit code 1."""
        from scripts.baremetal.container_runtime_health import run

        context = MockContext(
            tools_available=["docker"],
            command_outputs={
                ("systemctl", "is-active", "docker"): "active",
                ("systemctl", "is-enabled", "docker"): "enabled",
                ("docker", "info", "--format", "{{.ServerVersion}}"): "24.0.7",
                ("docker", "ps", "-a", "--format", "{{.State}}"): "running",
                ("docker", "images", "-q"): "abc123",
                ("docker", "images", "-f", "dangling=true", "-q"): "",
                # 90% storage usage
                ("df", "-B1", "/var/lib/docker"): "Filesystem     1B-blocks      Used Available Use% Mounted on\n/dev/sda1  100000000000 90000000000 10000000000  90% /var/lib/docker",
            },
            file_contents={
                "/var/lib/docker": "",
            },
        )
        output = Output()

        result = run(["--runtime", "docker"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "storage" in captured.out.lower()

    def test_docker_dead_containers(self, capsys):
        """Dead Docker containers trigger warning."""
        from scripts.baremetal.container_runtime_health import run

        context = MockContext(
            tools_available=["docker"],
            command_outputs={
                ("systemctl", "is-active", "docker"): "active",
                ("systemctl", "is-enabled", "docker"): "enabled",
                ("docker", "info", "--format", "{{.ServerVersion}}"): "24.0.7",
                ("docker", "ps", "-a", "--format", "{{.State}}"): "running\ndead\ndead",
                ("docker", "images", "-q"): "abc123",
                ("docker", "images", "-f", "dangling=true", "-q"): "",
                ("df", "-B1", "/var/lib/docker"): "Filesystem     1B-blocks      Used Available Use% Mounted on\n/dev/sda1  100000000000 40000000000 60000000000  40% /var/lib/docker",
            },
            file_contents={
                "/var/lib/docker": "",
            },
        )
        output = Output()

        result = run(["--runtime", "docker"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "dead" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.container_runtime_health import run

        context = MockContext(
            tools_available=["docker"],
            command_outputs={
                ("systemctl", "is-active", "docker"): "active",
                ("systemctl", "is-enabled", "docker"): "enabled",
                ("docker", "info", "--format", "{{.ServerVersion}}"): "24.0.7",
                ("docker", "ps", "-a", "--format", "{{.State}}"): "running",
                ("docker", "images", "-q"): "abc123",
                ("docker", "images", "-f", "dangling=true", "-q"): "",
                ("df", "-B1", "/var/lib/docker"): "Filesystem     1B-blocks      Used Available Use% Mounted on\n/dev/sda1  100000000000 40000000000 60000000000  40% /var/lib/docker",
            },
            file_contents={
                "/var/lib/docker": "",
            },
        )
        output = Output()

        result = run(["--runtime", "docker", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "runtimes" in data
        assert "summary" in data
        assert len(data["runtimes"]) == 1
        assert data["runtimes"][0]["runtime"] == "docker"

    def test_no_runtime_detected(self, capsys):
        """No runtime detected returns exit code 2."""
        from scripts.baremetal.container_runtime_health import run

        context = MockContext(
            tools_available=[],  # No container tools available
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format output works correctly."""
        from scripts.baremetal.container_runtime_health import run

        context = MockContext(
            tools_available=["docker"],
            command_outputs={
                ("systemctl", "is-active", "docker"): "active",
                ("systemctl", "is-enabled", "docker"): "enabled",
                ("docker", "info", "--format", "{{.ServerVersion}}"): "24.0.7",
                ("docker", "ps", "-a", "--format", "{{.State}}"): "running",
                ("docker", "images", "-q"): "abc123",
                ("docker", "images", "-f", "dangling=true", "-q"): "",
                ("df", "-B1", "/var/lib/docker"): "Filesystem     1B-blocks      Used Available Use% Mounted on\n/dev/sda1  100000000000 40000000000 60000000000  40% /var/lib/docker",
            },
            file_contents={
                "/var/lib/docker": "",
            },
        )
        output = Output()

        result = run(["--runtime", "docker", "--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Runtime" in captured.out
        assert "Status" in captured.out
        assert "docker" in captured.out

    def test_custom_storage_threshold(self, capsys):
        """Custom storage threshold is respected."""
        from scripts.baremetal.container_runtime_health import run

        context = MockContext(
            tools_available=["docker"],
            command_outputs={
                ("systemctl", "is-active", "docker"): "active",
                ("systemctl", "is-enabled", "docker"): "enabled",
                ("docker", "info", "--format", "{{.ServerVersion}}"): "24.0.7",
                ("docker", "ps", "-a", "--format", "{{.State}}"): "running",
                ("docker", "images", "-q"): "abc123",
                ("docker", "images", "-f", "dangling=true", "-q"): "",
                # 90% storage usage
                ("df", "-B1", "/var/lib/docker"): "Filesystem     1B-blocks      Used Available Use% Mounted on\n/dev/sda1  100000000000 90000000000 10000000000  90% /var/lib/docker",
            },
            file_contents={
                "/var/lib/docker": "",
            },
        )
        output = Output()

        # With 95% threshold, 90% should be OK
        result = run(["--runtime", "docker", "--storage-warn", "95"], output, context)

        assert result == 0

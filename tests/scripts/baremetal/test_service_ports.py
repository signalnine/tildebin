"""Tests for service_ports script."""

import pytest

from boxctl.core.output import Output


class TestServicePorts:
    """Tests for service_ports script."""

    def test_no_services_returns_error(self, mock_context):
        """Returns exit code 2 when no services specified."""
        from scripts.baremetal import service_ports

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_timeout(self, mock_context):
        """Returns exit code 2 for invalid timeout."""
        from scripts.baremetal import service_ports

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run(["--timeout", "0", "redis"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_service_spec(self, mock_context):
        """Returns exit code 2 for invalid service specification."""
        from scripts.baremetal import service_ports

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run(["invalid_no_port"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_unknown_preset(self, mock_context):
        """Returns exit code 2 for unknown preset."""
        from scripts.baremetal import service_ports

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run(["unknownservice@localhost"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_list_presets(self, mock_context):
        """--list-presets returns 0 and shows presets."""
        from scripts.baremetal import service_ports

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run(["--list-presets"], output, ctx)

        assert exit_code == 0
        assert "presets" in output.data
        assert len(output.data["presets"]) > 0

        # Check a known preset
        redis_preset = next((p for p in output.data["presets"] if p["name"] == "redis"), None)
        assert redis_preset is not None
        assert redis_preset["port"] == 6379

    def test_parse_service_spec_preset(self, mock_context):
        """Test parsing preset service specification."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("redis")

        assert error is None
        assert service["name"] == "redis"
        assert service["port"] == 6379
        assert service["protocol"] == "tcp"
        assert service["host"] == "localhost"

    def test_parse_service_spec_preset_at_host(self, mock_context):
        """Test parsing preset@host specification."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("redis@10.0.0.1")

        assert error is None
        assert service["name"] == "redis"
        assert service["host"] == "10.0.0.1"
        assert service["port"] == 6379

    def test_parse_service_spec_preset_at_host_port(self, mock_context):
        """Test parsing preset@host:port specification."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("http@10.0.0.1:8080")

        assert error is None
        assert service["name"] == "http"
        assert service["host"] == "10.0.0.1"
        assert service["port"] == 8080

    def test_parse_service_spec_host_port(self, mock_context):
        """Test parsing host:port specification."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("myhost:9999")

        assert error is None
        assert service["host"] == "myhost"
        assert service["port"] == 9999
        assert service["protocol"] == "tcp"

    def test_parse_service_spec_host_port_protocol(self, mock_context):
        """Test parsing host:port:protocol specification."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("10.0.0.1:53:udp")

        assert error is None
        assert service["host"] == "10.0.0.1"
        assert service["port"] == 53
        assert service["protocol"] == "udp"

    def test_parse_service_spec_invalid_port(self, mock_context):
        """Test parsing with invalid port number."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("localhost:invalid")

        assert service is None
        assert error is not None
        assert "Invalid port" in error

    def test_parse_service_spec_port_out_of_range(self, mock_context):
        """Test parsing with port out of range."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("localhost:99999")

        assert service is None
        assert error is not None
        assert "out of range" in error

    def test_parse_service_spec_invalid_protocol(self, mock_context):
        """Test parsing with invalid protocol."""
        from scripts.baremetal.service_ports import parse_service_spec

        service, error = parse_service_spec("localhost:80:sctp")

        assert service is None
        assert error is not None
        assert "Invalid protocol" in error

    def test_output_structure(self, mock_context, monkeypatch):
        """Test output data structure."""
        from scripts.baremetal import service_ports

        # Mock the check to avoid actual network calls
        monkeypatch.setattr(
            service_ports,
            "check_service",
            lambda svc, timeout: {"reachable": True, "latency_ms": 1.5, "error": None}
        )

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run(["redis"], output, ctx)

        assert exit_code == 0
        assert "services" in output.data
        assert output.data["total"] == 1
        assert output.data["reachable_count"] == 1
        assert output.data["unreachable_count"] == 0

    def test_unreachable_service(self, mock_context, monkeypatch):
        """Returns 1 when service is unreachable."""
        from scripts.baremetal import service_ports

        monkeypatch.setattr(
            service_ports,
            "check_service",
            lambda svc, timeout: {"reachable": False, "latency_ms": None, "error": "connection refused"}
        )

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run(["redis"], output, ctx)

        assert exit_code == 1
        assert output.data["unreachable_count"] == 1
        assert output.data["services"][0]["error"] == "connection refused"

    def test_verbose_includes_extras(self, mock_context, monkeypatch):
        """Verbose mode includes extra details."""
        from scripts.baremetal import service_ports

        monkeypatch.setattr(
            service_ports,
            "check_service",
            lambda svc, timeout: {
                "reachable": True,
                "latency_ms": 1.5,
                "error": None,
                "http_status": 200,
                "http_version": "HTTP/1.1"
            }
        )

        ctx = mock_context()
        output = Output()

        exit_code = service_ports.run(["--verbose", "http"], output, ctx)

        assert exit_code == 0
        assert output.data["services"][0]["http_status"] == 200
        assert output.data["services"][0]["http_version"] == "HTTP/1.1"

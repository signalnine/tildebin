"""Tests for k8s security_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestSecurityAudit:
    """Tests for security_audit."""

    def test_secure_pod(self, capsys):
        """Secure pod returns exit code 0."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "secure-pod",
                        "namespace": "production",
                        "annotations": {
                            "container.apparmor.security.beta.kubernetes.io/web": "runtime/default"
                        }
                    },
                    "spec": {
                        "securityContext": {
                            "runAsNonRoot": True,
                            "seccompProfile": {"type": "RuntimeDefault"}
                        },
                        "containers": [
                            {
                                "name": "web",
                                "securityContext": {
                                    "runAsUser": 1000,
                                    "readOnlyRootFilesystem": True,
                                    "allowPrivilegeEscalation": False
                                }
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_privileged_container(self, capsys):
        """Privileged container returns CRITICAL."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "privileged-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "securityContext": {
                                    "privileged": True
                                }
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "privileged" in captured.out.lower()

    def test_root_user(self, capsys):
        """Container running as root shows HIGH severity."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "root-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "securityContext": {
                                    "runAsUser": 0
                                }
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "root" in captured.out.lower()

    def test_dangerous_capability(self, capsys):
        """Dangerous capability shows appropriate severity."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "cap-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "securityContext": {
                                    "capabilities": {
                                        "add": ["SYS_ADMIN"]
                                    }
                                }
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "SYS_ADMIN" in captured.out

    def test_host_pid(self, capsys):
        """Host PID namespace shows CRITICAL."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "hostpid-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "hostPID": True,
                        "containers": [{"name": "app"}]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "host PID" in captured.out

    def test_host_network(self, capsys):
        """Host network shows HIGH severity."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "hostnet-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "hostNetwork": True,
                        "containers": [{"name": "app"}]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "host network" in captured.out.lower()

    def test_sensitive_host_path(self, capsys):
        """Sensitive host path mount shows HIGH severity."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "hostpath-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "volumes": [
                            {"name": "etc", "hostPath": {"path": "/etc"}}
                        ],
                        "containers": [{"name": "app"}]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "/etc" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "securityContext": {"privileged": True}
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "total_issues" in data["summary"]
        assert "critical" in data["summary"]
        assert "high" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "securityContext": {"privileged": True}
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Severity" in captured.out
        assert "Type" in captured.out
        assert "Detail" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters LOW severity issues."""
        from scripts.k8s.security_audit import run

        # Pod with only LOW severity issues (missing readOnlyRootFilesystem)
        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "pod",
                        "namespace": "production",
                        "annotations": {
                            "container.apparmor.security.beta.kubernetes.io/app": "runtime/default"
                        }
                    },
                    "spec": {
                        "securityContext": {"runAsNonRoot": True},
                        "containers": [
                            {
                                "name": "app",
                                "securityContext": {
                                    "allowPrivilegeEscalation": False
                                }
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        # Should return 0 because only LOW issues exist and warn-only filters them
        assert result == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.security_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_no_pods(self, capsys):
        """No pods returns exit code 0."""
        from scripts.k8s.security_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_init_containers_checked(self, capsys):
        """Init containers are also checked."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init",
                                "securityContext": {"privileged": True}
                            }
                        ],
                        "containers": [{"name": "app"}]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "init" in captured.out

    def test_summary_set(self):
        """Summary is set correctly."""
        from scripts.k8s.security_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "securityContext": {"privileged": True}
                            }
                        ]
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        run([], output, context)

        assert "issues=" in output.summary
        assert "critical=" in output.summary
        assert "high=" in output.summary

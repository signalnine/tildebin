"""Tests for k8s gitops_sync script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_flux_kustomization(
    name: str,
    namespace: str = "flux-system",
    ready: bool = True,
    suspended: bool = False,
    revision: str = "abc123def456",
) -> dict:
    """Create a Flux Kustomization for testing."""
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "suspend": suspended,
            "sourceRef": {"name": "source-repo"},
        },
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "reason": "ReconciliationSucceeded" if ready else "ReconciliationFailed",
                    "message": "Applied successfully" if ready else "Failed to apply",
                }
            ],
            "lastAppliedRevision": revision,
            "lastAttemptedRevision": revision,
        },
    }


def make_flux_helmrelease(
    name: str,
    namespace: str = "flux-system",
    ready: bool = True,
    suspended: bool = False,
    failures: int = 0,
) -> dict:
    """Create a Flux HelmRelease for testing."""
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "suspend": suspended,
            "chart": {"spec": {"name": "my-chart"}},
        },
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "reason": "InstallSucceeded" if ready else "InstallFailed",
                },
                {
                    "type": "Released",
                    "status": "True" if ready else "False",
                },
            ],
            "failures": failures,
            "lastAppliedRevision": "1.2.3",
        },
    }


def make_flux_gitrepository(
    name: str,
    namespace: str = "flux-system",
    ready: bool = True,
    suspended: bool = False,
) -> dict:
    """Create a Flux GitRepository for testing."""
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "suspend": suspended,
            "url": "https://github.com/org/repo",
            "ref": {"branch": "main"},
        },
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "reason": "GitCloneSucceeded" if ready else "GitCloneFailed",
                }
            ],
            "artifact": {"revision": "abc123def456"},
        },
    }


def make_argocd_application(
    name: str,
    namespace: str = "argocd",
    sync_status: str = "Synced",
    health_status: str = "Healthy",
) -> dict:
    """Create an ArgoCD Application for testing."""
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "source": {"repoURL": "https://github.com/org/repo", "targetRevision": "HEAD"},
            "destination": {"namespace": "default"},
        },
        "status": {
            "sync": {"status": sync_status},
            "health": {"status": health_status},
            "conditions": [],
        },
    }


class TestGitopsSync:
    """Tests for gitops_sync."""

    def test_healthy_flux_resources(self, capsys):
        """Healthy Flux resources return exit code 0."""
        from scripts.k8s.gitops_sync import run

        kustomizations = {"items": [make_flux_kustomization("app-1")]}
        helmreleases = {"items": [make_flux_helmrelease("release-1")]}
        gitrepositories = {"items": [make_flux_gitrepository("source-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(kustomizations),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(helmreleases),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(gitrepositories),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        assert "Flux CD Resources" in captured.out

    def test_unhealthy_flux_kustomization(self, capsys):
        """Unhealthy Flux Kustomization returns exit code 1."""
        from scripts.k8s.gitops_sync import run

        kustomizations = {"items": [make_flux_kustomization("app-1", ready=False)]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(kustomizations),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[!!]" in captured.out
        assert "Not ready" in captured.out

    def test_suspended_resource_flagged(self, capsys):
        """Suspended resources are flagged."""
        from scripts.k8s.gitops_sync import run

        kustomizations = {"items": [make_flux_kustomization("app-1", suspended=True)]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(kustomizations),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "SUSPENDED" in captured.out

    def test_healthy_argocd_application(self, capsys):
        """Healthy ArgoCD application returns exit code 0."""
        from scripts.k8s.gitops_sync import run

        applications = {"items": [make_argocd_application("app-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps(applications),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "ArgoCD Resources" in captured.out
        assert "[OK]" in captured.out

    def test_out_of_sync_argocd_application(self, capsys):
        """Out-of-sync ArgoCD application returns exit code 1."""
        from scripts.k8s.gitops_sync import run

        applications = {"items": [make_argocd_application("app-1", sync_status="OutOfSync")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps(applications),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "OutOfSync" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.gitops_sync import run

        kustomizations = {"items": [make_flux_kustomization("app-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(kustomizations),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["type"] == "Kustomization"
        assert data[0]["controller"] == "flux"
        assert "healthy" in data[0]

    def test_no_gitops_resources(self, capsys):
        """No GitOps resources returns exit code 0 with message."""
        from scripts.k8s.gitops_sync import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No GitOps resources found" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy resources."""
        from scripts.k8s.gitops_sync import run

        kustomizations = {
            "items": [
                make_flux_kustomization("healthy-app"),
                make_flux_kustomization("unhealthy-app", ready=False),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(kustomizations),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "unhealthy-app" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.gitops_sync import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_helmrelease_with_failures(self, capsys):
        """HelmRelease with failures is flagged."""
        from scripts.k8s.gitops_sync import run

        helmreleases = {"items": [make_flux_helmrelease("release-1", failures=3)]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(helmreleases),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "3 recorded failure" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.gitops_sync import run

        kustomizations = {"items": [make_flux_kustomization("app-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps(kustomizations),
                ("kubectl", "get", "helmreleases.helm.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "gitrepositories.source.toolkit.fluxcd.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applications.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "applicationsets.argoproj.io", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "resources=" in output.summary
        assert "healthy=" in output.summary

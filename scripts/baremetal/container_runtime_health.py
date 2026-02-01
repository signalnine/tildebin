#!/usr/bin/env python3
# boxctl:
#   category: baremetal/container
#   tags: [health, container, docker, containerd, podman, monitoring]
#   related: [cgroup_memory_limits, cgroup_cpu_limits, cgroup_pressure]
#   brief: Monitor container runtime health (Docker, containerd, podman)

"""
Monitor container runtime health on baremetal systems.

Monitors the health of container runtimes (Docker, containerd, podman)
running on baremetal hosts. Useful for:

- Detecting container runtime service failures before they impact workloads
- Monitoring disk space in container storage paths (/var/lib/docker, etc.)
- Identifying stale or dead containers consuming resources
- Tracking image storage growth and cleanup needs
- Verifying runtime socket availability for orchestrators

The script checks service status, storage usage, container states, and
runtime responsiveness. Supports multiple runtimes simultaneously.

Exit codes:
    0: All container runtimes healthy, no issues detected
    1: Warnings or errors found (service issues, high disk usage, dead containers)
    2: Usage error or no container runtime found
"""

import argparse
import json
import os

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_systemd_service(context: Context, service_name: str) -> dict:
    """Check systemd service status."""
    result = {
        "service": service_name,
        "active": False,
        "status": "unknown",
        "enabled": False,
    }

    # Check if service is active
    try:
        proc = context.run(["systemctl", "is-active", service_name])
        result["status"] = proc.stdout.strip()
        result["active"] = proc.returncode == 0
    except Exception:
        pass

    # Check if service is enabled
    try:
        proc = context.run(["systemctl", "is-enabled", service_name])
        result["enabled"] = proc.returncode == 0
    except Exception:
        pass

    return result


def get_storage_usage(context: Context, path: str) -> dict | None:
    """Get disk usage for a path."""
    if not context.file_exists(path):
        return None

    try:
        # Use df to get filesystem stats
        proc = context.run(["df", "-B1", path])
        if proc.returncode != 0:
            return None

        lines = proc.stdout.strip().split("\n")
        if len(lines) < 2:
            return None

        # Parse df output (second line has the stats)
        parts = lines[1].split()
        if len(parts) < 4:
            return None

        total = int(parts[1])
        used = int(parts[2])
        free = int(parts[3])

        return {
            "path": path,
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "usage_percent": (used / total * 100) if total > 0 else 0,
        }
    except Exception:
        return None


def format_bytes(bytes_val: int | None) -> str:
    """Format bytes to human readable format."""
    if bytes_val is None:
        return "N/A"
    if bytes_val >= 1024**3:
        return f"{bytes_val / (1024 ** 3):.1f} GB"
    elif bytes_val >= 1024**2:
        return f"{bytes_val / (1024 ** 2):.1f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    else:
        return f"{bytes_val} B"


def check_docker_health(context: Context, storage_threshold: float) -> dict:
    """Check Docker runtime health."""
    result = {
        "runtime": "docker",
        "available": True,
        "service": None,
        "storage": None,
        "containers": {"total": 0, "running": 0, "stopped": 0, "dead": 0},
        "images": {"total": 0, "dangling": 0},
        "responsive": False,
        "issues": [],
    }

    # Check Docker service
    result["service"] = check_systemd_service(context, "docker")
    if not result["service"]["active"]:
        result["issues"].append({
            "severity": "CRITICAL",
            "message": "Docker service is not running",
        })

    # Check storage
    storage_paths = ["/var/lib/docker", "/var/lib/containers/storage"]
    for path in storage_paths:
        storage = get_storage_usage(context, path)
        if storage:
            result["storage"] = storage
            if storage["usage_percent"] >= storage_threshold:
                result["issues"].append({
                    "severity": "WARNING",
                    "message": f"Docker storage {storage['usage_percent']:.1f}% used at {path}",
                })
            break

    # Check Docker responsiveness
    try:
        proc = context.run(["docker", "info", "--format", "{{.ServerVersion}}"])
        if proc.returncode == 0:
            result["responsive"] = True
            result["version"] = proc.stdout.strip()
        else:
            result["issues"].append({
                "severity": "CRITICAL",
                "message": f"Docker daemon not responsive: {proc.stderr.strip()}",
            })
            return result
    except Exception as e:
        result["issues"].append({
            "severity": "CRITICAL",
            "message": f"Docker daemon not responsive: {e}",
        })
        return result

    # Get container counts
    try:
        proc = context.run(["docker", "ps", "-a", "--format", "{{.State}}"])
        if proc.returncode == 0:
            states = proc.stdout.strip().split("\n") if proc.stdout.strip() else []
            result["containers"]["total"] = len([s for s in states if s])
            result["containers"]["running"] = states.count("running")
            result["containers"]["stopped"] = states.count("exited")
            result["containers"]["dead"] = states.count("dead")

            if result["containers"]["dead"] > 0:
                result["issues"].append({
                    "severity": "WARNING",
                    "message": f"{result['containers']['dead']} dead container(s) found",
                })
    except Exception:
        pass

    # Get image counts
    try:
        proc = context.run(["docker", "images", "-q"])
        if proc.returncode == 0:
            images = proc.stdout.strip().split("\n") if proc.stdout.strip() else []
            result["images"]["total"] = len([i for i in images if i])
    except Exception:
        pass

    # Check for dangling images
    try:
        proc = context.run(["docker", "images", "-f", "dangling=true", "-q"])
        if proc.returncode == 0:
            dangling = proc.stdout.strip().split("\n") if proc.stdout.strip() else []
            result["images"]["dangling"] = len([i for i in dangling if i])
            if result["images"]["dangling"] > 10:
                result["issues"].append({
                    "severity": "INFO",
                    "message": f"{result['images']['dangling']} dangling images (consider docker image prune)",
                })
    except Exception:
        pass

    return result


def check_containerd_health(context: Context, storage_threshold: float) -> dict:
    """Check containerd runtime health."""
    result = {
        "runtime": "containerd",
        "available": True,
        "service": None,
        "storage": None,
        "responsive": False,
        "issues": [],
    }

    # Check containerd service
    result["service"] = check_systemd_service(context, "containerd")
    if not result["service"]["active"]:
        result["issues"].append({
            "severity": "CRITICAL",
            "message": "containerd service is not running",
        })

    # Check storage
    storage_paths = ["/var/lib/containerd", "/run/containerd"]
    for path in storage_paths:
        storage = get_storage_usage(context, path)
        if storage:
            result["storage"] = storage
            if storage["usage_percent"] >= storage_threshold:
                result["issues"].append({
                    "severity": "WARNING",
                    "message": f"containerd storage {storage['usage_percent']:.1f}% used at {path}",
                })
            break

    # Check containerd responsiveness
    try:
        proc = context.run(["ctr", "version"])
        if proc.returncode == 0:
            result["responsive"] = True
            # Parse version from output
            for line in proc.stdout.split("\n"):
                if "Version:" in line:
                    result["version"] = line.split(":", 1)[1].strip()
                    break
        else:
            result["issues"].append({
                "severity": "CRITICAL",
                "message": f"containerd not responsive: {proc.stderr.strip()}",
            })
    except Exception as e:
        result["issues"].append({
            "severity": "CRITICAL",
            "message": f"containerd not responsive: {e}",
        })

    return result


def check_podman_health(context: Context, storage_threshold: float) -> dict:
    """Check Podman runtime health."""
    result = {
        "runtime": "podman",
        "available": True,
        "service": None,
        "storage": None,
        "containers": {"total": 0, "running": 0, "stopped": 0},
        "images": {"total": 0, "dangling": 0},
        "responsive": False,
        "issues": [],
    }

    # Check podman socket service (if using systemd socket activation)
    result["service"] = check_systemd_service(context, "podman.socket")

    # Check storage
    storage_paths = ["/var/lib/containers/storage", os.path.expanduser("~/.local/share/containers")]
    for path in storage_paths:
        storage = get_storage_usage(context, path)
        if storage:
            result["storage"] = storage
            if storage["usage_percent"] >= storage_threshold:
                result["issues"].append({
                    "severity": "WARNING",
                    "message": f"Podman storage {storage['usage_percent']:.1f}% used at {path}",
                })
            break

    # Check Podman responsiveness
    try:
        proc = context.run(["podman", "version", "--format", "{{.Client.Version}}"])
        if proc.returncode == 0:
            result["responsive"] = True
            result["version"] = proc.stdout.strip()
        else:
            # Podman may work without a daemon for rootless mode
            proc = context.run(["podman", "info", "--format", "{{.Version.Version}}"])
            if proc.returncode == 0:
                result["responsive"] = True
                result["version"] = proc.stdout.strip()
            else:
                result["issues"].append({
                    "severity": "WARNING",
                    "message": f"Podman not fully responsive: {proc.stderr.strip()}",
                })
                return result
    except Exception as e:
        result["issues"].append({
            "severity": "WARNING",
            "message": f"Podman not fully responsive: {e}",
        })
        return result

    # Get container counts
    try:
        proc = context.run(["podman", "ps", "-a", "--format", "{{.State}}"])
        if proc.returncode == 0:
            states = proc.stdout.strip().split("\n") if proc.stdout.strip() else []
            result["containers"]["total"] = len([s for s in states if s])
            result["containers"]["running"] = states.count("running")
            result["containers"]["stopped"] = states.count("exited")
    except Exception:
        pass

    # Get image counts
    try:
        proc = context.run(["podman", "images", "-q"])
        if proc.returncode == 0:
            images = proc.stdout.strip().split("\n") if proc.stdout.strip() else []
            result["images"]["total"] = len([i for i in images if i])
    except Exception:
        pass

    # Check for dangling images
    try:
        proc = context.run(["podman", "images", "-f", "dangling=true", "-q"])
        if proc.returncode == 0:
            dangling = proc.stdout.strip().split("\n") if proc.stdout.strip() else []
            result["images"]["dangling"] = len([i for i in dangling if i])
            if result["images"]["dangling"] > 10:
                result["issues"].append({
                    "severity": "INFO",
                    "message": f"{result['images']['dangling']} dangling images (consider podman image prune)",
                })
    except Exception:
        pass

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor container runtime health on baremetal systems"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format",
    )
    parser.add_argument(
        "--runtime",
        choices=["docker", "containerd", "podman"],
        action="append",
        help="Specific runtime(s) to check (default: auto-detect)",
    )
    parser.add_argument(
        "--storage-warn",
        type=float,
        default=85.0,
        metavar="PCT",
        help="Storage warning threshold percentage (default: 85%%)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show warnings and errors",
    )
    opts = parser.parse_args(args)

    # Validate storage threshold
    if opts.storage_warn < 0 or opts.storage_warn > 100:
        output.error("--storage-warn must be between 0 and 100")
        return 2

    # Detect or use specified runtimes
    if opts.runtime:
        runtimes = opts.runtime
    else:
        # Auto-detect
        runtimes = []
        if context.check_tool("docker"):
            runtimes.append("docker")
        if context.check_tool("ctr"):
            runtimes.append("containerd")
        if context.check_tool("podman"):
            runtimes.append("podman")

    if not runtimes:
        output.error("No container runtimes detected")
        output.error("Install one of: docker, containerd (ctr), podman")
        return 2

    # Check each runtime
    results = []
    for runtime in runtimes:
        if runtime == "docker":
            results.append(check_docker_health(context, opts.storage_warn))
        elif runtime == "containerd":
            results.append(check_containerd_health(context, opts.storage_warn))
        elif runtime == "podman":
            results.append(check_podman_health(context, opts.storage_warn))

    # Output results
    if opts.format == "json":
        result = {
            "runtimes": results,
            "summary": {
                "total_runtimes": len(results),
                "healthy": sum(
                    1
                    for r in results
                    if r.get("responsive")
                    and not any(i["severity"] == "CRITICAL" for i in r.get("issues", []))
                ),
                "has_warnings": any(
                    any(i["severity"] == "WARNING" for i in r.get("issues", []))
                    for r in results
                ),
                "has_errors": any(
                    any(i["severity"] == "CRITICAL" for i in r.get("issues", []))
                    for r in results
                ),
            },
        }
        print(json.dumps(result, indent=2))

    elif opts.format == "table":
        lines = []
        lines.append("=" * 80)
        lines.append("CONTAINER RUNTIME HEALTH SUMMARY")
        lines.append("=" * 80)
        lines.append(
            f"{'Runtime':<15} {'Status':<12} {'Version':<15} {'Containers':<15} {'Issues':<10}"
        )
        lines.append("-" * 80)

        for result in results:
            runtime = result["runtime"]
            status = "OK" if result.get("responsive") else "DOWN"
            version = result.get("version", "N/A")[:14]

            containers = result.get("containers", {})
            container_str = f"{containers.get('running', 0)}/{containers.get('total', 0)}"

            issues = result.get("issues", [])
            critical = sum(1 for i in issues if i["severity"] == "CRITICAL")
            warnings = sum(1 for i in issues if i["severity"] == "WARNING")
            issue_str = f"{critical}C/{warnings}W"

            lines.append(
                f"{runtime:<15} {status:<12} {version:<15} {container_str:<15} {issue_str:<10}"
            )

        lines.append("=" * 80)
        lines.append("")

        # Print all issues
        all_issues = []
        for result in results:
            for issue in result.get("issues", []):
                if opts.warn_only and issue["severity"] == "INFO":
                    continue
                all_issues.append((result["runtime"], issue))

        if all_issues:
            lines.append("ISSUES DETECTED")
            lines.append("-" * 80)
            for runtime, issue in all_issues:
                lines.append(f"[{issue['severity']}] {runtime}: {issue['message']}")
            lines.append("")

        print("\n".join(lines))

    else:  # plain
        for result in results:
            runtime = result["runtime"]
            issues = result.get("issues", [])

            # Skip if no issues and warn_only mode
            if opts.warn_only and not any(
                i["severity"] in ["CRITICAL", "WARNING"] for i in issues
            ):
                continue

            lines = []
            lines.append(f"=== {runtime.upper()} ===")

            if result.get("responsive"):
                version = result.get("version", "unknown")
                lines.append(f"Status: Running (version {version})")
            else:
                lines.append("Status: Not responsive")

            service = result.get("service")
            if service:
                status = "active" if service["active"] else "inactive"
                enabled = "enabled" if service["enabled"] else "disabled"
                lines.append(f"Service: {status} ({enabled})")

            storage = result.get("storage")
            if storage and opts.verbose:
                lines.append(
                    f"Storage: {format_bytes(storage['used_bytes'])} / {format_bytes(storage['total_bytes'])} "
                    f"({storage['usage_percent']:.1f}% used)"
                )

            containers = result.get("containers")
            if containers and opts.verbose:
                lines.append(
                    f"Containers: {containers['total']} total, {containers['running']} running, "
                    f"{containers['stopped']} stopped"
                )
                if containers.get("dead", 0) > 0:
                    lines.append(f"  Dead containers: {containers['dead']}")

            images = result.get("images")
            if images and opts.verbose:
                lines.append(f"Images: {images['total']} total, {images['dangling']} dangling")

            # Print issues
            for issue in issues:
                severity = issue["severity"]
                if opts.warn_only and severity == "INFO":
                    continue
                lines.append(f"[{severity}] {issue['message']}")

            lines.append("")
            print("\n".join(lines))

    # Determine exit code
    has_critical = any(
        any(i["severity"] == "CRITICAL" for i in r.get("issues", [])) for r in results
    )
    has_warning = any(
        any(i["severity"] == "WARNING" for i in r.get("issues", [])) for r in results
    )

    # Set summary
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")
    output.set_summary(f"runtimes={len(runtimes)}, status={status}")

    return 1 if (has_critical or has_warning) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))

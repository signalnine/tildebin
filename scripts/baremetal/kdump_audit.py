#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [kdump, crash, dump, kernel, disaster-recovery]
#   requires: []
#   privilege: user
#   related: [kernel_version, kernel_cmdline_audit, boot_issues_analyzer]
#   brief: Audit kdump (kernel crash dump) configuration for disaster recovery

"""
Audit kdump (kernel crash dump) configuration for disaster recovery readiness.

Verifies that kdump is properly configured to capture kernel crash dumps for
post-mortem analysis. Critical for large-scale baremetal environments where
kernel panics need to be debugged without physical access.

Checks performed:
- kdump service status (systemd)
- Crashkernel memory reservation (kernel cmdline)
- Dump target configuration (local, NFS, SSH)
- Available disk space for crash dumps
- Crash dump directory permissions
- Recent crash dump files
- Kexec crash kernel loaded status

Exit codes:
    0: kdump is properly configured
    1: Configuration issues detected
    2: Error (system files not accessible)
"""

import argparse
import glob
import json
import os
import re
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_kdump_service(context: Context) -> dict[str, Any]:
    """Check kdump service status via systemctl."""
    info = {
        "installed": False,
        "enabled": False,
        "active": False,
        "status": "unknown",
    }

    try:
        # Check if kdump service exists
        result = context.run(
            ["systemctl", "list-unit-files", "kdump.service"], check=False
        )
        if "kdump.service" in result.stdout:
            info["installed"] = True

            # Check if enabled
            result = context.run(
                ["systemctl", "is-enabled", "kdump.service"], check=False
            )
            info["enabled"] = result.returncode == 0

            # Check if active
            result = context.run(
                ["systemctl", "is-active", "kdump.service"], check=False
            )
            info["active"] = result.returncode == 0
            info["status"] = result.stdout.strip()
    except Exception as e:
        info["error"] = str(e)

    return info


def check_crashkernel_reservation() -> dict[str, Any]:
    """Check crashkernel memory reservation from kernel cmdline."""
    info = {
        "reserved": False,
        "parameter": None,
        "size": None,
        "offset": None,
    }

    try:
        with open("/proc/cmdline", "r") as f:
            cmdline = f.read().strip()

        # Look for crashkernel parameter
        # Formats: crashkernel=256M, crashkernel=256M@16M, crashkernel=auto
        match = re.search(r"crashkernel=(\S+)", cmdline)
        if match:
            info["reserved"] = True
            info["parameter"] = match.group(1)

            # Parse size
            size_match = re.match(r"(\d+)([MG])?", match.group(1))
            if size_match:
                size = int(size_match.group(1))
                unit = size_match.group(2) or "M"
                if unit == "G":
                    size *= 1024
                info["size"] = f"{size}M"

            # Check for offset
            offset_match = re.search(r"@(\d+[MG]?)", match.group(1))
            if offset_match:
                info["offset"] = offset_match.group(1)

            # Handle auto
            if match.group(1) == "auto":
                info["size"] = "auto"

    except FileNotFoundError:
        info["error"] = "/proc/cmdline not found"
    except Exception as e:
        info["error"] = str(e)

    return info


def check_kdump_config() -> dict[str, Any]:
    """Read and parse kdump configuration file."""
    config = {
        "path": None,
        "exists": False,
        "settings": {},
    }

    # Check common config file locations
    config_paths = [
        "/etc/kdump.conf",
        "/etc/sysconfig/kdump",
        "/etc/default/kdump-tools",
    ]

    for path in config_paths:
        if os.path.exists(path):
            config["path"] = path
            config["exists"] = True
            break

    if not config["exists"]:
        return config

    try:
        with open(config["path"], "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse key-value pairs
                parts = line.split(None, 1)
                if len(parts) >= 1:
                    key = parts[0]
                    value = parts[1] if len(parts) > 1 else True
                    config["settings"][key] = value

    except Exception as e:
        config["error"] = str(e)

    return config


def check_dump_target(config: dict) -> dict[str, Any]:
    """Determine dump target from configuration."""
    target = {
        "type": "local",
        "path": "/var/crash",
        "device": None,
        "host": None,
    }

    settings = config.get("settings", {})

    # Check for various target types
    if "path" in settings:
        target["path"] = settings["path"]

    if "ext4" in settings or "xfs" in settings or "raw" in settings:
        for fs_type in ["ext4", "xfs", "ext3", "raw"]:
            if fs_type in settings:
                target["type"] = fs_type
                target["device"] = settings[fs_type]
                break

    if "nfs" in settings:
        target["type"] = "nfs"
        target["host"] = settings["nfs"]

    if "ssh" in settings:
        target["type"] = "ssh"
        target["host"] = settings["ssh"]

    return target


def check_dump_directory(path: str) -> dict[str, Any]:
    """Check dump directory availability and permissions."""
    info = {
        "path": path,
        "exists": False,
        "writable": False,
        "available_bytes": 0,
        "total_bytes": 0,
        "used_percent": 0,
        "permissions": None,
    }

    if not os.path.exists(path):
        return info

    info["exists"] = True

    try:
        # Check permissions
        stat_info = os.stat(path)
        info["permissions"] = oct(stat_info.st_mode)[-3:]
        info["writable"] = os.access(path, os.W_OK)

        # Check disk space
        statvfs = os.statvfs(path)
        block_size = statvfs.f_frsize
        total = statvfs.f_blocks * block_size
        free = statvfs.f_bfree * block_size
        available = statvfs.f_bavail * block_size

        info["total_bytes"] = total
        info["available_bytes"] = available
        info["used_percent"] = ((total - free) / total * 100) if total > 0 else 0

    except Exception as e:
        info["error"] = str(e)

    return info


def check_memory_for_dump() -> dict[str, Any]:
    """Check if system has enough memory for crash dump."""
    info = {
        "total_bytes": 0,
        "estimated_dump_size": 0,
    }

    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    # Parse: MemTotal:       16384000 kB
                    parts = line.split()
                    mem_kb = int(parts[1])
                    info["total_bytes"] = mem_kb * 1024
                    # Crash dump is roughly memory size (compressed can be less)
                    info["estimated_dump_size"] = info["total_bytes"]
                    break

    except Exception as e:
        info["error"] = str(e)

    return info


def find_recent_crashes(dump_path: str, max_files: int = 10) -> list[dict]:
    """Find recent crash dump files."""
    crashes = []

    if not os.path.exists(dump_path):
        return crashes

    try:
        # Look for vmcore files and crash directories
        patterns = [
            os.path.join(dump_path, "**/vmcore"),
            os.path.join(dump_path, "**/vmcore.flat"),
            os.path.join(dump_path, "**/vmcore-dmesg.txt"),
        ]

        files = []
        for pattern in patterns:
            files.extend(glob.glob(pattern, recursive=True))

        # Get file info
        for filepath in files:
            if os.path.isfile(filepath):
                try:
                    stat = os.stat(filepath)
                    crashes.append(
                        {
                            "path": filepath,
                            "size_bytes": stat.st_size,
                            "mtime": stat.st_mtime,
                            "mtime_str": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        }
                    )
                except Exception:
                    continue

        # Sort by modification time (newest first)
        crashes.sort(key=lambda x: x["mtime"], reverse=True)

    except Exception:
        pass

    return crashes[:max_files]


def check_kexec_loaded() -> dict[str, Any]:
    """Check if kexec crash kernel is loaded."""
    info = {
        "loaded": False,
        "kexec_available": False,
    }

    # Check if crash kernel is loaded
    kexec_loaded_path = "/sys/kernel/kexec_crash_loaded"
    if os.path.exists(kexec_loaded_path):
        info["kexec_available"] = True
        try:
            with open(kexec_loaded_path, "r") as f:
                info["loaded"] = f.read().strip() == "1"
        except Exception:
            pass

    return info


def check_fadump() -> dict[str, Any]:
    """Check fadump (firmware-assisted dump) status for PowerPC."""
    info = {
        "supported": False,
        "enabled": False,
        "registered": False,
    }

    # Check if fadump is supported (PowerPC only)
    fadump_enabled_path = "/sys/kernel/fadump_enabled"
    fadump_registered_path = "/sys/kernel/fadump_registered"

    if os.path.exists(fadump_enabled_path):
        info["supported"] = True
        try:
            with open(fadump_enabled_path, "r") as f:
                info["enabled"] = f.read().strip() == "1"
        except Exception:
            pass

    if os.path.exists(fadump_registered_path):
        try:
            with open(fadump_registered_path, "r") as f:
                info["registered"] = f.read().strip() == "1"
        except Exception:
            pass

    return info


def format_bytes(size: int) -> str:
    """Format bytes to human readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def analyze_configuration(
    service: dict,
    crashkernel: dict,
    target: dict,
    directory: dict,
    memory: dict,
    kexec: dict,
    fadump: dict,
) -> list[dict]:
    """Analyze configuration and return issues."""
    issues = []

    # Check kdump service
    if not service["installed"]:
        issues.append(
            {
                "severity": "CRITICAL",
                "category": "service",
                "message": "kdump is not installed",
            }
        )
    elif not service["enabled"]:
        issues.append(
            {
                "severity": "WARNING",
                "category": "service",
                "message": "kdump service is not enabled at boot",
            }
        )
    elif not service["active"]:
        issues.append(
            {
                "severity": "CRITICAL",
                "category": "service",
                "message": "kdump service is not running",
            }
        )

    # Check crashkernel reservation
    if not crashkernel["reserved"]:
        issues.append(
            {
                "severity": "CRITICAL",
                "category": "memory",
                "message": "No crashkernel memory reserved (add crashkernel= to kernel cmdline)",
            }
        )
    elif crashkernel["size"] == "auto":
        issues.append(
            {
                "severity": "INFO",
                "category": "memory",
                "message": "Using crashkernel=auto - verify adequate memory is reserved",
            }
        )

    # Check kexec loaded status
    if service["active"] and not kexec["loaded"]:
        issues.append(
            {
                "severity": "WARNING",
                "category": "kexec",
                "message": "Crash kernel not loaded - kdump may not capture crashes",
            }
        )

    # Check dump directory
    if target["type"] == "local":
        if not directory["exists"]:
            issues.append(
                {
                    "severity": "WARNING",
                    "category": "storage",
                    "message": f"Dump directory {directory['path']} does not exist",
                }
            )
        elif not directory["writable"]:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "category": "storage",
                    "message": f"Dump directory {directory['path']} is not writable",
                }
            )

        # Check available space vs estimated dump size
        if directory["exists"] and memory["total_bytes"] > 0:
            if directory["available_bytes"] < memory["estimated_dump_size"]:
                issues.append(
                    {
                        "severity": "WARNING",
                        "category": "storage",
                        "message": f"Available space ({format_bytes(directory['available_bytes'])}) "
                        f"may be insufficient for full dump ({format_bytes(memory['estimated_dump_size'])})",
                    }
                )

        # Check disk usage
        if directory["used_percent"] > 90:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "category": "storage",
                    "message": f"Dump filesystem is {directory['used_percent']:.1f}% full",
                }
            )
        elif directory["used_percent"] > 75:
            issues.append(
                {
                    "severity": "WARNING",
                    "category": "storage",
                    "message": f"Dump filesystem is {directory['used_percent']:.1f}% full",
                }
            )

    # Check remote targets
    if target["type"] in ["nfs", "ssh"]:
        issues.append(
            {
                "severity": "INFO",
                "category": "target",
                "message": f"Using remote dump target ({target['type']}): {target['host']}",
            }
        )

    # Check fadump on PowerPC
    if fadump["supported"] and not fadump["enabled"]:
        issues.append(
            {
                "severity": "INFO",
                "category": "fadump",
                "message": "Fadump is supported but not enabled (consider for faster dumps)",
            }
        )

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = properly configured, 1 = issues detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit kdump (kernel crash dump) configuration"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show additional details"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show warnings and errors"
    )
    parser.add_argument(
        "--dump-path",
        default="/var/crash",
        help="Path to check for crash dumps (default: /var/crash)",
    )
    opts = parser.parse_args(args)

    # Check for Linux
    if not os.path.exists("/proc"):
        output.error("/proc not found - requires Linux")
        return 2

    # Gather information
    service = check_kdump_service(context)
    crashkernel = check_crashkernel_reservation()
    config = check_kdump_config()
    target = check_dump_target(config)

    # Use configured path or command line override
    dump_path = target["path"]
    if opts.dump_path != "/var/crash":
        dump_path = opts.dump_path

    directory = check_dump_directory(dump_path)
    memory = check_memory_for_dump()
    kexec = check_kexec_loaded()
    fadump = check_fadump()
    recent_crashes = find_recent_crashes(dump_path)

    # Analyze configuration
    issues = analyze_configuration(
        service, crashkernel, target, directory, memory, kexec, fadump
    )

    # Build result data
    data = {
        "service": service,
        "crashkernel": crashkernel,
        "config": config,
        "dump_target": target,
        "dump_directory": directory,
        "memory": memory,
        "kexec": kexec,
        "fadump": fadump,
        "recent_crashes": recent_crashes,
        "issues": issues,
    }

    output.emit(data)

    # Output results
    if opts.format == "json":
        print(json.dumps(data, indent=2, default=str))
    else:
        if not opts.warn_only:
            print("Kdump Configuration Audit")
            print("=" * 60)

            # Service status
            status_str = "running" if service["active"] else "stopped"
            enabled_str = "enabled" if service["enabled"] else "disabled"
            print(f"Service: {status_str} ({enabled_str})")

            # Crashkernel
            if crashkernel["reserved"]:
                print(f"Crashkernel: {crashkernel['parameter']}")
            else:
                print("Crashkernel: NOT RESERVED")

            # Kexec
            print(f"Crash kernel loaded: {'Yes' if kexec['loaded'] else 'No'}")

            # Dump target
            print(f"\nDump Target: {target['type']}")
            if target["type"] == "local":
                print(f"  Path: {target['path']}")
            elif target["host"]:
                print(f"  Host: {target['host']}")

            # Directory info
            if directory["exists"]:
                print(f"\nDump Directory: {directory['path']}")
                print(f"  Available: {format_bytes(directory['available_bytes'])}")
                print(f"  Used: {directory['used_percent']:.1f}%")
                print(f"  Writable: {'Yes' if directory['writable'] else 'No'}")

            # Memory estimate
            if memory["total_bytes"] > 0:
                print(f"\nSystem Memory: {format_bytes(memory['total_bytes'])}")
                print(f"Estimated dump size: {format_bytes(memory['estimated_dump_size'])}")

            # Recent crashes
            if recent_crashes:
                print(f"\nRecent Crash Dumps ({len(recent_crashes)} found):")
                for crash in recent_crashes[:5]:
                    name = os.path.basename(crash["path"])
                    size = format_bytes(crash["size_bytes"])
                    print(f"  {name}: {size} ({crash['mtime_str'][:10]})")

            print()

        # Print issues
        if issues:
            for issue in issues:
                if opts.warn_only and issue["severity"] == "INFO":
                    continue
                print(f"[{issue['severity']}] {issue['message']}")
        elif not opts.warn_only:
            print("No kdump configuration issues detected.")

    # Summary
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "ok")
    output.set_summary(f"status={status}, issues={len(issues)}")

    # Determine exit code
    if has_critical or has_warning:
        return 1
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))

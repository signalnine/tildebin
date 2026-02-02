#!/usr/bin/env python3
# boxctl:
#   category: baremetal/boot
#   tags: [boot, initramfs, initrd, kernel, health]
#   requires: []
#   privilege: user
#   related: [kernel_version, boot_issues_analyzer, efi_boot_audit]
#   brief: Monitor initramfs/initrd health for all installed kernels

"""
Monitor initramfs/initrd health for baremetal Linux systems.

Verifies that initial RAM disk images exist for all installed kernels,
checks file integrity, validates size, and ensures boot readiness.
Critical for preventing unbootable systems after kernel updates.

Checks performed:
- Initramfs exists for each installed kernel
- File size is within expected range (not zero, not suspiciously small)
- File permissions and ownership are correct
- Compression format is readable
- Age relative to kernel installation

Exit codes:
    0: All initramfs images are healthy
    1: Issues detected (missing, corrupted, or problematic initramfs)
    2: Error running checks (not root, missing paths)
"""

import argparse
import glob
import gzip
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Minimum expected size for a compressed initramfs (10MB)
MIN_INITRAMFS_SIZE = 10 * 1024 * 1024
# Maximum age difference between kernel and initramfs (days)
MAX_AGE_DIFF_DAYS = 30


def get_file_info(path: str) -> dict[str, Any] | None:
    """Get file metadata."""
    try:
        stat = os.stat(path)
        return {
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime),
            "mode": oct(stat.st_mode)[-4:],
            "uid": stat.st_uid,
            "gid": stat.st_gid,
        }
    except (OSError, IOError):
        return None


def detect_compression(path: str) -> str | None:
    """Detect compression format of initramfs."""
    try:
        with open(path, "rb") as f:
            magic = f.read(6)

            # Gzip magic: 1f 8b
            if magic[:2] == b"\x1f\x8b":
                return "gzip"
            # XZ magic: fd 37 7a 58 5a 00
            if magic[:6] == b"\xfd7zXZ\x00":
                return "xz"
            # LZ4 magic: 04 22 4d 18
            if magic[:4] == b"\x04\x22\x4d\x18":
                return "lz4"
            # LZMA magic
            if magic[:3] == b"\x5d\x00\x00":
                return "lzma"
            # Zstd magic: 28 b5 2f fd
            if magic[:4] == b"\x28\xb5\x2f\xfd":
                return "zstd"
            # CPIO magic (uncompressed): 070701 or 070702
            if magic[:6] in (b"070701", b"070702"):
                return "cpio"
            # Bzip2 magic: 42 5a 68 (BZh)
            if magic[:3] == b"BZh":
                return "bzip2"

            return "unknown"
    except (IOError, OSError):
        return None


def validate_initramfs_contents(path: str, compression: str) -> tuple[bool, str | None]:
    """Basic validation that initramfs can be read."""
    try:
        if compression == "gzip":
            with gzip.open(path, "rb") as f:
                # Try to read first few bytes
                header = f.read(6)
                # CPIO header starts with 070701 or 070702
                if header[:6] in (b"070701", b"070702"):
                    return True, None
                return True, "Unexpected content format"
        # For other formats, just check we can open the file
        with open(path, "rb") as f:
            f.read(1024)
        return True, None
    except Exception as e:
        return False, str(e)


def find_installed_kernels() -> list[dict[str, Any]]:
    """Find all installed kernel versions."""
    kernels = []

    # Check /boot for vmlinuz files
    vmlinuz_patterns = [
        "/boot/vmlinuz-*",
        "/boot/vmlinux-*",  # Some distros use vmlinux
    ]

    for pattern in vmlinuz_patterns:
        for path in glob.glob(pattern):
            # Extract version from filename
            basename = os.path.basename(path)
            match = re.match(r"vmlinuz?-(.+)", basename)
            if match:
                version = match.group(1)
                kernels.append(
                    {
                        "version": version,
                        "vmlinuz_path": path,
                        "vmlinuz_info": get_file_info(path),
                    }
                )

    # Also check /lib/modules for kernel modules
    modules_path = "/lib/modules"
    if os.path.isdir(modules_path):
        for version in os.listdir(modules_path):
            module_path = os.path.join(modules_path, version)
            if os.path.isdir(module_path):
                # Check if we already have this kernel from vmlinuz
                existing = next((k for k in kernels if k["version"] == version), None)
                if existing:
                    existing["modules_path"] = module_path
                else:
                    # Modules exist but no vmlinuz - might be orphaned
                    kernels.append(
                        {
                            "version": version,
                            "vmlinuz_path": None,
                            "modules_path": module_path,
                        }
                    )

    return kernels


def find_initramfs_for_kernel(version: str) -> str | None:
    """Find initramfs file for a given kernel version."""
    patterns = [
        f"/boot/initramfs-{version}.img",  # RHEL/CentOS/Fedora
        f"/boot/initrd.img-{version}",  # Debian/Ubuntu
        f"/boot/initrd-{version}",  # Some distros
        f"/boot/initramfs-{version}",  # Alternative
        f"/boot/initramfs-linux-{version}.img",  # Arch
    ]

    for pattern in patterns:
        if os.path.exists(pattern):
            return pattern

    # Try glob for partial matches
    for base_pattern in ["/boot/initramfs-*", "/boot/initrd.img-*", "/boot/initrd-*"]:
        for path in glob.glob(base_pattern):
            if version in path:
                return path

    return None


def find_orphaned_initramfs(kernels: list[dict]) -> list[dict[str, Any]]:
    """Find initramfs files without corresponding kernels."""
    orphaned = []
    kernel_versions = {k["version"] for k in kernels}

    initramfs_patterns = [
        "/boot/initramfs-*.img",
        "/boot/initrd.img-*",
        "/boot/initrd-*",
    ]

    for pattern in initramfs_patterns:
        for path in glob.glob(pattern):
            basename = os.path.basename(path)
            # Extract version
            match = re.match(r"(?:initramfs-|initrd\.img-|initrd-)(.+?)(?:\.img)?$", basename)
            if match:
                version = match.group(1)
                if version not in kernel_versions:
                    orphaned.append(
                        {
                            "path": path,
                            "version": version,
                            "info": get_file_info(path),
                        }
                    )

    return orphaned


def check_regeneration_tools(context: Context) -> dict[str, dict]:
    """Check availability of initramfs regeneration tools."""
    tools = {}

    tool_checks = [
        ("dracut", ["dracut", "--version"]),
        ("mkinitcpio", ["mkinitcpio", "--version"]),
        ("update-initramfs", ["update-initramfs", "-h"]),
    ]

    for name, cmd in tool_checks:
        tools[name] = {"available": context.check_tool(name)}

    return tools


def get_running_kernel(context: Context) -> str | None:
    """Get the currently running kernel version."""
    try:
        result = context.run(["uname", "-r"])
        return result.stdout.strip()
    except Exception:
        return None


def analyze_initramfs_health(context: Context) -> dict[str, Any]:
    """Main analysis function."""
    results = {
        "timestamp": datetime.now().isoformat(),
        "running_kernel": get_running_kernel(context),
        "kernels": [],
        "orphaned_initramfs": [],
        "regeneration_tools": check_regeneration_tools(context),
        "issues": [],
        "summary": {
            "total_kernels": 0,
            "healthy": 0,
            "missing_initramfs": 0,
            "problematic": 0,
            "orphaned": 0,
        },
    }

    kernels = find_installed_kernels()
    results["summary"]["total_kernels"] = len(kernels)

    for kernel in kernels:
        version = kernel["version"]
        kernel_info = {
            "version": version,
            "vmlinuz_path": kernel.get("vmlinuz_path"),
            "modules_path": kernel.get("modules_path"),
            "initramfs_path": None,
            "status": "unknown",
            "issues": [],
        }

        # Find initramfs
        initramfs_path = find_initramfs_for_kernel(version)
        kernel_info["initramfs_path"] = initramfs_path

        if not initramfs_path:
            kernel_info["status"] = "missing"
            kernel_info["issues"].append("No initramfs found for this kernel")
            results["issues"].append(f"Missing initramfs for kernel {version}")
            results["summary"]["missing_initramfs"] += 1
        else:
            # Check initramfs health
            file_info = get_file_info(initramfs_path)
            kernel_info["initramfs_info"] = file_info

            if not file_info:
                kernel_info["status"] = "error"
                kernel_info["issues"].append("Cannot read initramfs file")
                results["issues"].append(f"Cannot read initramfs for kernel {version}")
                results["summary"]["problematic"] += 1
                results["kernels"].append(kernel_info)
                continue

            # Check size
            if file_info["size"] == 0:
                kernel_info["issues"].append("Initramfs is empty (0 bytes)")
                results["issues"].append(f"Empty initramfs for kernel {version}")
            elif file_info["size"] < MIN_INITRAMFS_SIZE:
                kernel_info["issues"].append(
                    f"Initramfs is suspiciously small ({file_info['size']} bytes)"
                )
                results["issues"].append(
                    f"Small initramfs for kernel {version}: {file_info['size']} bytes"
                )

            # Check compression
            compression = detect_compression(initramfs_path)
            kernel_info["compression"] = compression

            if compression == "unknown":
                kernel_info["issues"].append("Unknown or invalid compression format")
            elif compression is None:
                kernel_info["issues"].append("Cannot read initramfs header")

            # Validate contents if gzip
            if compression == "gzip":
                valid, error = validate_initramfs_contents(initramfs_path, compression)
                if not valid:
                    kernel_info["issues"].append(f"Initramfs validation failed: {error}")
                    results["issues"].append(f"Corrupted initramfs for kernel {version}")

            # Check permissions
            if file_info["mode"] not in ("0644", "0600"):
                kernel_info["issues"].append(
                    f"Unusual permissions: {file_info['mode']} (expected 0644 or 0600)"
                )

            # Check ownership
            if file_info["uid"] != 0:
                kernel_info["issues"].append(f"Not owned by root (uid={file_info['uid']})")

            # Check age relative to vmlinuz
            if kernel.get("vmlinuz_info"):
                vmlinuz_mtime = kernel["vmlinuz_info"]["mtime"]
                initramfs_mtime = file_info["mtime"]
                age_diff = (vmlinuz_mtime - initramfs_mtime).days

                if abs(age_diff) > MAX_AGE_DIFF_DAYS:
                    kernel_info["issues"].append(
                        f"Initramfs significantly older/newer than kernel ({age_diff} days)"
                    )

            # Determine status
            if kernel_info["issues"]:
                kernel_info["status"] = "warning"
                results["summary"]["problematic"] += 1
            else:
                kernel_info["status"] = "healthy"
                results["summary"]["healthy"] += 1

        results["kernels"].append(kernel_info)

    # Find orphaned initramfs
    orphaned = find_orphaned_initramfs(kernels)
    results["orphaned_initramfs"] = orphaned
    results["summary"]["orphaned"] = len(orphaned)

    for orphan in orphaned:
        results["issues"].append(f"Orphaned initramfs: {orphan['path']}")

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor initramfs health for baremetal Linux systems"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show output if issues are detected",
    )
    opts = parser.parse_args(args)

    # Check if /boot exists
    if not os.path.isdir("/boot"):
        output.error("/boot directory not found")
        return 2

    # Run analysis
    try:
        results = analyze_initramfs_health(context)
    except Exception as e:
        output.error(f"Error during analysis: {e}")
        return 2

    output.emit(results)

    # Output results
    if opts.format == "json":
        # Convert datetime objects to strings for JSON
        json_results = results.copy()
        for kernel in json_results["kernels"]:
            if kernel.get("initramfs_info") and kernel["initramfs_info"].get("mtime"):
                kernel["initramfs_info"]["mtime"] = kernel["initramfs_info"][
                    "mtime"
                ].isoformat()
        for orphan in json_results["orphaned_initramfs"]:
            if orphan.get("info") and orphan["info"].get("mtime"):
                orphan["info"]["mtime"] = orphan["info"]["mtime"].isoformat()
        print(json.dumps(json_results, indent=2))
    else:
        if opts.warn_only and not results["issues"]:
            pass  # Silent when no issues in warn-only mode
        else:
            print("Initramfs Health Monitor")
            print("=" * 60)
            print(f"Running kernel: {results['running_kernel']}")
            print()

            # Summary
            s = results["summary"]
            print(f"Summary: {s['total_kernels']} kernel(s) found")
            print(f"  Healthy:           {s['healthy']}")
            print(f"  Missing initramfs: {s['missing_initramfs']}")
            print(f"  Problematic:       {s['problematic']}")
            print(f"  Orphaned:          {s['orphaned']}")
            print()

            # Kernel details
            print("Kernel Status:")
            print("-" * 60)

            for kernel in results["kernels"]:
                status_icon = {
                    "healthy": "[OK]",
                    "warning": "[WARN]",
                    "missing": "[MISS]",
                    "error": "[ERR]",
                }.get(kernel["status"], "[?]")

                print(f"{status_icon} {kernel['version']}")

                if opts.verbose or kernel["status"] != "healthy":
                    if kernel["initramfs_path"]:
                        print(f"      Initramfs: {kernel['initramfs_path']}")
                        if kernel.get("initramfs_info"):
                            size_mb = kernel["initramfs_info"]["size"] / (1024 * 1024)
                            print(f"      Size: {size_mb:.1f} MB")
                        if kernel.get("compression"):
                            print(f"      Compression: {kernel['compression']}")
                    else:
                        print("      Initramfs: NOT FOUND")

                    for issue in kernel["issues"]:
                        print(f"      ! {issue}")

                if opts.verbose or kernel["status"] != "healthy":
                    print()

            # Orphaned initramfs
            if results["orphaned_initramfs"]:
                print()
                print("Orphaned Initramfs (no matching kernel):")
                print("-" * 60)
                for orphan in results["orphaned_initramfs"]:
                    size_mb = orphan["info"]["size"] / (1024 * 1024) if orphan["info"] else 0
                    print(f"  {orphan['path']} ({size_mb:.1f} MB)")

            # Regeneration tools
            if opts.verbose:
                print()
                print("Regeneration Tools:")
                print("-" * 60)
                for tool, info in results["regeneration_tools"].items():
                    status = "available" if info["available"] else "not found"
                    print(f"  {tool}: {status}")

            # Issues summary
            if results["issues"]:
                print()
                print("Issues Summary:")
                print("-" * 60)
                for issue in results["issues"]:
                    print(f"  ! {issue}")

    summary = results["summary"]
    output.set_summary(
        f"{summary['healthy']} healthy, {summary['missing_initramfs']} missing, "
        f"{summary['problematic']} problematic"
    )

    # Determine exit code
    if summary["missing_initramfs"] > 0 or summary["problematic"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))

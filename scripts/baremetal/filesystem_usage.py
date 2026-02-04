#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [disk, usage, filesystem, du]
#   requires: [du]
#   privilege: user
#   related: [disk_space_forecaster, inode_usage]
#   brief: Track filesystem usage and identify large directories

"""
Track filesystem usage and identify large directories.

Scans a filesystem path and reports disk usage by directory,
helping administrators identify which directories consume the most space.

Returns exit code 0 on success, 1 on scan errors, 2 on usage errors.
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_size_to_bytes(size_str: str) -> int:
    """Parse human-readable size string to bytes."""
    size_str = size_str.strip()

    units = {
        'K': 1024,
        'M': 1024 ** 2,
        'G': 1024 ** 3,
        'T': 1024 ** 4,
    }

    for unit, multiplier in units.items():
        if size_str.endswith(unit):
            try:
                value = float(size_str[:-1])
                return int(value * multiplier)
            except ValueError:
                pass

    try:
        return int(float(size_str))
    except ValueError:
        return 0


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable size."""
    for unit, divisor in [('T', 1024**4), ('G', 1024**3),
                          ('M', 1024**2), ('K', 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = success, 1 = error, 2 = usage error
    """
    parser = argparse.ArgumentParser(
        description="Track filesystem usage and identify large directories"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="/",
        help="Root filesystem path to scan (default: /)"
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=3,
        help="Maximum directory depth to traverse (default: 3)"
    )
    parser.add_argument(
        "-n", "--top",
        type=int,
        default=10,
        help="Number of top entries to display (default: 10)"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )
    parser.add_argument(
        "-x", "--one-file-system",
        action="store_true",
        default=True,
        help="Stay on one filesystem (default: true)"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        dest="excludes",
        help="Exclude pattern (can be repeated)"
    )

    opts = parser.parse_args(args)

    # Validate path
    if not os.path.exists(opts.path):
        output.error(f"Path does not exist: {opts.path}")

        output.render(opts.format, "Track filesystem usage and identify large directories")
        return 2

    if not os.path.isdir(opts.path):
        output.error(f"Path is not a directory: {opts.path}")

        output.render(opts.format, "Track filesystem usage and identify large directories")
        return 2

    # Validate arguments
    if opts.depth < 0:
        output.error("--depth must be >= 0")

        output.render(opts.format, "Track filesystem usage and identify large directories")
        return 2

    if opts.top < 1:
        output.error("--top must be >= 1")

        output.render(opts.format, "Track filesystem usage and identify large directories")
        return 2

    # Check for du command
    if not context.check_tool("du"):
        output.error("du command not found. Please install coreutils.")

        output.render(opts.format, "Track filesystem usage and identify large directories")
        return 2

    # Run du command
    cmd = ['du', '-a', f'--max-depth={opts.depth}', '-h']

    # Stay on one filesystem to avoid slow network/pseudo mounts
    if opts.one_file_system:
        cmd.append('-x')

    # Add exclusions
    default_excludes = ['/proc', '/sys', '/dev', '/run', '/snap', '/var/snap']
    excludes = (opts.excludes or []) + default_excludes
    for exc in excludes:
        cmd.extend(['--exclude', exc])

    cmd.append(opts.path)

    try:
        result = context.run(cmd, check=False, timeout=300)

        if result.returncode != 0 and not result.stdout:
            output.error(f"du command failed: {result.stderr}")
            return 1

        entries = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            parts = line.split('\t', 1)
            if len(parts) == 2:
                size_str = parts[0]
                directory = parts[1]
                size_bytes = parse_size_to_bytes(size_str)
                entries.append({
                    'directory': directory,
                    'size_bytes': size_bytes,
                    'size_human': size_str.strip()
                })

        # Sort by size descending
        entries.sort(key=lambda x: x['size_bytes'], reverse=True)

        # Limit to top N
        entries = entries[:opts.top]

        # Calculate percentages
        total_bytes = entries[0]['size_bytes'] if entries else 0
        for entry in entries:
            if total_bytes > 0:
                entry['percent'] = round(entry['size_bytes'] / total_bytes * 100, 1)
            else:
                entry['percent'] = 0

        output.emit({
            "path": opts.path,
            "total_size": format_bytes(total_bytes) if entries else "0B",
            "entries": entries
        })

        output.set_summary(f"Scanned {len(entries)} directories under {opts.path}")

        output.render(opts.format, "Track filesystem usage and identify large directories")
        return 0

    except Exception as e:
        output.error(f"Failed to scan filesystem: {e}")

        output.render(opts.format, "Track filesystem usage and identify large directories")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))

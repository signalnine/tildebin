#!/usr/bin/env python3
"""
Track filesystem usage and identify large directories.

Scans a filesystem path and reports disk usage by directory,
helping administrators identify which directories consume the most space.

Exit codes:
  0 - Successful scan, directory information displayed
  1 - Error during scanning (permission denied, path not found, etc.)
  2 - Usage error (invalid arguments, missing required parameters)
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def get_du_output(path, max_depth=3, human_readable=True):
    """
    Get directory usage using 'du' command.

    Args:
        path: Root path to scan
        max_depth: Maximum depth to traverse (default 3)
        human_readable: Use human-readable format (default True)

    Returns:
        List of tuples: (size_bytes, size_str, directory)

    Raises:
        RuntimeError: If du command fails
    """
    cmd = ['du', '-a', f'--max-depth={max_depth}']

    if human_readable:
        cmd.append('-h')
    else:
        cmd.append('-b')

    cmd.append(path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise RuntimeError(f"du command failed: {error_msg}")

        entries = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            parts = line.split('\t', 1)
            if len(parts) == 2:
                size_str = parts[0]
                directory = parts[1]

                # Parse size to bytes
                size_bytes = parse_size_to_bytes(size_str)
                entries.append((size_bytes, size_str, directory))

        return sorted(entries, reverse=True)

    except subprocess.TimeoutExpired:
        raise RuntimeError(f"du scan timeout after 300 seconds on {path}")
    except FileNotFoundError:
        raise RuntimeError("du command not found. Please install coreutils.")


def parse_size_to_bytes(size_str):
    """
    Parse human-readable size string to bytes.

    Examples: '1.2G', '512M', '10K', '1024'

    Args:
        size_str: Size string with optional K/M/G/T suffix

    Returns:
        Size in bytes as integer
    """
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

    # No suffix, assume bytes
    try:
        return int(float(size_str))
    except ValueError:
        return 0


def format_bytes(bytes_val):
    """
    Format bytes to human-readable size.

    Args:
        bytes_val: Size in bytes

    Returns:
        Formatted string (e.g., '1.2G')
    """
    for unit, divisor in [('T', 1024**4), ('G', 1024**3),
                          ('M', 1024**2), ('K', 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def output_plain(entries, top_n, path):
    """
    Output results in plain format.

    Args:
        entries: List of (size_bytes, size_str, directory) tuples
        top_n: Number of top entries to show
        path: Root path being scanned
    """
    print(f"Directory usage for: {path}\n")
    print("Size       Directory")
    print("-" * 70)

    for size_bytes, size_str, directory in entries[:top_n]:
        print(f"{size_str:>10} {directory}")


def output_table(entries, top_n, path):
    """
    Output results in table format.

    Args:
        entries: List of (size_bytes, size_str, directory) tuples
        top_n: Number of top entries to show
        path: Root path being scanned
    """
    print(f"Directory usage for: {path}\n")
    print(f"{'Size':>12} | {'Percent':>8} | Directory")
    print("-" * 70)

    if not entries:
        print("No entries found")
        return

    total_size = entries[0][0]  # Total is usually first entry

    for size_bytes, size_str, directory in entries[:top_n]:
        if total_size > 0:
            percent = (size_bytes / total_size) * 100
        else:
            percent = 0

        print(f"{size_str:>12} | {percent:>7.1f}% | {directory}")


def output_json(entries, top_n, path):
    """
    Output results in JSON format.

    Args:
        entries: List of (size_bytes, size_str, directory) tuples
        top_n: Number of top entries to show
        path: Root path being scanned
    """
    output = {
        "path": path,
        "entries": [
            {
                "bytes": size_bytes,
                "human_readable": size_str,
                "directory": directory
            }
            for size_bytes, size_str, directory in entries[:top_n]
        ]
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Track filesystem usage and identify large directories"
    )
    parser.add_argument(
        "path",
        help="Root filesystem path to scan"
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
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all output except results"
    )

    args = parser.parse_args()

    # Validate path
    if not os.path.exists(args.path):
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.path):
        print(f"Error: Path is not a directory: {args.path}", file=sys.stderr)
        sys.exit(1)

    # Validate arguments
    if args.depth < 0:
        print("Error: --depth must be >= 0", file=sys.stderr)
        sys.exit(2)

    if args.top < 1:
        print("Error: --top must be >= 1", file=sys.stderr)
        sys.exit(2)

    try:
        if not args.quiet:
            print(f"Scanning {args.path}...", file=sys.stderr)

        entries = get_du_output(args.path, max_depth=args.depth, human_readable=True)

        if not entries:
            print(f"No directories found in {args.path}", file=sys.stderr)
            sys.exit(0)

        # Output results
        if args.format == "plain":
            output_plain(entries, args.top, args.path)
        elif args.format == "table":
            output_table(entries, args.top, args.path)
        elif args.format == "json":
            output_json(entries, args.top, args.path)

        sys.exit(0)

    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

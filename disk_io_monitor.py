#!/usr/bin/env python3
"""
Monitor disk I/O performance and identify bottlenecks.

Analyzes disk I/O statistics to detect high latency, saturated I/O queues,
and slow-performing devices that may impact application performance.

Exit codes:
    0 - All disks performing normally
    1 - Performance warnings or issues detected
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import subprocess


def check_iostat_available():
    """Check if iostat command is available"""
    try:
        result = subprocess.run(
            ['which', 'iostat'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_iostat():
    """Execute iostat and return parsed results"""
    try:
        # Run iostat with extended stats (-x) for 2 iterations, 1 second apart
        # First iteration is since boot, second is current snapshot
        result = subprocess.run(
            ['iostat', '-x', '-d', '1', '2'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running iostat: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def parse_iostat_output(output):
    """Parse iostat output and return device statistics"""
    devices = []
    lines = output.strip().split('\n')

    # Find the second statistics block (current snapshot, not since boot)
    in_second_block = False
    header_found = False

    for line in lines:
        # Look for the Device header line
        if line.startswith('Device'):
            if header_found:
                in_second_block = True
            else:
                header_found = True
            continue

        # Skip until we're in the second block
        if not in_second_block or not line.strip():
            continue

        # Parse device statistics
        parts = line.split()
        if len(parts) >= 14:
            device = parts[0]

            # Skip loop and ram devices by default
            if device.startswith('loop') or device.startswith('ram'):
                continue

            try:
                stats = {
                    'device': device,
                    'rrqm_per_s': float(parts[1]),  # Read requests merged per second
                    'wrqm_per_s': float(parts[2]),  # Write requests merged per second
                    'r_per_s': float(parts[3]),     # Reads per second
                    'w_per_s': float(parts[4]),     # Writes per second
                    'rkb_per_s': float(parts[5]),   # KB read per second
                    'wkb_per_s': float(parts[6]),   # KB written per second
                    'avgrq_sz': float(parts[7]),    # Average request size (sectors)
                    'avgqu_sz': float(parts[8]),    # Average queue length
                    'await': float(parts[9]),       # Average wait time (ms)
                    'r_await': float(parts[10]),    # Average read wait time (ms)
                    'w_await': float(parts[11]),    # Average write wait time (ms)
                    'svctm': float(parts[12]),      # Service time (deprecated but useful)
                    'util': float(parts[13])        # Utilization percentage
                }
                devices.append(stats)
            except (ValueError, IndexError):
                # Skip malformed lines
                continue

    return devices


def analyze_device(stats, args):
    """Analyze device stats and identify issues"""
    issues = []
    status = 'OK'

    device = stats['device']
    util = stats['util']
    await_time = stats['await']
    avgqu_sz = stats['avgqu_sz']

    # Check utilization
    if util > 90:
        issues.append(f"CRITICAL: Utilization at {util:.1f}% (device saturated)")
        status = 'CRITICAL'
    elif util > 75:
        issues.append(f"WARNING: Utilization at {util:.1f}% (nearing saturation)")
        if status == 'OK':
            status = 'WARNING'

    # Check average wait time (latency)
    if await_time > 100:
        issues.append(f"CRITICAL: Average wait time {await_time:.1f}ms (very high latency)")
        status = 'CRITICAL'
    elif await_time > 50:
        issues.append(f"WARNING: Average wait time {await_time:.1f}ms (high latency)")
        if status == 'OK':
            status = 'WARNING'

    # Check queue depth
    if avgqu_sz > 10:
        issues.append(f"WARNING: Average queue length {avgqu_sz:.1f} (I/O backlog)")
        if status == 'OK':
            status = 'WARNING'

    # Check for read vs write imbalance (one much slower than other)
    r_await = stats['r_await']
    w_await = stats['w_await']
    if r_await > 0 and w_await > 0:
        if r_await > w_await * 5:
            issues.append(f"INFO: Read latency ({r_await:.1f}ms) much higher than write ({w_await:.1f}ms)")
        elif w_await > r_await * 5:
            issues.append(f"INFO: Write latency ({w_await:.1f}ms) much higher than read ({r_await:.1f}ms)")

    return status, issues


def output_plain(devices, args):
    """Plain text output"""
    has_issues = False

    for stats in devices:
        status, issues = analyze_device(stats, args)

        # Skip OK devices if warn-only mode
        if args.warn_only and status == 'OK':
            continue

        if status != 'OK':
            has_issues = True

        device = stats['device']
        util = stats['util']
        await_time = stats['await']
        r_per_s = stats['r_per_s']
        w_per_s = stats['w_per_s']
        rkb_per_s = stats['rkb_per_s']
        wkb_per_s = stats['wkb_per_s']

        print(f"{device} {status} util={util:.1f}% await={await_time:.1f}ms "
              f"r/s={r_per_s:.1f} w/s={w_per_s:.1f} "
              f"rkB/s={rkb_per_s:.1f} wkB/s={wkb_per_s:.1f}")

        if args.verbose or status != 'OK':
            for issue in issues:
                print(f"  {issue}")

    return has_issues


def output_json(devices, args):
    """JSON output"""
    results = []
    has_issues = False

    for stats in devices:
        status, issues = analyze_device(stats, args)

        # Skip OK devices if warn-only mode
        if args.warn_only and status == 'OK':
            continue

        if status != 'OK':
            has_issues = True

        result = {
            'device': stats['device'],
            'status': status,
            'utilization_pct': stats['util'],
            'await_ms': stats['await'],
            'r_await_ms': stats['r_await'],
            'w_await_ms': stats['w_await'],
            'avg_queue_length': stats['avgqu_sz'],
            'reads_per_sec': stats['r_per_s'],
            'writes_per_sec': stats['w_per_s'],
            'read_kb_per_sec': stats['rkb_per_s'],
            'write_kb_per_sec': stats['wkb_per_s'],
            'issues': issues
        }
        results.append(result)

    print(json.dumps(results, indent=2))
    return has_issues


def output_table(devices, args):
    """Tabular output"""
    has_issues = False

    # Print header
    print(f"{'Device':<12} {'Status':<10} {'Util%':>7} {'Await':>8} "
          f"{'R/s':>8} {'W/s':>8} {'RkB/s':>10} {'WkB/s':>10}")
    print("-" * 80)

    for stats in devices:
        status, issues = analyze_device(stats, args)

        # Skip OK devices if warn-only mode
        if args.warn_only and status == 'OK':
            continue

        if status != 'OK':
            has_issues = True

        device = stats['device']
        util = stats['util']
        await_time = stats['await']
        r_per_s = stats['r_per_s']
        w_per_s = stats['w_per_s']
        rkb_per_s = stats['rkb_per_s']
        wkb_per_s = stats['wkb_per_s']

        print(f"{device:<12} {status:<10} {util:>6.1f}% {await_time:>7.1f}ms "
              f"{r_per_s:>8.1f} {w_per_s:>8.1f} {rkb_per_s:>10.1f} {wkb_per_s:>10.1f}")

        if args.verbose and issues:
            for issue in issues:
                print(f"  {issue}")

    return has_issues


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor disk I/O performance and identify bottlenecks",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-f", "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with warnings or issues"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information and all issues"
    )

    args = parser.parse_args()

    # Check for iostat
    if not check_iostat_available():
        print("Error: 'iostat' command not found", file=sys.stderr)
        print("Install with: sudo apt-get install sysstat", file=sys.stderr)
        sys.exit(2)

    # Get iostat output
    output = run_iostat()

    # Parse device statistics
    devices = parse_iostat_output(output)

    if not devices:
        print("No disk devices found", file=sys.stderr)
        sys.exit(1)

    # Output results
    if args.format == "json":
        has_issues = output_json(devices, args)
    elif args.format == "table":
        has_issues = output_table(devices, args)
    else:  # plain
        has_issues = output_plain(devices, args)

    # Exit based on findings
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()

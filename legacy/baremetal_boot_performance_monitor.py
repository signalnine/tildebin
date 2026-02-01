#!/usr/bin/env python3
"""
Monitor system boot performance and systemd initialization times.

This script analyzes systemd boot performance using 'systemd-analyze' to identify
slow-booting systems and problematic services that delay system startup. Useful
for large-scale baremetal environments where boot time impacts incident recovery.

Key metrics:
- Total boot time (kernel + userspace)
- Kernel initialization time
- Userspace (systemd) initialization time
- Firmware/bootloader time (if available)
- Top slow-starting services

Exit codes:
    0 - Boot performance is normal
    1 - Boot time exceeds warning thresholds
    2 - systemd-analyze not available or usage error
"""

import argparse
import sys
import subprocess
import json
import re

# Thresholds (in seconds)
DEFAULT_BOOT_WARN_THRESHOLD = 120  # 2 minutes total boot time
DEFAULT_USERSPACE_WARN_THRESHOLD = 60  # 1 minute userspace time
DEFAULT_SERVICE_WARN_THRESHOLD = 10  # 10 seconds for individual service


def check_systemd_analyze_available():
    """Check if systemd-analyze is available."""
    try:
        result = subprocess.run(
            ['which', 'systemd-analyze'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_command(cmd):
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def parse_boot_time(output):
    """Parse systemd-analyze output for boot time statistics."""
    # Example output:
    # Startup finished in 4.234s (kernel) + 12.456s (userspace) = 16.690s
    # or with firmware:
    # Startup finished in 2.1s (firmware) + 3.2s (loader) + 4.234s (kernel) + 12.456s (userspace) = 21.934s

    pattern = r'Startup finished in (.+)'
    match = re.search(pattern, output)

    if not match:
        return None

    time_str = match.group(1)

    result = {
        'firmware': 0,
        'loader': 0,
        'kernel': 0,
        'userspace': 0,
        'total': 0
    }

    # Parse individual components
    firmware_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(firmware\)', time_str)
    loader_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(loader\)', time_str)
    kernel_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(kernel\)', time_str)
    userspace_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(userspace\)', time_str)
    total_match = re.search(r'= (\d+\.?\d*)(s|ms|min)\s*$', time_str)

    def convert_to_seconds(value, unit):
        """Convert time value to seconds."""
        val = float(value)
        if unit == 'ms':
            return val / 1000
        elif unit == 'min':
            return val * 60
        else:  # 's'
            return val

    if firmware_match:
        result['firmware'] = convert_to_seconds(firmware_match.group(1), firmware_match.group(2))
    if loader_match:
        result['loader'] = convert_to_seconds(loader_match.group(1), loader_match.group(2))
    if kernel_match:
        result['kernel'] = convert_to_seconds(kernel_match.group(1), kernel_match.group(2))
    if userspace_match:
        result['userspace'] = convert_to_seconds(userspace_match.group(1), userspace_match.group(2))
    if total_match:
        result['total'] = convert_to_seconds(total_match.group(1), total_match.group(2))

    return result


def parse_blame_output(output, top_n=10):
    """Parse systemd-analyze blame output for slow services."""
    # Example output:
    #  12.456s service-name.service
    #   5.123s another-service.service

    services = []
    lines = output.strip().split('\n')

    for line in lines[:top_n]:
        line = line.strip()
        if not line:
            continue

        # Parse time and service name
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue

        time_str = parts[0]
        service_name = parts[1]

        # Convert time to seconds
        time_match = re.match(r'(\d+\.?\d*)(s|ms|min)', time_str)
        if not time_match:
            continue

        value = float(time_match.group(1))
        unit = time_match.group(2)

        if unit == 'ms':
            seconds = value / 1000
        elif unit == 'min':
            seconds = value * 60
        else:
            seconds = value

        services.append({
            'name': service_name,
            'time': seconds,
            'time_str': time_str
        })

    return services


def get_boot_statistics():
    """Get boot performance statistics."""
    # Get overall boot time
    returncode, stdout, stderr = run_command(['systemd-analyze'])

    if returncode != 0:
        return None, f"systemd-analyze failed: {stderr}"

    boot_times = parse_boot_time(stdout)

    if not boot_times:
        return None, "Failed to parse boot time output"

    # Get slow services
    returncode, stdout, stderr = run_command(['systemd-analyze', 'blame'])

    if returncode != 0:
        slow_services = []
    else:
        slow_services = parse_blame_output(stdout, top_n=10)

    return {
        'boot_times': boot_times,
        'slow_services': slow_services
    }, None


def check_thresholds(boot_stats, boot_warn, userspace_warn, service_warn):
    """Check boot statistics against thresholds."""
    issues = []

    boot_times = boot_stats['boot_times']

    # Check total boot time
    if boot_times['total'] > boot_warn:
        issues.append({
            'severity': 'WARNING',
            'component': 'total_boot_time',
            'message': f"Total boot time {boot_times['total']:.1f}s exceeds threshold {boot_warn}s"
        })

    # Check userspace time
    if boot_times['userspace'] > userspace_warn:
        issues.append({
            'severity': 'WARNING',
            'component': 'userspace_time',
            'message': f"Userspace init time {boot_times['userspace']:.1f}s exceeds threshold {userspace_warn}s"
        })

    # Check slow services
    for service in boot_stats['slow_services']:
        if service['time'] > service_warn:
            issues.append({
                'severity': 'INFO',
                'component': 'slow_service',
                'message': f"Service {service['name']} took {service['time']:.1f}s to start (threshold: {service_warn}s)"
            })

    return issues


def output_plain(boot_stats, issues, verbose=False):
    """Output results in plain text format."""
    boot_times = boot_stats['boot_times']

    print("Boot Performance Summary:")
    print(f"  Total Boot Time: {boot_times['total']:.2f}s")

    if boot_times['firmware'] > 0:
        print(f"  Firmware: {boot_times['firmware']:.2f}s")
    if boot_times['loader'] > 0:
        print(f"  Bootloader: {boot_times['loader']:.2f}s")

    print(f"  Kernel: {boot_times['kernel']:.2f}s")
    print(f"  Userspace: {boot_times['userspace']:.2f}s")

    if issues:
        print("\nIssues Detected:")
        for issue in issues:
            print(f"  [{issue['severity']}] {issue['message']}")

    if verbose and boot_stats['slow_services']:
        print("\nTop Slow Services:")
        for service in boot_stats['slow_services'][:10]:
            print(f"  {service['time_str']:>10s}  {service['name']}")


def output_json(boot_stats, issues):
    """Output results in JSON format."""
    output = {
        'boot_times': boot_stats['boot_times'],
        'slow_services': boot_stats['slow_services'],
        'issues': issues
    }
    print(json.dumps(output, indent=2))


def output_table(boot_stats, issues, verbose=False):
    """Output results in table format."""
    boot_times = boot_stats['boot_times']

    print("=" * 60)
    print("Boot Performance Summary")
    print("=" * 60)
    print(f"{'Component':<20} {'Time (seconds)':<15} {'Status':<20}")
    print("-" * 60)
    print(f"{'Firmware':<20} {boot_times['firmware']:>14.2f} {'N/A':<20}")
    print(f"{'Bootloader':<20} {boot_times['loader']:>14.2f} {'N/A':<20}")
    print(f"{'Kernel':<20} {boot_times['kernel']:>14.2f} {'N/A':<20}")
    print(f"{'Userspace':<20} {boot_times['userspace']:>14.2f} {'N/A':<20}")
    print("-" * 60)
    print(f"{'TOTAL':<20} {boot_times['total']:>14.2f} {'N/A':<20}")
    print("=" * 60)

    if issues:
        print("\nIssues Detected:")
        print("-" * 60)
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")

    if verbose and boot_stats['slow_services']:
        print("\nTop 10 Slow Services:")
        print("-" * 60)
        print(f"{'Time':<15} {'Service Name':<45}")
        print("-" * 60)
        for service in boot_stats['slow_services'][:10]:
            print(f"{service['time_str']:<15} {service['name']:<45}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor system boot performance and identify slow-starting services",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including top slow services"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    parser.add_argument(
        "--boot-threshold",
        type=float,
        default=DEFAULT_BOOT_WARN_THRESHOLD,
        help=f"Warning threshold for total boot time in seconds (default: {DEFAULT_BOOT_WARN_THRESHOLD})"
    )

    parser.add_argument(
        "--userspace-threshold",
        type=float,
        default=DEFAULT_USERSPACE_WARN_THRESHOLD,
        help=f"Warning threshold for userspace init time in seconds (default: {DEFAULT_USERSPACE_WARN_THRESHOLD})"
    )

    parser.add_argument(
        "--service-threshold",
        type=float,
        default=DEFAULT_SERVICE_WARN_THRESHOLD,
        help=f"Warning threshold for individual service start time in seconds (default: {DEFAULT_SERVICE_WARN_THRESHOLD})"
    )

    args = parser.parse_args()

    # Check for systemd-analyze
    if not check_systemd_analyze_available():
        print("Error: systemd-analyze not found in PATH", file=sys.stderr)
        print("This tool requires systemd-based systems", file=sys.stderr)
        sys.exit(2)

    # Get boot statistics
    boot_stats, error = get_boot_statistics()

    if error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    # Check thresholds
    issues = check_thresholds(
        boot_stats,
        args.boot_threshold,
        args.userspace_threshold,
        args.service_threshold
    )

    # Output results
    if args.warn_only and not issues:
        sys.exit(0)

    if args.format == "json":
        output_json(boot_stats, issues)
    elif args.format == "table":
        output_table(boot_stats, issues, args.verbose)
    else:  # plain
        output_plain(boot_stats, issues, args.verbose)

    # Exit based on findings
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Monitor system entropy pool levels for cryptographic operations.

This script monitors the available entropy in the kernel's random number
generator pool. Low entropy can cause blocking in applications that use
/dev/random and performance degradation for TLS/SSL operations. Critical for:

- High-traffic TLS/SSL servers that consume entropy rapidly
- Virtualized environments where entropy sources are limited
- Headless servers without keyboard/mouse input
- Systems generating many cryptographic keys or certificates
- Applications using /dev/random (GPG, key generation, etc.)

The script reads from /proc/sys/kernel/random/ to check:
- entropy_avail: Current entropy pool size (bits)
- poolsize: Maximum entropy pool capacity
- read/write wakeup thresholds: When processes block/wake

Low entropy causes:
- /dev/random reads to block (hang)
- SSL/TLS handshake delays
- Key generation delays
- Performance issues in crypto-heavy applications

Remediation:
- Install rng-tools or haveged for additional entropy sources
- Use hardware RNG if available (rdrand on modern CPUs)
- Consider virtio-rng for virtual machines

Exit codes:
    0 - Entropy levels are healthy
    1 - Low entropy detected (warning or critical)
    2 - Usage error or /proc filesystem not available
"""

import argparse
import sys
import json
import os


def read_entropy_value(filename, required=True, default=None):
    """Read a single value from /proc/sys/kernel/random/.

    Args:
        filename: Name of the file to read
        required: If True, exit on missing file; if False, return default
        default: Default value to return if file missing and not required

    Returns:
        int: Value read from the file, or default if not required and missing

    Raises:
        SystemExit: If required file cannot be read
    """
    path = f'/proc/sys/kernel/random/{filename}'
    try:
        with open(path, 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        if required:
            print(f"Error: {path} not found (non-Linux system?)", file=sys.stderr)
            sys.exit(2)
        return default
    except ValueError as e:
        print(f"Error: Invalid value in {path}: {e}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"Error: Permission denied reading {path}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        sys.exit(2)


def check_rng_available():
    """Check if hardware RNG is available.

    Returns:
        dict: Information about hardware RNG availability
    """
    rng_info = {
        'hw_rng_available': False,
        'hw_rng_name': None,
        'rngd_running': False,
        'haveged_running': False
    }

    # Check for hardware RNG device
    if os.path.exists('/dev/hwrng'):
        rng_info['hw_rng_available'] = True
        try:
            with open('/sys/class/misc/hw_random/rng_current', 'r') as f:
                rng_info['hw_rng_name'] = f.read().strip()
        except (FileNotFoundError, PermissionError):
            pass

    # Check for rngd or haveged processes
    try:
        for pid_dir in os.listdir('/proc'):
            if pid_dir.isdigit():
                try:
                    with open(f'/proc/{pid_dir}/comm', 'r') as f:
                        comm = f.read().strip()
                        if comm == 'rngd':
                            rng_info['rngd_running'] = True
                        elif comm == 'haveged':
                            rng_info['haveged_running'] = True
                except (FileNotFoundError, PermissionError):
                    continue
    except Exception:
        pass

    return rng_info


def get_entropy_stats():
    """Gather all entropy statistics.

    Returns:
        dict: Entropy statistics
    """
    # entropy_avail and poolsize are required
    # read/write_wakeup_threshold may not exist on newer kernels (5.6+)
    stats = {
        'entropy_avail': read_entropy_value('entropy_avail'),
        'poolsize': read_entropy_value('poolsize'),
        'read_wakeup_threshold': read_entropy_value('read_wakeup_threshold',
                                                     required=False, default=64),
        'write_wakeup_threshold': read_entropy_value('write_wakeup_threshold',
                                                      required=False, default=896)
    }

    # Calculate percentage
    stats['entropy_percent'] = (
        (stats['entropy_avail'] / stats['poolsize'] * 100)
        if stats['poolsize'] > 0 else 0
    )

    return stats


def analyze_entropy(stats, warn_threshold, crit_threshold, rng_info):
    """Analyze entropy levels and return issues.

    Args:
        stats: Entropy statistics dict
        warn_threshold: Warning threshold (bits)
        crit_threshold: Critical threshold (bits)
        rng_info: Hardware RNG information

    Returns:
        list: List of issue dictionaries
    """
    issues = []
    entropy = stats['entropy_avail']

    # Check entropy thresholds
    if entropy <= crit_threshold:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'entropy_avail',
            'value': entropy,
            'threshold': crit_threshold,
            'message': f'Entropy critically low: {entropy} bits '
                      f'(threshold: {crit_threshold}) - '
                      f'/dev/random may block, crypto operations affected'
        })
    elif entropy <= warn_threshold:
        issues.append({
            'severity': 'WARNING',
            'metric': 'entropy_avail',
            'value': entropy,
            'threshold': warn_threshold,
            'message': f'Entropy low: {entropy} bits '
                      f'(threshold: {warn_threshold}) - '
                      f'consider installing rng-tools or haveged'
        })

    # Check if entropy is below read wakeup threshold
    if entropy < stats['read_wakeup_threshold']:
        issues.append({
            'severity': 'WARNING',
            'metric': 'read_wakeup',
            'value': entropy,
            'threshold': stats['read_wakeup_threshold'],
            'message': f'Entropy below read wakeup threshold: {entropy} < '
                      f'{stats["read_wakeup_threshold"]} bits - '
                      f'processes reading /dev/random will block'
        })

    # Suggest remediation if no entropy daemon running and entropy is low
    if entropy <= warn_threshold:
        if not rng_info['rngd_running'] and not rng_info['haveged_running']:
            if rng_info['hw_rng_available']:
                issues.append({
                    'severity': 'INFO',
                    'metric': 'rng_daemon',
                    'value': None,
                    'message': f'Hardware RNG available ({rng_info["hw_rng_name"]}) '
                              f'but rngd not running - install rng-tools'
                })
            else:
                issues.append({
                    'severity': 'INFO',
                    'metric': 'rng_daemon',
                    'value': None,
                    'message': 'No entropy daemon running - '
                              'consider installing haveged or rng-tools'
                })

    return issues


def output_plain(stats, rng_info, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only or issues:
        print(f"Entropy: {stats['entropy_avail']} / {stats['poolsize']} bits "
              f"({stats['entropy_percent']:.1f}%)")

        if verbose:
            print(f"Read wakeup threshold: {stats['read_wakeup_threshold']} bits")
            print(f"Write wakeup threshold: {stats['write_wakeup_threshold']} bits")

            # Show RNG info
            if rng_info['hw_rng_available']:
                print(f"Hardware RNG: {rng_info['hw_rng_name']} (available)")
            else:
                print("Hardware RNG: not available")

            if rng_info['rngd_running']:
                print("Entropy daemon: rngd running")
            elif rng_info['haveged_running']:
                print("Entropy daemon: haveged running")
            else:
                print("Entropy daemon: none detected")

        print()

    # Print issues
    for issue in issues:
        severity = issue['severity']
        message = issue['message']

        # Skip INFO messages in warn-only mode
        if warn_only and severity == 'INFO':
            continue

        prefix = {
            'CRITICAL': '[CRITICAL]',
            'WARNING': '[WARNING]',
            'INFO': '[INFO]'
        }.get(severity, '[UNKNOWN]')

        print(f"{prefix} {message}")


def output_json(stats, rng_info, issues, verbose):
    """Output results in JSON format."""
    result = {
        'entropy': {
            'available': stats['entropy_avail'],
            'pool_size': stats['poolsize'],
            'percent': round(stats['entropy_percent'], 2),
            'read_wakeup_threshold': stats['read_wakeup_threshold'],
            'write_wakeup_threshold': stats['write_wakeup_threshold']
        },
        'issues': issues
    }

    if verbose:
        result['rng'] = {
            'hw_available': rng_info['hw_rng_available'],
            'hw_name': rng_info['hw_rng_name'],
            'rngd_running': rng_info['rngd_running'],
            'haveged_running': rng_info['haveged_running']
        }

    print(json.dumps(result, indent=2))


def output_table(stats, rng_info, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only or issues:
        print("=" * 70)
        print("ENTROPY POOL STATUS")
        print("=" * 70)
        print(f"{'Metric':<30} {'Value':<20} {'Status':<15}")
        print("-" * 70)

        # Determine status based on thresholds
        entropy = stats['entropy_avail']
        if entropy < 100:
            status = "CRITICAL"
        elif entropy < 256:
            status = "WARNING"
        else:
            status = "OK"

        print(f"{'Entropy Available':<30} {entropy} bits{'':<10} {status:<15}")
        print(f"{'Pool Size':<30} {stats['poolsize']} bits{'':<10}")
        print(f"{'Pool Utilization':<30} {stats['entropy_percent']:.1f}%{'':<10}")

        if verbose:
            print(f"{'Read Wakeup Threshold':<30} "
                  f"{stats['read_wakeup_threshold']} bits")
            print(f"{'Write Wakeup Threshold':<30} "
                  f"{stats['write_wakeup_threshold']} bits")
            print()
            print("ENTROPY SOURCES")
            print("-" * 70)

            hw_status = (f"{rng_info['hw_rng_name']} (active)"
                        if rng_info['hw_rng_available']
                        else "not available")
            print(f"{'Hardware RNG':<30} {hw_status:<40}")

            if rng_info['rngd_running']:
                daemon_status = "rngd (running)"
            elif rng_info['haveged_running']:
                daemon_status = "haveged (running)"
            else:
                daemon_status = "none detected"
            print(f"{'Entropy Daemon':<30} {daemon_status:<40}")

        print("=" * 70)
        print()

    # Print issues
    if issues:
        filtered_issues = [i for i in issues
                          if not (warn_only and i['severity'] == 'INFO')]
        if filtered_issues:
            print("ISSUES DETECTED")
            print("=" * 70)
            for issue in filtered_issues:
                print(f"[{issue['severity']}] {issue['message']}")
            print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor system entropy pool levels for cryptographic operations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check entropy with default thresholds
  %(prog)s --warn 200 --crit 50 # Custom thresholds
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --verbose            # Show RNG sources and daemon status
  %(prog)s --warn-only          # Only show warnings/errors

Thresholds:
  --warn: Entropy level (bits) to trigger warning (default: 256)
  --crit: Entropy level (bits) to trigger critical alert (default: 100)

Common entropy levels:
  - 256+ bits: Healthy, no blocking expected
  - 128-256 bits: Adequate for most operations
  - < 128 bits: May cause delays in crypto operations
  - < 64 bits: /dev/random likely blocking, serious issues

Exit codes:
  0 - Entropy levels are healthy
  1 - Low entropy detected
  2 - Usage error or /proc filesystem unavailable
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed entropy source information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--warn',
        type=int,
        default=256,
        metavar='BITS',
        help='Warning threshold for entropy (bits) (default: 256)'
    )

    parser.add_argument(
        '--crit',
        type=int,
        default=100,
        metavar='BITS',
        help='Critical threshold for entropy (bits) (default: 100)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0:
        print("Error: --warn must be positive", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0:
        print("Error: --crit must be positive", file=sys.stderr)
        sys.exit(2)

    if args.crit >= args.warn:
        print("Error: --crit must be less than --warn", file=sys.stderr)
        sys.exit(2)

    # Gather information
    stats = get_entropy_stats()
    rng_info = check_rng_available()

    # Analyze entropy levels
    issues = analyze_entropy(stats, args.warn, args.crit, rng_info)

    # Output results
    if args.format == 'json':
        output_json(stats, rng_info, issues, args.verbose)
    elif args.format == 'table':
        output_table(stats, rng_info, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(stats, rng_info, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

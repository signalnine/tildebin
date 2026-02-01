#!/usr/bin/env python3
"""
Detect sysctl parameter drift from baseline or recommended values.

Compares current kernel parameters against a baseline configuration file
or built-in recommended values for production systems. Useful for detecting
configuration drift across large baremetal fleets.

Features:
- Compare against custom baseline file (JSON or key=value format)
- Built-in recommended values for common production settings
- Detect missing, changed, or extra parameters
- Support for pattern-based parameter filtering
- Fleet-wide configuration consistency checking

Use cases:
- Detect configuration drift after system updates
- Verify security hardening across fleet
- Audit kernel tuning consistency
- Pre-deployment configuration validation
- Post-incident configuration verification

Exit codes:
    0 - No drift detected (or --warn-only with no issues)
    1 - Configuration drift detected
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import subprocess
import re
from collections import defaultdict


# Recommended production values for common sysctls
# These are general recommendations - adjust for your workload
RECOMMENDED_VALUES = {
    # Network security
    'net.ipv4.conf.all.rp_filter': '1',
    'net.ipv4.conf.default.rp_filter': '1',
    'net.ipv4.conf.all.accept_source_route': '0',
    'net.ipv4.conf.default.accept_source_route': '0',
    'net.ipv4.conf.all.accept_redirects': '0',
    'net.ipv4.conf.default.accept_redirects': '0',
    'net.ipv4.conf.all.secure_redirects': '0',
    'net.ipv4.conf.default.secure_redirects': '0',
    'net.ipv4.conf.all.send_redirects': '0',
    'net.ipv4.conf.default.send_redirects': '0',
    'net.ipv4.icmp_echo_ignore_broadcasts': '1',
    'net.ipv4.icmp_ignore_bogus_error_responses': '1',
    'net.ipv4.tcp_syncookies': '1',

    # IPv6 security
    'net.ipv6.conf.all.accept_redirects': '0',
    'net.ipv6.conf.default.accept_redirects': '0',
    'net.ipv6.conf.all.accept_source_route': '0',
    'net.ipv6.conf.default.accept_source_route': '0',

    # Kernel security
    'kernel.randomize_va_space': '2',
    'kernel.kptr_restrict': '1',
    'kernel.dmesg_restrict': '1',
    'kernel.perf_event_paranoid': '2',
    'kernel.yama.ptrace_scope': '1',
    'kernel.sysrq': '0',

    # Core dumps
    'kernel.core_uses_pid': '1',
    'fs.suid_dumpable': '0',

    # File system
    'fs.protected_hardlinks': '1',
    'fs.protected_symlinks': '1',
}

# Categories for grouping parameters
PARAM_CATEGORIES = {
    'network_security': [
        'net.ipv4.conf.',
        'net.ipv6.conf.',
        'net.ipv4.icmp_',
        'net.ipv4.tcp_syncookies',
    ],
    'kernel_security': [
        'kernel.randomize_va_space',
        'kernel.kptr_restrict',
        'kernel.dmesg_restrict',
        'kernel.perf_event_paranoid',
        'kernel.yama.',
        'kernel.sysrq',
    ],
    'memory': [
        'vm.',
        'kernel.shmmax',
        'kernel.shmall',
    ],
    'network_performance': [
        'net.core.',
        'net.ipv4.tcp_',
        'net.ipv4.udp_',
    ],
    'filesystem': [
        'fs.',
    ],
}


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
    except FileNotFoundError:
        return -2, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def get_current_sysctls(pattern=None):
    """Get current sysctl values."""
    cmd = ['sysctl', '-a']
    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0 and returncode != -2:
        # sysctl -a may return non-zero due to permission errors on some keys
        # but still output valid data, so we continue if we have output
        if not stdout:
            return None

    if returncode == -2:
        print("Error: 'sysctl' command not found", file=sys.stderr)
        print("Install with: sudo apt-get install procps", file=sys.stderr)
        sys.exit(2)

    sysctls = {}
    for line in stdout.splitlines():
        if '=' in line:
            # Handle "key = value" format
            parts = line.split('=', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()

                # Apply pattern filter if specified
                if pattern:
                    if not re.search(pattern, key):
                        continue

                sysctls[key] = value

    return sysctls


def load_baseline(filepath):
    """Load baseline configuration from file."""
    if not os.path.exists(filepath):
        print(f"Error: Baseline file not found: {filepath}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except IOError as e:
        print(f"Error reading baseline file: {e}", file=sys.stderr)
        sys.exit(2)

    # Try JSON format first
    try:
        baseline = json.loads(content)
        if isinstance(baseline, dict):
            return baseline
    except json.JSONDecodeError:
        pass

    # Try key=value format (like sysctl.conf)
    baseline = {}
    for line in content.splitlines():
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith('#') or line.startswith(';'):
            continue

        if '=' in line:
            parts = line.split('=', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                baseline[key] = value

    return baseline


def save_baseline(sysctls, filepath, format_type='json'):
    """Save current sysctls as baseline file."""
    try:
        with open(filepath, 'w') as f:
            if format_type == 'json':
                json.dump(sysctls, f, indent=2, sort_keys=True)
                f.write('\n')
            else:
                # sysctl.conf format
                for key in sorted(sysctls.keys()):
                    f.write(f"{key} = {sysctls[key]}\n")
        return True
    except IOError as e:
        print(f"Error writing baseline file: {e}", file=sys.stderr)
        return False


def get_category(param):
    """Determine category for a parameter."""
    for category, prefixes in PARAM_CATEGORIES.items():
        for prefix in prefixes:
            if param.startswith(prefix):
                return category
    return 'other'


def compare_sysctls(current, baseline, ignore_extra=False):
    """Compare current sysctls against baseline."""
    drift = {
        'changed': [],
        'missing': [],
        'extra': [],
    }

    # Check for changed and missing parameters
    for key, expected_value in baseline.items():
        if key in current:
            current_value = current[key]
            # Normalize values for comparison (strip whitespace, handle tabs)
            norm_current = ' '.join(current_value.split())
            norm_expected = ' '.join(str(expected_value).split())

            if norm_current != norm_expected:
                drift['changed'].append({
                    'key': key,
                    'expected': expected_value,
                    'actual': current_value,
                    'category': get_category(key),
                })
        else:
            drift['missing'].append({
                'key': key,
                'expected': expected_value,
                'category': get_category(key),
            })

    # Check for extra parameters (not in baseline)
    if not ignore_extra:
        baseline_keys = set(baseline.keys())
        for key in current:
            if key not in baseline_keys:
                # Only report extra if it matches baseline patterns
                for baseline_key in baseline_keys:
                    # Check if same prefix family
                    prefix = '.'.join(baseline_key.split('.')[:2])
                    if key.startswith(prefix):
                        drift['extra'].append({
                            'key': key,
                            'value': current[key],
                            'category': get_category(key),
                        })
                        break

    return drift


def output_plain(drift, verbose=False, warn_only=False):
    """Output results in plain text format."""
    total_issues = len(drift['changed']) + len(drift['missing'])

    if not warn_only:
        print("Sysctl Drift Detection Report")
        print("=" * 60)
        print(f"Changed parameters: {len(drift['changed'])}")
        print(f"Missing parameters: {len(drift['missing'])}")
        print(f"Extra parameters: {len(drift['extra'])}")
        print()

    if drift['changed']:
        print("CHANGED PARAMETERS:")
        print("-" * 60)
        for item in sorted(drift['changed'], key=lambda x: x['key']):
            print(f"  {item['key']}")
            print(f"    Expected: {item['expected']}")
            print(f"    Actual:   {item['actual']}")
            if verbose:
                print(f"    Category: {item['category']}")
        print()

    if drift['missing']:
        print("MISSING PARAMETERS (in baseline but not on system):")
        print("-" * 60)
        for item in sorted(drift['missing'], key=lambda x: x['key']):
            print(f"  {item['key']} = {item['expected']}")
        print()

    if verbose and drift['extra']:
        print("EXTRA PARAMETERS (on system but not in baseline):")
        print("-" * 60)
        for item in sorted(drift['extra'], key=lambda x: x['key'])[:20]:
            print(f"  {item['key']} = {item['value']}")
        if len(drift['extra']) > 20:
            print(f"  ... and {len(drift['extra']) - 20} more")
        print()

    if total_issues == 0 and not warn_only:
        print("No configuration drift detected.")


def output_json(drift, current_values=None, verbose=False):
    """Output results in JSON format."""
    result = {
        'summary': {
            'changed_count': len(drift['changed']),
            'missing_count': len(drift['missing']),
            'extra_count': len(drift['extra']),
            'total_drift': len(drift['changed']) + len(drift['missing']),
        },
        'changed': drift['changed'],
        'missing': drift['missing'],
    }

    if verbose:
        result['extra'] = drift['extra']
        if current_values:
            result['current_values'] = current_values

    print(json.dumps(result, indent=2))


def output_table(drift, verbose=False, warn_only=False):
    """Output results in table format."""
    if not warn_only:
        print("=" * 80)
        print("SYSCTL DRIFT DETECTION")
        print("=" * 80)
        print(f"{'Metric':<25} {'Count':<10}")
        print("-" * 35)
        print(f"{'Changed Parameters':<25} {len(drift['changed']):<10}")
        print(f"{'Missing Parameters':<25} {len(drift['missing']):<10}")
        print(f"{'Extra Parameters':<25} {len(drift['extra']):<10}")
        print("=" * 80)
        print()

    if drift['changed']:
        print(f"{'Parameter':<45} {'Expected':<15} {'Actual':<15}")
        print("-" * 75)
        for item in sorted(drift['changed'], key=lambda x: x['key']):
            key = item['key']
            if len(key) > 44:
                key = key[:41] + '...'
            expected = str(item['expected'])[:14]
            actual = str(item['actual'])[:14]
            print(f"{key:<45} {expected:<15} {actual:<15}")
        print()

    if drift['missing']:
        print(f"{'Missing Parameter':<45} {'Expected Value':<30}")
        print("-" * 75)
        for item in sorted(drift['missing'], key=lambda x: x['key']):
            key = item['key']
            if len(key) > 44:
                key = key[:41] + '...'
            expected = str(item['expected'])[:29]
            print(f"{key:<45} {expected:<30}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Detect sysctl parameter drift from baseline or recommended values',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Compare against built-in recommendations
  %(prog)s --baseline /etc/sysctl.baseline.json
                                     # Compare against custom baseline
  %(prog)s --save-baseline /tmp/baseline.json
                                     # Save current config as baseline
  %(prog)s --pattern "net.ipv4"      # Only check network parameters
  %(prog)s --format json             # JSON output for automation
  %(prog)s --category network_security
                                     # Only check network security params

Categories:
  network_security   - IP forwarding, redirects, source routing
  kernel_security    - ASLR, ptrace, sysrq, dmesg_restrict
  memory             - VM tuning, shared memory
  network_performance - TCP/UDP buffers, core network settings
  filesystem         - File handle limits, protected links

Exit codes:
  0 - No drift detected
  1 - Configuration drift detected
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '--baseline', '-b',
        metavar='FILE',
        help='Baseline configuration file (JSON or sysctl.conf format)'
    )

    parser.add_argument(
        '--save-baseline',
        metavar='FILE',
        help='Save current configuration as baseline file'
    )

    parser.add_argument(
        '--pattern', '-p',
        metavar='REGEX',
        help='Only check parameters matching pattern'
    )

    parser.add_argument(
        '--category', '-c',
        choices=list(PARAM_CATEGORIES.keys()),
        help='Only check parameters in specified category'
    )

    parser.add_argument(
        '--ignore-extra',
        action='store_true',
        help='Ignore parameters not in baseline'
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
        help='Show detailed information including extra parameters'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show drift issues, suppress summary'
    )

    parser.add_argument(
        '--use-recommended',
        action='store_true',
        help='Use built-in recommended values (default when no baseline specified)'
    )

    args = parser.parse_args()

    # Get current sysctls
    current = get_current_sysctls(pattern=args.pattern)
    if current is None:
        print("Error: Failed to get current sysctl values", file=sys.stderr)
        sys.exit(2)

    # Handle save baseline mode
    if args.save_baseline:
        if save_baseline(current, args.save_baseline):
            print(f"Baseline saved to: {args.save_baseline}")
            print(f"Parameters saved: {len(current)}")
            sys.exit(0)
        else:
            sys.exit(2)

    # Determine baseline to use
    if args.baseline:
        baseline = load_baseline(args.baseline)
    else:
        # Use built-in recommended values
        baseline = RECOMMENDED_VALUES.copy()

    # Filter by category if specified
    if args.category:
        prefixes = PARAM_CATEGORIES.get(args.category, [])
        baseline = {
            k: v for k, v in baseline.items()
            if any(k.startswith(p) for p in prefixes)
        }

    # Filter by pattern if specified
    if args.pattern:
        baseline = {
            k: v for k, v in baseline.items()
            if re.search(args.pattern, k)
        }

    if not baseline:
        print("Warning: No parameters to check after filtering", file=sys.stderr)
        sys.exit(0)

    # Compare sysctls
    drift = compare_sysctls(current, baseline, ignore_extra=args.ignore_extra)

    # Output results
    if args.format == 'json':
        output_json(drift, current if args.verbose else None, args.verbose)
    elif args.format == 'table':
        output_table(drift, args.verbose, args.warn_only)
    else:
        output_plain(drift, args.verbose, args.warn_only)

    # Exit based on findings
    total_drift = len(drift['changed']) + len(drift['missing'])
    if total_drift > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Audit kernel security parameters against hardening best practices.

This script checks sysctl parameters against security hardening guidelines
including CIS benchmarks, STIG requirements, and common production hardening
recommendations. It's designed for large-scale baremetal environments where
consistent security posture is critical.

Checks include:
- Network security (ICMP, IP forwarding, SYN flood protection)
- Memory protection (ASLR, exec-shield, mmap restrictions)
- Filesystem hardening (symlink/hardlink restrictions, core dumps)
- Kernel hardening (kptr_restrict, dmesg_restrict, module loading)
- User namespace restrictions

Exit codes:
    0 - All security parameters meet recommended settings
    1 - One or more parameters do not meet recommendations
    2 - Usage error or missing dependency

Examples:
    # Full security audit
    baremetal_kernel_security_audit.py

    # JSON output for monitoring systems
    baremetal_kernel_security_audit.py --format json

    # Only show failed checks
    baremetal_kernel_security_audit.py --warn-only

    # Check specific category
    baremetal_kernel_security_audit.py --category network

    # Strict mode (INFO items become warnings)
    baremetal_kernel_security_audit.py --strict
"""

import argparse
import sys
import os
import json
from datetime import datetime


# Security parameter definitions
# Format: (sysctl_key, recommended_value, severity, category, description)
# Severity: CRITICAL, WARNING, INFO
SECURITY_CHECKS = [
    # Network security - prevent IP spoofing and MITM
    ('net.ipv4.conf.all.rp_filter', '1', 'WARNING', 'network',
     'Enable reverse path filtering to prevent IP spoofing'),
    ('net.ipv4.conf.default.rp_filter', '1', 'WARNING', 'network',
     'Enable reverse path filtering on new interfaces'),
    ('net.ipv4.conf.all.accept_source_route', '0', 'WARNING', 'network',
     'Disable source routing to prevent routing manipulation'),
    ('net.ipv4.conf.default.accept_source_route', '0', 'WARNING', 'network',
     'Disable source routing on new interfaces'),
    ('net.ipv6.conf.all.accept_source_route', '0', 'WARNING', 'network',
     'Disable IPv6 source routing'),
    ('net.ipv4.conf.all.accept_redirects', '0', 'WARNING', 'network',
     'Disable ICMP redirects to prevent MITM attacks'),
    ('net.ipv4.conf.default.accept_redirects', '0', 'WARNING', 'network',
     'Disable ICMP redirects on new interfaces'),
    ('net.ipv6.conf.all.accept_redirects', '0', 'WARNING', 'network',
     'Disable IPv6 ICMP redirects'),
    ('net.ipv4.conf.all.secure_redirects', '0', 'INFO', 'network',
     'Disable secure ICMP redirects'),
    ('net.ipv4.conf.all.send_redirects', '0', 'WARNING', 'network',
     'Disable sending ICMP redirects (non-router)'),
    ('net.ipv4.conf.default.send_redirects', '0', 'WARNING', 'network',
     'Disable sending ICMP redirects on new interfaces'),
    ('net.ipv4.icmp_ignore_bogus_error_responses', '1', 'INFO', 'network',
     'Ignore bogus ICMP error responses'),
    ('net.ipv4.icmp_echo_ignore_broadcasts', '1', 'WARNING', 'network',
     'Ignore broadcast ICMP echo requests (Smurf attack protection)'),
    ('net.ipv4.tcp_syncookies', '1', 'CRITICAL', 'network',
     'Enable SYN cookies for SYN flood protection'),
    ('net.ipv4.tcp_timestamps', '1', 'INFO', 'network',
     'Enable TCP timestamps for PAWS and RTT estimation'),

    # IP forwarding - should be disabled unless this is a router
    ('net.ipv4.ip_forward', '0', 'INFO', 'network',
     'Disable IP forwarding (enable only for routers/containers)'),
    ('net.ipv6.conf.all.forwarding', '0', 'INFO', 'network',
     'Disable IPv6 forwarding (enable only for routers)'),

    # Memory protection
    ('kernel.randomize_va_space', '2', 'CRITICAL', 'memory',
     'Enable full ASLR (Address Space Layout Randomization)'),
    ('vm.mmap_min_addr', '65536', 'WARNING', 'memory',
     'Prevent mapping memory at low addresses (NULL deref protection)'),
    ('vm.mmap_rnd_bits', '32', 'INFO', 'memory',
     'ASLR entropy for mmap base (32-bit max on x86_64)'),
    ('vm.mmap_rnd_compat_bits', '16', 'INFO', 'memory',
     'ASLR entropy for compat mmap base'),

    # Kernel hardening
    ('kernel.kptr_restrict', '1', 'WARNING', 'kernel',
     'Restrict kernel pointer exposure in /proc'),
    ('kernel.dmesg_restrict', '1', 'WARNING', 'kernel',
     'Restrict dmesg access to privileged users'),
    ('kernel.perf_event_paranoid', '2', 'INFO', 'kernel',
     'Restrict perf_event access'),
    ('kernel.sysrq', '0', 'INFO', 'kernel',
     'Disable magic SysRq key (or use 176 for safe subset)'),
    ('kernel.yama.ptrace_scope', '1', 'WARNING', 'kernel',
     'Restrict ptrace to parent processes only'),
    ('kernel.kexec_load_disabled', '1', 'INFO', 'kernel',
     'Disable kexec to prevent runtime kernel replacement'),
    ('kernel.unprivileged_bpf_disabled', '1', 'WARNING', 'kernel',
     'Disable unprivileged BPF to reduce attack surface'),

    # Filesystem hardening
    ('fs.protected_symlinks', '1', 'WARNING', 'filesystem',
     'Protect against symlink attacks in world-writable dirs'),
    ('fs.protected_hardlinks', '1', 'WARNING', 'filesystem',
     'Protect against hardlink attacks'),
    ('fs.protected_fifos', '2', 'INFO', 'filesystem',
     'Protect against FIFO attacks in world-writable dirs'),
    ('fs.protected_regular', '2', 'INFO', 'filesystem',
     'Protect against file creation attacks'),
    ('fs.suid_dumpable', '0', 'WARNING', 'filesystem',
     'Disable core dumps for setuid programs'),

    # User namespace restrictions
    ('kernel.unprivileged_userns_clone', '0', 'INFO', 'namespace',
     'Disable unprivileged user namespace creation'),
    ('user.max_user_namespaces', '0', 'INFO', 'namespace',
     'Limit user namespace creation'),

    # Module loading restrictions
    ('kernel.modules_disabled', '0', 'INFO', 'kernel',
     'Module loading status (1=locked down, may break functionality)'),
]


def read_sysctl(key):
    """Read a sysctl value from /proc/sys."""
    path = '/proc/sys/' + key.replace('.', '/')
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def check_parameter(key, recommended, severity, category, description):
    """Check a single security parameter."""
    current = read_sysctl(key)

    result = {
        'parameter': key,
        'recommended': recommended,
        'current': current,
        'severity': severity,
        'category': category,
        'description': description,
        'status': 'unknown',
    }

    if current is None:
        result['status'] = 'unavailable'
        result['message'] = 'Parameter not available on this system'
    elif current == recommended:
        result['status'] = 'pass'
        result['message'] = 'Parameter meets recommendation'
    else:
        result['status'] = 'fail'
        result['message'] = f'Current value "{current}" does not match recommended "{recommended}"'

        # Special cases where different values might be acceptable
        if key == 'net.ipv4.ip_forward' and current == '1':
            result['message'] += ' (may be intentional for routing/containers)'
        elif key == 'kernel.sysrq' and current in ['176', '1']:
            result['message'] += ' (restricted SysRq may be acceptable)'
        elif key == 'vm.mmap_min_addr' and int(current) >= int(recommended):
            result['status'] = 'pass'
            result['message'] = f'Current value "{current}" meets or exceeds recommendation'
        elif key == 'kernel.perf_event_paranoid' and int(current) >= int(recommended):
            result['status'] = 'pass'
            result['message'] = f'Current value "{current}" is more restrictive'

    return result


def run_audit(categories=None):
    """Run the full security audit."""
    results = []

    for check in SECURITY_CHECKS:
        key, recommended, severity, category, description = check

        # Filter by category if specified
        if categories and category not in categories:
            continue

        result = check_parameter(key, recommended, severity, category, description)
        results.append(result)

    return results


def get_summary(results):
    """Generate summary statistics."""
    summary = {
        'total': len(results),
        'pass': sum(1 for r in results if r['status'] == 'pass'),
        'fail': sum(1 for r in results if r['status'] == 'fail'),
        'unavailable': sum(1 for r in results if r['status'] == 'unavailable'),
        'critical_failures': sum(1 for r in results
                                  if r['status'] == 'fail' and r['severity'] == 'CRITICAL'),
        'warning_failures': sum(1 for r in results
                                 if r['status'] == 'fail' and r['severity'] == 'WARNING'),
        'info_failures': sum(1 for r in results
                              if r['status'] == 'fail' and r['severity'] == 'INFO'),
    }

    # Calculate score as percentage of passing checks
    checkable = summary['total'] - summary['unavailable']
    if checkable > 0:
        summary['score'] = round(100 * summary['pass'] / checkable, 1)
    else:
        summary['score'] = 0

    return summary


def output_plain(results, warn_only, verbose, strict):
    """Plain text output format."""
    categories = {}
    for result in results:
        cat = result['category']
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(result)

    has_issues = False

    for category, checks in sorted(categories.items()):
        # Filter results for this category
        if warn_only:
            checks = [c for c in checks if c['status'] == 'fail']
            if not checks:
                continue

        print(f"\n=== {category.upper()} ===")

        for check in checks:
            status = check['status']
            severity = check['severity']

            # Skip passing checks in warn-only mode
            if warn_only and status == 'pass':
                continue

            # In strict mode, INFO failures become issues
            if strict and status == 'fail':
                has_issues = True
            elif status == 'fail' and severity in ['CRITICAL', 'WARNING']:
                has_issues = True

            # Status indicator
            if status == 'pass':
                indicator = '[PASS]'
            elif status == 'fail':
                indicator = f'[FAIL:{severity}]'
            elif status == 'unavailable':
                indicator = '[N/A]'
            else:
                indicator = '[???]'

            print(f"  {indicator} {check['parameter']}")

            if verbose or status != 'pass':
                print(f"      {check['description']}")
                if status == 'fail':
                    print(f"      Current: {check['current']} | Recommended: {check['recommended']}")
                elif status == 'pass' and verbose:
                    print(f"      Value: {check['current']}")

    # Summary
    summary = get_summary(results)
    print(f"\n=== SUMMARY ===")
    print(f"  Security Score: {summary['score']}%")
    print(f"  Passed: {summary['pass']}/{summary['total'] - summary['unavailable']}")
    if summary['critical_failures']:
        print(f"  Critical Failures: {summary['critical_failures']}")
    if summary['warning_failures']:
        print(f"  Warning Failures: {summary['warning_failures']}")
    if summary['info_failures']:
        print(f"  Info Failures: {summary['info_failures']}")
    if summary['unavailable']:
        print(f"  Unavailable: {summary['unavailable']}")

    return has_issues


def output_json(results, strict):
    """JSON output format."""
    summary = get_summary(results)

    output = {
        'timestamp': datetime.now().isoformat(),
        'hostname': os.uname().nodename,
        'results': results,
        'summary': summary,
    }

    print(json.dumps(output, indent=2))

    # Determine if there are issues
    if strict:
        return summary['fail'] > 0
    else:
        return summary['critical_failures'] > 0 or summary['warning_failures'] > 0


def output_table(results, warn_only, strict):
    """Tabular output format."""
    if warn_only:
        results = [r for r in results if r['status'] == 'fail']

    if not results:
        print("All security parameters meet recommendations")
        return False

    print(f"{'Parameter':<45} {'Current':<12} {'Recommended':<12} {'Severity':<10} {'Status':<8}")
    print("-" * 95)

    has_issues = False
    for result in results:
        param = result['parameter'][:44]
        current = str(result['current'])[:11] if result['current'] else 'N/A'
        recommended = str(result['recommended'])[:11]
        severity = result['severity']
        status = result['status'].upper()

        print(f"{param:<45} {current:<12} {recommended:<12} {severity:<10} {status:<8}")

        if result['status'] == 'fail':
            if strict or severity in ['CRITICAL', 'WARNING']:
                has_issues = True

    print("-" * 95)

    summary = get_summary(results)
    print(f"\nSecurity Score: {summary['score']}% ({summary['pass']} passed, {summary['fail']} failed)")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Audit kernel security parameters against hardening best practices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                       # Full security audit
  %(prog)s --format json         # JSON output for monitoring
  %(prog)s --warn-only           # Only show failures
  %(prog)s --category network    # Check network parameters only
  %(prog)s --strict              # Treat INFO failures as issues

Categories:
  network    - Network stack security (ICMP, routing, TCP)
  memory     - Memory protection (ASLR, mmap restrictions)
  kernel     - Kernel hardening (ptrace, kptr_restrict)
  filesystem - Filesystem protection (symlinks, core dumps)
  namespace  - User namespace restrictions

Reference:
  Based on CIS Benchmarks, STIG requirements, and common
  production hardening guidelines.

Exit codes:
  0 - All CRITICAL and WARNING checks pass
  1 - One or more CRITICAL or WARNING failures
  2 - Usage error
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
        help='Show detailed information for all checks'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show failed checks'
    )

    parser.add_argument(
        '--category',
        choices=['network', 'memory', 'kernel', 'filesystem', 'namespace'],
        action='append',
        dest='categories',
        help='Check specific category (can be repeated)'
    )

    parser.add_argument(
        '--strict',
        action='store_true',
        help='Treat INFO-level failures as issues (affects exit code)'
    )

    parser.add_argument(
        '--list-parameters',
        action='store_true',
        help='List all checked parameters and exit'
    )

    args = parser.parse_args()

    # Handle list-parameters
    if args.list_parameters:
        print("Security parameters checked by this script:\n")
        current_category = None
        for check in SECURITY_CHECKS:
            key, recommended, severity, category, description = check
            if category != current_category:
                print(f"\n[{category.upper()}]")
                current_category = category
            print(f"  {key} = {recommended} ({severity})")
            print(f"    {description}")
        sys.exit(0)

    # Run audit
    results = run_audit(categories=args.categories)

    if not results:
        print("No parameters matched the specified criteria", file=sys.stderr)
        sys.exit(2)

    # Output results
    if args.format == 'json':
        has_issues = output_json(results, args.strict)
    elif args.format == 'table':
        has_issues = output_table(results, args.warn_only, args.strict)
    else:
        has_issues = output_plain(results, args.warn_only, args.verbose, args.strict)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()

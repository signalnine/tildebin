#!/usr/bin/env python3
"""
Audit kernel sysctl parameters against security hardening best practices.

Unlike sysctl_audit.py which compares against a user-provided baseline,
this script has built-in security recommendations based on CIS benchmarks,
STIG guidelines, and Linux kernel security best practices.

Checks cover:
- Network security (IP forwarding, ICMP, SYN flood protection)
- Kernel memory protections (ASLR, exec-shield, ptrace scope)
- Filesystem security (protected symlinks, hardlinks, core dumps)
- User namespace and privilege controls

Exit codes:
    0 - All checks pass (no security issues found)
    1 - Security issues found (one or more checks failed)
    2 - Usage error or sysctl command not available
"""

import argparse
import subprocess
import sys
import json


# Security recommendations organized by category
# Format: (parameter, recommended_value, severity, description)
# severity: 'critical', 'high', 'medium', 'low'
SECURITY_CHECKS = {
    'network_ipv4': [
        ('net.ipv4.ip_forward', '0', 'high',
         'Disable IPv4 forwarding unless acting as router'),
        ('net.ipv4.conf.all.send_redirects', '0', 'medium',
         'Disable sending ICMP redirects'),
        ('net.ipv4.conf.default.send_redirects', '0', 'medium',
         'Disable sending ICMP redirects (default)'),
        ('net.ipv4.conf.all.accept_redirects', '0', 'medium',
         'Ignore ICMP redirects'),
        ('net.ipv4.conf.default.accept_redirects', '0', 'medium',
         'Ignore ICMP redirects (default)'),
        ('net.ipv4.conf.all.secure_redirects', '0', 'medium',
         'Ignore secure ICMP redirects'),
        ('net.ipv4.conf.default.secure_redirects', '0', 'medium',
         'Ignore secure ICMP redirects (default)'),
        ('net.ipv4.conf.all.accept_source_route', '0', 'high',
         'Disable source routing'),
        ('net.ipv4.conf.default.accept_source_route', '0', 'high',
         'Disable source routing (default)'),
        ('net.ipv4.conf.all.log_martians', '1', 'low',
         'Log packets with impossible addresses'),
        ('net.ipv4.conf.default.log_martians', '1', 'low',
         'Log martian packets (default)'),
        ('net.ipv4.icmp_echo_ignore_broadcasts', '1', 'medium',
         'Ignore broadcast ICMP echo requests (smurf attack mitigation)'),
        ('net.ipv4.icmp_ignore_bogus_error_responses', '1', 'low',
         'Ignore bogus ICMP error responses'),
        ('net.ipv4.conf.all.rp_filter', '1', 'high',
         'Enable reverse path filtering (spoofing protection)'),
        ('net.ipv4.conf.default.rp_filter', '1', 'high',
         'Enable reverse path filtering (default)'),
        ('net.ipv4.tcp_syncookies', '1', 'high',
         'Enable SYN flood protection'),
        ('net.ipv4.tcp_timestamps', '1', 'low',
         'Enable TCP timestamps (PAWS protection)'),
    ],
    'network_ipv6': [
        ('net.ipv6.conf.all.forwarding', '0', 'high',
         'Disable IPv6 forwarding unless acting as router'),
        ('net.ipv6.conf.all.accept_redirects', '0', 'medium',
         'Ignore IPv6 ICMP redirects'),
        ('net.ipv6.conf.default.accept_redirects', '0', 'medium',
         'Ignore IPv6 ICMP redirects (default)'),
        ('net.ipv6.conf.all.accept_source_route', '0', 'high',
         'Disable IPv6 source routing'),
        ('net.ipv6.conf.default.accept_source_route', '0', 'high',
         'Disable IPv6 source routing (default)'),
        ('net.ipv6.conf.all.accept_ra', '0', 'medium',
         'Ignore IPv6 router advertisements'),
        ('net.ipv6.conf.default.accept_ra', '0', 'medium',
         'Ignore IPv6 router advertisements (default)'),
    ],
    'kernel_memory': [
        ('kernel.randomize_va_space', '2', 'critical',
         'Enable full ASLR (Address Space Layout Randomization)'),
        ('kernel.kptr_restrict', '1', 'high',
         'Restrict kernel pointer exposure'),
        ('kernel.dmesg_restrict', '1', 'medium',
         'Restrict access to kernel logs'),
        ('kernel.perf_event_paranoid', '2', 'medium',
         'Restrict unprivileged access to perf events'),
        ('kernel.yama.ptrace_scope', '1', 'high',
         'Restrict ptrace to child processes only'),
        ('vm.mmap_min_addr', '65536', 'high',
         'Prevent mapping at low addresses (NULL deref protection)'),
    ],
    'kernel_modules': [
        ('kernel.modules_disabled', '0', 'low',
         'Module loading (1=disabled after boot, 0=allowed)'),
        ('kernel.kexec_load_disabled', '1', 'medium',
         'Disable kexec system call'),
    ],
    'filesystem': [
        ('fs.protected_symlinks', '1', 'high',
         'Protect against symlink attacks in world-writable directories'),
        ('fs.protected_hardlinks', '1', 'high',
         'Protect against hardlink attacks'),
        ('fs.protected_fifos', '1', 'medium',
         'Protect against FIFO attacks in world-writable directories'),
        ('fs.protected_regular', '2', 'medium',
         'Protect against regular file overwrites'),
        ('fs.suid_dumpable', '0', 'high',
         'Disable core dumps for setuid programs'),
    ],
    'user_namespaces': [
        ('kernel.unprivileged_userns_clone', '0', 'medium',
         'Restrict unprivileged user namespace creation'),
        ('kernel.unprivileged_bpf_disabled', '1', 'high',
         'Disable unprivileged BPF'),
        ('net.core.bpf_jit_harden', '2', 'medium',
         'Harden BPF JIT compiler'),
    ],
}


def run_command(cmd):
    """Execute a command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def get_sysctl_value(param):
    """Get the current value of a sysctl parameter"""
    returncode, stdout, stderr = run_command(
        "sysctl -n {} 2>/dev/null".format(param)
    )
    if returncode == 0:
        return stdout.strip()
    return None


def check_sysctl_available():
    """Check if sysctl command is available"""
    returncode, _, _ = run_command("which sysctl")
    return returncode == 0


def audit_category(category_name, checks, verbose=False):
    """Audit a category of sysctl parameters"""
    results = []

    for param, expected, severity, description in checks:
        actual = get_sysctl_value(param)

        if actual is None:
            status = 'unavailable'
            passed = True  # Not a failure if parameter doesn't exist
        elif actual == expected:
            status = 'pass'
            passed = True
        else:
            status = 'fail'
            passed = False

        result = {
            'parameter': param,
            'expected': expected,
            'actual': actual,
            'severity': severity,
            'description': description,
            'status': status,
            'passed': passed,
            'category': category_name,
        }

        # In non-verbose mode, only include failures and unavailable
        if verbose or status in ('fail', 'unavailable'):
            results.append(result)

    return results


def output_plain(results, show_passed=False, warn_only=False):
    """Output results in plain text format"""
    if not results:
        print("All security checks passed!")
        return

    # Group by category
    by_category = {}
    for r in results:
        cat = r['category']
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(r)

    # Group by severity for summary
    by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
    for r in results:
        if r['status'] == 'fail':
            by_severity[r['severity']].append(r)

    # Print summary
    total_issues = sum(len(v) for v in by_severity.values())
    if total_issues > 0:
        print("Security Audit Summary")
        print("=" * 70)
        print("Critical: {}  High: {}  Medium: {}  Low: {}".format(
            len(by_severity['critical']),
            len(by_severity['high']),
            len(by_severity['medium']),
            len(by_severity['low']),
        ))
        print()

    # Print by category
    category_names = {
        'network_ipv4': 'Network Security (IPv4)',
        'network_ipv6': 'Network Security (IPv6)',
        'kernel_memory': 'Kernel Memory Protections',
        'kernel_modules': 'Kernel Module Controls',
        'filesystem': 'Filesystem Security',
        'user_namespaces': 'User Namespace & BPF Controls',
    }

    for cat_key in ['network_ipv4', 'network_ipv6', 'kernel_memory',
                    'kernel_modules', 'filesystem', 'user_namespaces']:
        if cat_key not in by_category:
            continue

        cat_results = by_category[cat_key]
        if warn_only:
            cat_results = [r for r in cat_results if r['status'] == 'fail']

        if not cat_results:
            continue

        print(category_names.get(cat_key, cat_key))
        print("-" * 70)

        for r in cat_results:
            if r['status'] == 'pass':
                symbol = '[PASS]'
            elif r['status'] == 'unavailable':
                symbol = '[N/A] '
            else:
                symbol = '[FAIL]'

            severity_tag = '[{}]'.format(r['severity'].upper())
            print("{} {} {}".format(symbol, severity_tag.ljust(10), r['parameter']))

            if r['status'] == 'fail':
                print("       Current: {}  Recommended: {}".format(
                    r['actual'], r['expected']))
                print("       {}".format(r['description']))
            elif r['status'] == 'unavailable':
                print("       Parameter not available on this kernel")

        print()


def output_json(results):
    """Output results in JSON format"""
    summary = {
        'total_checks': len(results),
        'passed': len([r for r in results if r['status'] == 'pass']),
        'failed': len([r for r in results if r['status'] == 'fail']),
        'unavailable': len([r for r in results if r['status'] == 'unavailable']),
        'by_severity': {
            'critical': len([r for r in results
                           if r['status'] == 'fail' and r['severity'] == 'critical']),
            'high': len([r for r in results
                        if r['status'] == 'fail' and r['severity'] == 'high']),
            'medium': len([r for r in results
                          if r['status'] == 'fail' and r['severity'] == 'medium']),
            'low': len([r for r in results
                       if r['status'] == 'fail' and r['severity'] == 'low']),
        }
    }

    output = {
        'summary': summary,
        'results': results,
    }

    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format"""
    if warn_only:
        results = [r for r in results if r['status'] == 'fail']

    if not results:
        print("All security checks passed!")
        return

    # Header
    print("{:<6} {:<10} {:<45} {:<8} {:<8}".format(
        'Status', 'Severity', 'Parameter', 'Current', 'Expected'))
    print("-" * 80)

    # Sort by severity then parameter
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_results = sorted(results,
                           key=lambda x: (severity_order.get(x['severity'], 4),
                                         x['parameter']))

    for r in sorted_results:
        status = 'PASS' if r['status'] == 'pass' else (
            'N/A' if r['status'] == 'unavailable' else 'FAIL')
        actual = r['actual'] if r['actual'] else 'N/A'
        print("{:<6} {:<10} {:<45} {:<8} {:<8}".format(
            status,
            r['severity'].upper(),
            r['parameter'][:45],
            str(actual)[:8],
            r['expected'][:8],
        ))


def main():
    parser = argparse.ArgumentParser(
        description="Audit kernel sysctl parameters against security best practices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Categories checked:
  network_ipv4    - IPv4 network security (forwarding, ICMP, spoofing)
  network_ipv6    - IPv6 network security
  kernel_memory   - ASLR, ptrace restrictions, kernel pointer exposure
  kernel_modules  - Module loading and kexec controls
  filesystem      - Symlink/hardlink protections, core dump settings
  user_namespaces - Unprivileged namespace and BPF restrictions

Examples:
  %(prog)s                      # Run all security checks
  %(prog)s --category network   # Check only network settings
  %(prog)s --warn-only          # Only show failures
  %(prog)s --format json        # JSON output for automation
  %(prog)s --severity high      # Only check high/critical severity
"""
    )

    parser.add_argument(
        "-c", "--category",
        choices=['network', 'kernel', 'filesystem', 'all'],
        default='all',
        help="Category to audit (default: all)"
    )

    parser.add_argument(
        "-s", "--severity",
        choices=['critical', 'high', 'medium', 'low', 'all'],
        default='all',
        help="Minimum severity to check (default: all)"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all checks including passed ones"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show failed checks"
    )

    parser.add_argument(
        "-l", "--list-checks",
        action="store_true",
        help="List all checks without running them"
    )

    args = parser.parse_args()

    # List checks mode
    if args.list_checks:
        total = 0
        for cat_name, checks in sorted(SECURITY_CHECKS.items()):
            print("{}:".format(cat_name))
            for param, expected, severity, desc in checks:
                print("  {} [{}] = {} ({})".format(
                    param, severity, expected, desc))
                total += 1
            print()
        print("Total: {} checks".format(total))
        sys.exit(0)

    # Check sysctl availability
    if not check_sysctl_available():
        print("Error: sysctl command not found", file=sys.stderr)
        print("This tool requires procps/sysctl to be installed", file=sys.stderr)
        sys.exit(2)

    # Determine which categories to check
    categories_to_check = []
    if args.category == 'all':
        categories_to_check = list(SECURITY_CHECKS.keys())
    elif args.category == 'network':
        categories_to_check = ['network_ipv4', 'network_ipv6']
    elif args.category == 'kernel':
        categories_to_check = ['kernel_memory', 'kernel_modules', 'user_namespaces']
    elif args.category == 'filesystem':
        categories_to_check = ['filesystem']

    # Filter by severity
    severity_levels = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    min_severity = severity_levels.get(args.severity, 3)

    # Run checks
    all_results = []
    for cat_name in categories_to_check:
        checks = SECURITY_CHECKS.get(cat_name, [])

        # Filter by severity
        if args.severity != 'all':
            checks = [c for c in checks
                     if severity_levels.get(c[2], 3) <= min_severity]

        results = audit_category(cat_name, checks, verbose=args.verbose)
        all_results.extend(results)

    # Output results
    if args.format == "json":
        output_json(all_results)
    elif args.format == "table":
        output_table(all_results, warn_only=args.warn_only)
    else:
        output_plain(all_results, show_passed=args.verbose, warn_only=args.warn_only)

    # Exit code based on failures
    has_failures = any(r['status'] == 'fail' for r in all_results)
    sys.exit(1 if has_failures else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Audit kernel runtime configuration against security and performance baselines.

This script checks /proc/sys kernel parameters against recommended values for
production server environments. Useful for ensuring consistent configuration
across large baremetal fleets.

Checks include:
- Network security settings (syn cookies, rp_filter, etc.)
- Memory management (swappiness, overcommit, OOM behavior)
- Performance tuning (TCP buffers, file limits, vm settings)
- Security hardening (ASLR, ptrace, dmesg restrictions)

Profiles available:
- security: Focus on security hardening
- performance: Focus on high-performance computing
- balanced: Combined security and performance (default)
- custom: Load from external YAML/JSON file

Exit codes:
    0 - All checked parameters meet recommendations
    1 - One or more parameters don't match recommendations
    2 - Usage error or missing dependency
"""

import argparse
import json
import os
import sys
from pathlib import Path


# Baseline configurations organized by profile
# Format: {sysctl_path: (recommended_value, comparison, description)}
# comparison: 'eq' (equal), 'ge' (>=), 'le' (<=), 'ne' (not equal)

SECURITY_BASELINE = {
    # Network security
    'net.ipv4.tcp_syncookies': ('1', 'eq', 'Enable SYN flood protection'),
    'net.ipv4.conf.all.rp_filter': ('1', 'ge', 'Enable reverse path filtering'),
    'net.ipv4.conf.default.rp_filter': ('1', 'ge', 'Enable reverse path filtering'),
    'net.ipv4.conf.all.accept_redirects': ('0', 'eq', 'Disable ICMP redirects'),
    'net.ipv4.conf.default.accept_redirects': ('0', 'eq', 'Disable ICMP redirects'),
    'net.ipv4.conf.all.send_redirects': ('0', 'eq', 'Disable sending ICMP redirects'),
    'net.ipv4.conf.default.send_redirects': ('0', 'eq', 'Disable sending ICMP redirects'),
    'net.ipv4.conf.all.accept_source_route': ('0', 'eq', 'Disable source routing'),
    'net.ipv4.conf.default.accept_source_route': ('0', 'eq', 'Disable source routing'),
    'net.ipv4.conf.all.log_martians': ('1', 'eq', 'Log spoofed packets'),
    'net.ipv4.icmp_echo_ignore_broadcasts': ('1', 'eq', 'Ignore broadcast ICMP'),
    'net.ipv4.icmp_ignore_bogus_error_responses': ('1', 'eq', 'Ignore bogus ICMP errors'),
    'net.ipv6.conf.all.accept_redirects': ('0', 'eq', 'Disable IPv6 ICMP redirects'),
    'net.ipv6.conf.default.accept_redirects': ('0', 'eq', 'Disable IPv6 ICMP redirects'),
    'net.ipv6.conf.all.accept_source_route': ('0', 'eq', 'Disable IPv6 source routing'),
    'net.ipv6.conf.default.accept_source_route': ('0', 'eq', 'Disable IPv6 source routing'),

    # Kernel security
    'kernel.randomize_va_space': ('2', 'eq', 'Full ASLR enabled'),
    'kernel.dmesg_restrict': ('1', 'eq', 'Restrict dmesg access'),
    'kernel.kptr_restrict': ('1', 'ge', 'Restrict kernel pointer exposure'),
    'kernel.yama.ptrace_scope': ('1', 'ge', 'Restrict ptrace to parent process'),
    'kernel.sysrq': ('0', 'le', 'Disable/restrict SysRq (0=disabled, 1=all, 176=safe subset)'),
    'kernel.core_uses_pid': ('1', 'eq', 'Core dumps include PID'),

    # Filesystem security
    'fs.protected_hardlinks': ('1', 'eq', 'Protect against hardlink attacks'),
    'fs.protected_symlinks': ('1', 'eq', 'Protect against symlink attacks'),
    'fs.suid_dumpable': ('0', 'eq', 'Disable core dumps for setuid programs'),
}

PERFORMANCE_BASELINE = {
    # TCP/Network performance
    'net.core.somaxconn': ('4096', 'ge', 'Socket listen backlog'),
    'net.core.netdev_max_backlog': ('5000', 'ge', 'Network device backlog queue'),
    'net.core.rmem_max': ('16777216', 'ge', 'Max receive socket buffer'),
    'net.core.wmem_max': ('16777216', 'ge', 'Max send socket buffer'),
    'net.ipv4.tcp_rmem': ('4096 87380 16777216', 'eq', 'TCP receive buffer sizes'),
    'net.ipv4.tcp_wmem': ('4096 65536 16777216', 'eq', 'TCP send buffer sizes'),
    'net.ipv4.tcp_max_syn_backlog': ('4096', 'ge', 'SYN backlog queue size'),
    'net.ipv4.tcp_fin_timeout': ('15', 'le', 'TCP FIN timeout (lower = faster cleanup)'),
    'net.ipv4.tcp_tw_reuse': ('1', 'eq', 'Allow TIME_WAIT socket reuse'),
    'net.ipv4.tcp_keepalive_time': ('600', 'le', 'TCP keepalive time'),
    'net.ipv4.tcp_keepalive_intvl': ('60', 'le', 'TCP keepalive interval'),
    'net.ipv4.tcp_keepalive_probes': ('5', 'le', 'TCP keepalive probes'),
    'net.ipv4.ip_local_port_range': ('1024 65535', 'eq', 'Ephemeral port range'),

    # Memory/VM performance
    'vm.swappiness': ('10', 'le', 'Reduce swap usage preference'),
    'vm.dirty_ratio': ('40', 'le', 'Max dirty pages percentage before blocking writes'),
    'vm.dirty_background_ratio': ('10', 'le', 'Background dirty pages flush threshold'),
    'vm.vfs_cache_pressure': ('50', 'le', 'Reduce inode/dentry cache reclaim pressure'),
    'vm.min_free_kbytes': ('65536', 'ge', 'Minimum free memory reserved for kernel'),

    # File descriptor limits
    'fs.file-max': ('2097152', 'ge', 'Maximum open files system-wide'),
    'fs.nr_open': ('1048576', 'ge', 'Maximum file descriptors per process'),
    'fs.inotify.max_user_watches': ('524288', 'ge', 'Inotify watches per user'),
    'fs.inotify.max_user_instances': ('1024', 'ge', 'Inotify instances per user'),

    # Kernel performance
    'kernel.pid_max': ('4194304', 'ge', 'Maximum PID value'),
    'kernel.threads-max': ('256000', 'ge', 'Maximum threads system-wide'),
}

BALANCED_BASELINE = {**SECURITY_BASELINE, **PERFORMANCE_BASELINE}


def sysctl_path_to_file(sysctl_path):
    """Convert sysctl path (net.ipv4.tcp_syncookies) to file path"""
    return '/proc/sys/' + sysctl_path.replace('.', '/')


def read_sysctl(sysctl_path):
    """Read current value of a sysctl parameter"""
    file_path = sysctl_path_to_file(sysctl_path)
    try:
        with open(file_path, 'r') as f:
            value = f.read().strip()
            # Normalize whitespace for multi-value params like tcp_rmem
            value = ' '.join(value.split())
            return value
    except FileNotFoundError:
        return None
    except PermissionError:
        return '[permission denied]'
    except IOError as e:
        return f'[error: {e}]'


def compare_values(current, expected, comparison):
    """Compare values based on comparison type"""
    if current is None or current.startswith('['):
        return False, 'unreadable'

    try:
        # Handle multi-value parameters (like tcp_rmem "4096 87380 16777216")
        if ' ' in expected:
            # For multi-value, use string comparison
            return current == expected, 'eq'

        # Try numeric comparison
        current_num = int(current)
        expected_num = int(expected)

        if comparison == 'eq':
            return current_num == expected_num, comparison
        elif comparison == 'ge':
            return current_num >= expected_num, comparison
        elif comparison == 'le':
            return current_num <= expected_num, comparison
        elif comparison == 'ne':
            return current_num != expected_num, comparison
        else:
            return current == expected, 'eq'

    except ValueError:
        # Fall back to string comparison
        if comparison == 'eq':
            return current == expected, comparison
        elif comparison == 'ne':
            return current != expected, comparison
        else:
            return current == expected, 'eq'


def audit_baseline(baseline, verbose=False):
    """Audit current settings against baseline"""
    results = []
    passed = 0
    failed = 0
    skipped = 0

    for sysctl_path, (expected, comparison, description) in baseline.items():
        current = read_sysctl(sysctl_path)

        if current is None:
            status = 'skipped'
            skipped += 1
            match = None
        elif current.startswith('['):
            status = 'error'
            skipped += 1
            match = False
        else:
            match, _ = compare_values(current, expected, comparison)
            if match:
                status = 'pass'
                passed += 1
            else:
                status = 'fail'
                failed += 1

        results.append({
            'param': sysctl_path,
            'current': current,
            'expected': expected,
            'comparison': comparison,
            'description': description,
            'status': status,
            'match': match,
        })

    return {
        'results': results,
        'summary': {
            'total': len(baseline),
            'passed': passed,
            'failed': failed,
            'skipped': skipped,
        }
    }


def load_custom_baseline(path):
    """Load custom baseline from JSON or YAML file"""
    path = Path(path)

    if not path.exists():
        print(f"Error: Custom baseline file not found: {path}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(path, 'r') as f:
            if path.suffix in ('.yaml', '.yml'):
                try:
                    import yaml
                    data = yaml.safe_load(f)
                except ImportError:
                    print("Error: PyYAML required for YAML files", file=sys.stderr)
                    print("Install with: pip install pyyaml", file=sys.stderr)
                    sys.exit(2)
            else:
                data = json.load(f)

        # Convert to internal format
        baseline = {}
        for param, config in data.items():
            if isinstance(config, dict):
                expected = str(config.get('value', config.get('expected', '')))
                comparison = config.get('comparison', 'eq')
                description = config.get('description', '')
            else:
                expected = str(config)
                comparison = 'eq'
                description = ''

            baseline[param] = (expected, comparison, description)

        return baseline

    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error loading baseline file: {e}", file=sys.stderr)
        sys.exit(2)


def output_plain(audit_result, warn_only=False, verbose=False):
    """Output results in plain text format"""
    summary = audit_result['summary']
    results = audit_result['results']

    if not warn_only:
        print("Kernel Configuration Audit")
        print("=" * 70)
        print(f"Total: {summary['total']} | "
              f"Passed: {summary['passed']} | "
              f"Failed: {summary['failed']} | "
              f"Skipped: {summary['skipped']}")
        print()

    # Group by status
    failures = [r for r in results if r['status'] == 'fail']
    passes = [r for r in results if r['status'] == 'pass']
    skipped = [r for r in results if r['status'] in ('skipped', 'error')]

    if failures:
        print("FAILED CHECKS:")
        print("-" * 70)
        for r in failures:
            comp_symbol = {'eq': '=', 'ge': '>=', 'le': '<=', 'ne': '!='}
            expected_str = f"{comp_symbol.get(r['comparison'], '=')} {r['expected']}"
            print(f"[FAIL] {r['param']}")
            print(f"       Current: {r['current']} | Expected: {expected_str}")
            if verbose and r['description']:
                print(f"       {r['description']}")
        print()

    if verbose and not warn_only:
        if passes:
            print("PASSED CHECKS:")
            print("-" * 70)
            for r in passes:
                print(f"[PASS] {r['param']} = {r['current']}")
            print()

        if skipped:
            print("SKIPPED (parameter not found or unreadable):")
            print("-" * 70)
            for r in skipped:
                reason = r['current'] if r['current'] else 'not found'
                print(f"[SKIP] {r['param']} ({reason})")
            print()

    if not warn_only:
        if summary['failed'] == 0:
            print("Status: OK - All checked parameters meet recommendations")
        else:
            print(f"Status: FAIL - {summary['failed']} parameter(s) need attention")


def output_json(audit_result):
    """Output results in JSON format"""
    print(json.dumps(audit_result, indent=2))


def output_table(audit_result, warn_only=False):
    """Output results in table format"""
    results = audit_result['results']

    if warn_only:
        results = [r for r in results if r['status'] == 'fail']

    if not results:
        print("No issues found" if warn_only else "All parameters pass")
        return

    print(f"{'Status':<8} {'Parameter':<45} {'Current':<15} {'Expected':<15}")
    print("=" * 85)

    for r in sorted(results, key=lambda x: (x['status'] != 'fail', x['param'])):
        status = r['status'].upper()[:8]
        param = r['param'][:45]
        current = str(r['current'])[:15] if r['current'] else 'N/A'
        expected = str(r['expected'])[:15]

        print(f"{status:<8} {param:<45} {current:<15} {expected:<15}")


def get_fix_commands(audit_result):
    """Generate sysctl commands to fix failed parameters"""
    commands = []
    for r in audit_result['results']:
        if r['status'] == 'fail':
            commands.append(f"sysctl -w {r['param']}={r['expected']}")
    return commands


def main():
    parser = argparse.ArgumentParser(
        description='Audit kernel runtime configuration against baselines',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles:
  security     - Security hardening settings (network, kernel, filesystem)
  performance  - High-performance server tuning (TCP, memory, limits)
  balanced     - Combined security and performance (default)
  custom       - Load from external file (use --baseline-file)

Examples:
  %(prog)s                         # Audit with balanced profile
  %(prog)s --profile security      # Security-focused audit
  %(prog)s --profile performance   # Performance-focused audit
  %(prog)s --baseline-file my.json # Custom baseline
  %(prog)s --format json           # JSON output for automation
  %(prog)s --show-fixes            # Show commands to fix issues

Custom baseline file format (JSON):
  {
    "net.ipv4.tcp_syncookies": {"value": "1", "comparison": "eq", "description": "..."},
    "vm.swappiness": {"value": "10", "comparison": "le"},
    "fs.file-max": "2097152"
  }

Exit codes:
  0 - All parameters pass
  1 - One or more parameters fail
  2 - Usage or configuration error
        """
    )

    parser.add_argument(
        '--profile',
        choices=['security', 'performance', 'balanced', 'custom'],
        default='balanced',
        help='Configuration profile to audit against (default: %(default)s)'
    )

    parser.add_argument(
        '--baseline-file',
        help='Path to custom baseline file (JSON or YAML)'
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
        help='Show all parameters including passed and skipped'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show failed parameters'
    )

    parser.add_argument(
        '--show-fixes',
        action='store_true',
        help='Show sysctl commands to fix failed parameters'
    )

    parser.add_argument(
        '--param',
        action='append',
        help='Check only specific parameter(s). Can be specified multiple times.'
    )

    args = parser.parse_args()

    # Check for Linux
    if not os.path.exists('/proc/sys'):
        print("Error: /proc/sys not found - requires Linux", file=sys.stderr)
        sys.exit(2)

    # Select baseline
    if args.profile == 'custom':
        if not args.baseline_file:
            print("Error: --baseline-file required with --profile custom",
                  file=sys.stderr)
            sys.exit(2)
        baseline = load_custom_baseline(args.baseline_file)
    elif args.baseline_file:
        baseline = load_custom_baseline(args.baseline_file)
    elif args.profile == 'security':
        baseline = SECURITY_BASELINE
    elif args.profile == 'performance':
        baseline = PERFORMANCE_BASELINE
    else:  # balanced
        baseline = BALANCED_BASELINE

    # Filter to specific params if requested
    if args.param:
        filtered = {}
        for p in args.param:
            if p in baseline:
                filtered[p] = baseline[p]
            else:
                print(f"Warning: Parameter '{p}' not in baseline", file=sys.stderr)
        if filtered:
            baseline = filtered
        else:
            print("Error: No valid parameters to check", file=sys.stderr)
            sys.exit(2)

    # Run audit
    audit_result = audit_baseline(baseline, verbose=args.verbose)

    # Output results
    if args.format == 'json':
        output_json(audit_result)
    elif args.format == 'table':
        output_table(audit_result, warn_only=args.warn_only)
    else:
        output_plain(audit_result, warn_only=args.warn_only, verbose=args.verbose)

    # Show fix commands if requested
    if args.show_fixes and audit_result['summary']['failed'] > 0:
        print()
        print("Commands to fix failed parameters:")
        print("-" * 50)
        for cmd in get_fix_commands(audit_result):
            print(f"  sudo {cmd}")
        print()
        print("To persist changes, add to /etc/sysctl.d/99-custom.conf")

    # Exit based on failures
    sys.exit(1 if audit_result['summary']['failed'] > 0 else 0)


if __name__ == '__main__':
    main()

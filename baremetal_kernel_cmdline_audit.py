#!/usr/bin/env python3
"""
Kernel Command Line Parameter Audit

Audits kernel boot parameters from /proc/cmdline for security best practices,
performance tuning, and common misconfigurations. Useful for ensuring consistent
kernel configurations across large baremetal server fleets.

Checks include:
- Security hardening (IOMMU, KPTI, KASLR, spectre/meltdown mitigations)
- Performance tuning (hugepages, NUMA, I/O scheduler)
- Debug options that should be disabled in production
- Known problematic or deprecated parameters
- Custom baseline comparison for fleet consistency

Exit codes:
    0 - All parameters pass audit (or info-only findings)
    1 - Warnings or issues detected
    2 - Usage error or /proc/cmdline not available

Examples:
    # Run security audit with default checks
    baremetal_kernel_cmdline_audit.py

    # Show only warnings and errors
    baremetal_kernel_cmdline_audit.py --warn-only

    # JSON output for monitoring integration
    baremetal_kernel_cmdline_audit.py --format json

    # Compare against a baseline file
    baremetal_kernel_cmdline_audit.py --baseline /etc/kernel-baseline.conf

    # Save current parameters as baseline
    baremetal_kernel_cmdline_audit.py --save /etc/kernel-baseline.conf
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Any, Optional, Tuple


# Security-related parameter checks
SECURITY_CHECKS = {
    # IOMMU for DMA protection
    'iommu': {
        'description': 'IOMMU for DMA attack protection',
        'recommended': ['on', 'force'],
        'severity': 'WARNING',
        'recommendation': 'Enable with iommu=on or intel_iommu=on/amd_iommu=on',
    },
    'intel_iommu': {
        'description': 'Intel IOMMU/VT-d for DMA protection',
        'recommended': ['on'],
        'severity': 'WARNING',
        'recommendation': 'Enable with intel_iommu=on for Intel systems',
    },
    'amd_iommu': {
        'description': 'AMD IOMMU for DMA protection',
        'recommended': ['on'],
        'severity': 'WARNING',
        'recommendation': 'Enable with amd_iommu=on for AMD systems',
    },
    # CPU vulnerability mitigations
    'mitigations': {
        'description': 'CPU vulnerability mitigations',
        'bad_values': ['off'],
        'severity': 'CRITICAL',
        'recommendation': 'Do not disable CPU mitigations in production',
    },
    'spectre_v2': {
        'description': 'Spectre v2 mitigation',
        'bad_values': ['off'],
        'severity': 'CRITICAL',
        'recommendation': 'Do not disable Spectre mitigations',
    },
    'spec_store_bypass_disable': {
        'description': 'Speculative Store Bypass mitigation',
        'bad_values': ['off'],
        'severity': 'WARNING',
        'recommendation': 'Consider enabling for security-sensitive workloads',
    },
    'pti': {
        'description': 'Page Table Isolation (Meltdown mitigation)',
        'bad_values': ['off'],
        'severity': 'CRITICAL',
        'recommendation': 'Do not disable PTI/KPTI in production',
    },
    'kpti': {
        'description': 'Kernel Page Table Isolation',
        'bad_values': ['off', '0'],
        'severity': 'CRITICAL',
        'recommendation': 'Do not disable KPTI in production',
    },
    # KASLR
    'nokaslr': {
        'description': 'KASLR disabled',
        'presence_is_bad': True,
        'severity': 'WARNING',
        'recommendation': 'Remove nokaslr to enable kernel address randomization',
    },
    # Security modules
    'selinux': {
        'description': 'SELinux security module',
        'bad_values': ['0'],
        'severity': 'INFO',
        'recommendation': 'Consider enabling SELinux for mandatory access control',
    },
    'apparmor': {
        'description': 'AppArmor security module',
        'bad_values': ['0'],
        'severity': 'INFO',
        'recommendation': 'Consider enabling AppArmor for mandatory access control',
    },
}

# Debug parameters that should not be in production
DEBUG_PARAMS = {
    'debug': {
        'description': 'Kernel debug mode',
        'presence_is_bad': True,
        'severity': 'WARNING',
        'recommendation': 'Remove debug parameter in production',
    },
    'ignore_loglevel': {
        'description': 'Ignore log level (verbose logging)',
        'presence_is_bad': True,
        'severity': 'INFO',
        'recommendation': 'Consider removing for production',
    },
    'initcall_debug': {
        'description': 'Init call debugging',
        'presence_is_bad': True,
        'severity': 'WARNING',
        'recommendation': 'Remove initcall_debug in production',
    },
    'earlyprintk': {
        'description': 'Early printk debugging',
        'presence_is_bad': True,
        'severity': 'INFO',
        'recommendation': 'Consider removing unless needed for boot debugging',
    },
    'norandmaps': {
        'description': 'Disable ASLR for user processes',
        'presence_is_bad': True,
        'severity': 'WARNING',
        'recommendation': 'Remove norandmaps to enable ASLR',
    },
}

# Performance-related parameters
PERFORMANCE_CHECKS = {
    'transparent_hugepage': {
        'description': 'Transparent Huge Pages',
        'info_values': ['never', 'madvise', 'always'],
        'severity': 'INFO',
        'recommendation': 'THP=never often recommended for databases; THP=madvise for mixed workloads',
    },
    'elevator': {
        'description': 'I/O scheduler',
        'info_values': ['noop', 'deadline', 'cfq', 'mq-deadline', 'none', 'bfq', 'kyber'],
        'severity': 'INFO',
        'recommendation': 'Consider mq-deadline for SSDs, bfq for interactive workloads',
    },
    'numa_balancing': {
        'description': 'NUMA memory balancing',
        'info_values': ['enable', 'disable'],
        'severity': 'INFO',
        'recommendation': 'Disable for latency-sensitive workloads with pinned processes',
    },
    'nohz': {
        'description': 'Tickless kernel',
        'info_values': ['on', 'off'],
        'severity': 'INFO',
        'recommendation': 'nohz=on reduces CPU overhead on idle cores',
    },
    'isolcpus': {
        'description': 'Isolated CPUs for dedicated workloads',
        'severity': 'INFO',
        'recommendation': 'Useful for real-time or latency-sensitive applications',
    },
    'nohz_full': {
        'description': 'Full tickless CPUs',
        'severity': 'INFO',
        'recommendation': 'Reduces interrupts on specified CPUs for latency-sensitive workloads',
    },
    'rcu_nocbs': {
        'description': 'RCU callback offloading',
        'severity': 'INFO',
        'recommendation': 'Offloads RCU callbacks from specified CPUs',
    },
}

# Memory-related parameters
MEMORY_CHECKS = {
    'mem': {
        'description': 'Memory limit',
        'severity': 'WARNING',
        'recommendation': 'Artificial memory limit may cause issues',
    },
    'memmap': {
        'description': 'Memory mapping override',
        'severity': 'INFO',
        'recommendation': 'Custom memory mapping in use',
    },
    'hugepagesz': {
        'description': 'Huge page size',
        'severity': 'INFO',
        'recommendation': 'Custom huge page size configured',
    },
    'hugepages': {
        'description': 'Number of huge pages',
        'severity': 'INFO',
        'recommendation': 'Pre-allocated huge pages configured',
    },
    'default_hugepagesz': {
        'description': 'Default huge page size',
        'severity': 'INFO',
        'recommendation': 'Default huge page size configured',
    },
}


def read_cmdline() -> str:
    """Read kernel command line from /proc/cmdline."""
    try:
        with open('/proc/cmdline', 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        print("Error: /proc/cmdline not found", file=sys.stderr)
        print("This tool requires a Linux system with /proc filesystem", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/cmdline", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading /proc/cmdline: {e}", file=sys.stderr)
        sys.exit(2)


def parse_cmdline(cmdline: str) -> Dict[str, Optional[str]]:
    """Parse kernel command line into parameter dictionary.

    Returns dict where keys are parameter names and values are:
    - The parameter value if param=value format
    - None if parameter is a flag without value
    """
    params = {}

    # Handle quoted values and complex parameters
    tokens = cmdline.split()

    for token in tokens:
        if '=' in token:
            # Split on first = only (value might contain =)
            key, value = token.split('=', 1)
            params[key] = value
        else:
            # Flag-style parameter
            params[token] = None

    return params


def check_security(params: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    """Check security-related parameters."""
    findings = []

    for param, check in SECURITY_CHECKS.items():
        value = params.get(param)
        finding = None

        if check.get('presence_is_bad') and param in params:
            finding = {
                'parameter': param,
                'value': value,
                'category': 'security',
                'severity': check['severity'],
                'description': check['description'],
                'issue': 'Parameter should not be present',
                'recommendation': check['recommendation'],
            }
        elif 'bad_values' in check and value in check['bad_values']:
            finding = {
                'parameter': param,
                'value': value,
                'category': 'security',
                'severity': check['severity'],
                'description': check['description'],
                'issue': f'Insecure value: {value}',
                'recommendation': check['recommendation'],
            }
        elif 'recommended' in check and param not in params:
            # Only report missing recommended params as INFO
            finding = {
                'parameter': param,
                'value': None,
                'category': 'security',
                'severity': 'INFO',
                'description': check['description'],
                'issue': 'Recommended parameter not present',
                'recommendation': check['recommendation'],
            }

        if finding:
            findings.append(finding)

    return findings


def check_debug(params: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    """Check for debug parameters that shouldn't be in production."""
    findings = []

    for param, check in DEBUG_PARAMS.items():
        if param in params:
            findings.append({
                'parameter': param,
                'value': params.get(param),
                'category': 'debug',
                'severity': check['severity'],
                'description': check['description'],
                'issue': 'Debug parameter present',
                'recommendation': check['recommendation'],
            })

    return findings


def check_performance(params: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    """Check performance-related parameters (informational)."""
    findings = []

    for param, check in PERFORMANCE_CHECKS.items():
        if param in params:
            findings.append({
                'parameter': param,
                'value': params.get(param),
                'category': 'performance',
                'severity': check['severity'],
                'description': check['description'],
                'issue': 'Performance tuning parameter',
                'recommendation': check['recommendation'],
            })

    return findings


def check_memory(params: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    """Check memory-related parameters."""
    findings = []

    for param, check in MEMORY_CHECKS.items():
        if param in params:
            findings.append({
                'parameter': param,
                'value': params.get(param),
                'category': 'memory',
                'severity': check['severity'],
                'description': check['description'],
                'issue': 'Memory configuration parameter',
                'recommendation': check['recommendation'],
            })

    return findings


def load_baseline(filepath: str) -> Dict[str, Optional[str]]:
    """Load baseline parameters from file."""
    if not os.path.exists(filepath):
        print(f"Error: Baseline file not found: {filepath}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(filepath, 'r') as f:
            content = f.read().strip()
            # Baseline file contains cmdline format
            return parse_cmdline(content)
    except Exception as e:
        print(f"Error reading baseline file: {e}", file=sys.stderr)
        sys.exit(2)


def save_baseline(filepath: str, cmdline: str) -> bool:
    """Save current cmdline as baseline."""
    try:
        with open(filepath, 'w') as f:
            f.write(f"# Kernel cmdline baseline\n")
            f.write(f"# Generated by baremetal_kernel_cmdline_audit.py\n")
            f.write(cmdline)
            f.write("\n")
        print(f"Baseline saved to: {filepath}")
        return True
    except Exception as e:
        print(f"Error saving baseline: {e}", file=sys.stderr)
        return False


def compare_baseline(current: Dict[str, Optional[str]],
                     baseline: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    """Compare current parameters against baseline."""
    findings = []

    # Parameters in baseline but not in current
    for param, expected in baseline.items():
        if param not in current:
            findings.append({
                'parameter': param,
                'value': None,
                'expected': expected,
                'category': 'baseline',
                'severity': 'WARNING',
                'description': 'Missing from baseline',
                'issue': f'Expected parameter not present',
                'recommendation': f'Add {param}={expected}' if expected else f'Add {param}',
            })
        elif current[param] != expected:
            findings.append({
                'parameter': param,
                'value': current[param],
                'expected': expected,
                'category': 'baseline',
                'severity': 'WARNING',
                'description': 'Value differs from baseline',
                'issue': f'Expected {expected}, got {current[param]}',
                'recommendation': f'Change to {param}={expected}' if expected else f'Check {param}',
            })

    # Parameters in current but not in baseline
    for param, value in current.items():
        if param not in baseline:
            findings.append({
                'parameter': param,
                'value': value,
                'expected': None,
                'category': 'baseline',
                'severity': 'INFO',
                'description': 'Extra parameter not in baseline',
                'issue': 'Parameter not in baseline',
                'recommendation': 'Verify this parameter is intended',
            })

    return findings


def output_plain(cmdline: str, params: Dict[str, Optional[str]],
                 findings: List[Dict[str, Any]], verbose: bool,
                 warn_only: bool) -> None:
    """Output results in plain text format."""
    if not warn_only:
        print("Kernel Command Line Audit")
        print("=" * 70)
        print()

        if verbose:
            print(f"Full cmdline: {cmdline}")
            print()
            print(f"Total parameters: {len(params)}")
            print()

    # Group findings by severity
    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    warnings = [f for f in findings if f['severity'] == 'WARNING']
    info = [f for f in findings if f['severity'] == 'INFO']

    if critical:
        print("CRITICAL ISSUES:")
        print("-" * 70)
        for f in critical:
            value_str = f'={f["value"]}' if f['value'] else ''
            print(f"  !!! {f['parameter']}{value_str}")
            print(f"      {f['description']}: {f['issue']}")
            if verbose:
                print(f"      Recommendation: {f['recommendation']}")
        print()

    if warnings:
        print("WARNINGS:")
        print("-" * 70)
        for f in warnings:
            value_str = f'={f["value"]}' if f['value'] else ''
            print(f"  !   {f['parameter']}{value_str}")
            print(f"      {f['description']}: {f['issue']}")
            if verbose:
                print(f"      Recommendation: {f['recommendation']}")
        print()

    if info and not warn_only:
        print("INFORMATIONAL:")
        print("-" * 70)
        for f in info:
            value_str = f'={f["value"]}' if f['value'] else ''
            print(f"  i   {f['parameter']}{value_str}")
            print(f"      {f['description']}")
            if verbose:
                print(f"      Note: {f['recommendation']}")
        print()

    # Summary
    if not warn_only:
        print("SUMMARY:")
        print("-" * 70)
        print(f"  Critical: {len(critical)}")
        print(f"  Warnings: {len(warnings)}")
        print(f"  Info:     {len(info)}")

    if not findings:
        print("No issues detected.")


def output_json(cmdline: str, params: Dict[str, Optional[str]],
                findings: List[Dict[str, Any]]) -> None:
    """Output results in JSON format."""
    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    warnings = [f for f in findings if f['severity'] == 'WARNING']
    info = [f for f in findings if f['severity'] == 'INFO']

    output = {
        'cmdline': cmdline,
        'parameter_count': len(params),
        'parameters': {k: v for k, v in params.items()},
        'summary': {
            'critical': len(critical),
            'warning': len(warnings),
            'info': len(info),
            'total': len(findings),
        },
        'findings': findings,
    }

    print(json.dumps(output, indent=2, default=str))


def output_table(cmdline: str, params: Dict[str, Optional[str]],
                 findings: List[Dict[str, Any]], warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only:
        findings = [f for f in findings if f['severity'] in ['CRITICAL', 'WARNING']]

    print(f"{'SEVERITY':<10} {'CATEGORY':<12} {'PARAMETER':<25} {'ISSUE':<30}")
    print("=" * 80)

    for f in findings:
        param_str = f['parameter']
        if f['value']:
            param_str = f"{f['parameter']}={f['value']}"
        if len(param_str) > 25:
            param_str = param_str[:22] + '...'

        issue = f['issue']
        if len(issue) > 30:
            issue = issue[:27] + '...'

        print(f"{f['severity']:<10} {f['category']:<12} {param_str:<25} {issue:<30}")

    print()
    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    warnings = sum(1 for f in findings if f['severity'] == 'WARNING')
    print(f"Total: {len(findings)} findings | Critical: {critical} | Warnings: {warnings}")


def main():
    parser = argparse.ArgumentParser(
        description='Audit kernel command line parameters for security and best practices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Run default audit
  %(prog)s --warn-only               # Show only warnings and critical
  %(prog)s --format json             # JSON output for automation
  %(prog)s --baseline /etc/baseline  # Compare against baseline
  %(prog)s --save /etc/baseline      # Save current as baseline
  %(prog)s -v                        # Verbose with recommendations

Exit codes:
  0 - No critical or warning findings
  1 - Critical or warning findings detected
  2 - Usage error or system error
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
        help='Show detailed recommendations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and critical issues'
    )

    parser.add_argument(
        '--baseline',
        metavar='FILE',
        help='Compare against baseline file'
    )

    parser.add_argument(
        '--save',
        metavar='FILE',
        help='Save current parameters as baseline'
    )

    parser.add_argument(
        '--skip-security',
        action='store_true',
        help='Skip security checks'
    )

    parser.add_argument(
        '--skip-debug',
        action='store_true',
        help='Skip debug parameter checks'
    )

    parser.add_argument(
        '--skip-performance',
        action='store_true',
        help='Skip performance parameter checks'
    )

    args = parser.parse_args()

    # Read current cmdline
    cmdline = read_cmdline()
    params = parse_cmdline(cmdline)

    # Handle save baseline
    if args.save:
        if save_baseline(args.save, cmdline):
            sys.exit(0)
        else:
            sys.exit(1)

    # Collect findings
    findings = []

    if not args.skip_security:
        findings.extend(check_security(params))

    if not args.skip_debug:
        findings.extend(check_debug(params))

    if not args.skip_performance:
        findings.extend(check_performance(params))

    findings.extend(check_memory(params))

    # Baseline comparison
    if args.baseline:
        baseline = load_baseline(args.baseline)
        findings.extend(compare_baseline(params, baseline))

    # Sort by severity
    severity_order = {'CRITICAL': 0, 'WARNING': 1, 'INFO': 2}
    findings.sort(key=lambda x: (severity_order.get(x['severity'], 3), x['parameter']))

    # Output
    if args.format == 'json':
        output_json(cmdline, params, findings)
    elif args.format == 'table':
        output_table(cmdline, params, findings, args.warn_only)
    else:
        output_plain(cmdline, params, findings, args.verbose, args.warn_only)

    # Exit code based on findings
    has_issues = any(f['severity'] in ['CRITICAL', 'WARNING'] for f in findings)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()

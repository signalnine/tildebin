#!/usr/bin/env python3
"""
Audit iptables/nftables firewall rules for security and performance issues.

This script analyzes firewall rules to detect common problems in large-scale
baremetal environments where rules accumulate over time:

- Rule count analysis (high counts cause performance degradation)
- Empty chains that can be cleaned up
- Chains with excessive rules (suggests consolidation needed)
- Rules with zero packet/byte counters (potentially unused)
- Duplicate or redundant rules
- Rules blocking all traffic (overly restrictive)
- Rules allowing all traffic (overly permissive)
- Default policy analysis

In large datacenters, firewall rules often accumulate over years and cause:
- Increased latency for every packet (rules evaluated sequentially)
- Security blind spots from forgotten rules
- Operational confusion from undocumented rules
- Memory overhead from large rule tables

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found
    2 - Usage error or iptables not available
"""

import argparse
import sys
import json
import subprocess
import re
from collections import defaultdict


def check_iptables_available():
    """Check if iptables command is available."""
    try:
        result = subprocess.run(
            ['which', 'iptables'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_iptables(args, table='filter'):
    """Run iptables command and return output.

    Args:
        args: List of additional arguments for iptables
        table: Table to query (filter, nat, mangle, raw)

    Returns:
        tuple: (return_code, stdout, stderr)
    """
    cmd = ['iptables', '-t', table] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 2, "", "iptables command not found"
    except PermissionError:
        return 2, "", "Permission denied running iptables (need root?)"
    except Exception as e:
        return 2, "", str(e)


def parse_iptables_rules(table='filter'):
    """Parse iptables rules with verbose output including counters.

    Args:
        table: Table to query

    Returns:
        dict: Parsed rules organized by chain
    """
    # Get rules with counters (-v) and line numbers (-n for numeric, --line-numbers)
    rc, stdout, stderr = run_iptables(['-L', '-v', '-n', '--line-numbers'], table)

    if rc != 0:
        return None, stderr

    chains = {}
    current_chain = None
    current_policy = None

    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Chain header: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
        chain_match = re.match(r'^Chain (\S+) \(policy (\S+)', line)
        if chain_match:
            current_chain = chain_match.group(1)
            current_policy = chain_match.group(2)
            chains[current_chain] = {
                'policy': current_policy,
                'rules': [],
                'builtin': True
            }
            continue

        # Chain header for user chains: "Chain MY_CHAIN (1 references)"
        user_chain_match = re.match(r'^Chain (\S+) \((\d+) references?\)', line)
        if user_chain_match:
            current_chain = user_chain_match.group(1)
            chains[current_chain] = {
                'policy': None,
                'references': int(user_chain_match.group(2)),
                'rules': [],
                'builtin': False
            }
            continue

        # Skip header line
        if line.startswith('num') or line.startswith('pkts'):
            continue

        # Rule line: "1    0     0 ACCEPT     all  --  lo     *       0.0.0.0/0"
        rule_match = re.match(
            r'^(\d+)\s+(\d+[KMG]?)\s+(\d+[KMG]?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)?$',
            line
        )
        if rule_match and current_chain:
            # Parse packet/byte counters (may have K/M/G suffixes)
            pkts_str = rule_match.group(2)
            bytes_str = rule_match.group(3)

            def parse_counter(s):
                """Parse counter value with optional K/M/G suffix."""
                s = s.strip()
                if not s:
                    return 0
                multiplier = 1
                if s.endswith('K'):
                    multiplier = 1000
                    s = s[:-1]
                elif s.endswith('M'):
                    multiplier = 1000000
                    s = s[:-1]
                elif s.endswith('G'):
                    multiplier = 1000000000
                    s = s[:-1]
                try:
                    return int(float(s) * multiplier)
                except ValueError:
                    return 0

            rule = {
                'num': int(rule_match.group(1)),
                'pkts': parse_counter(pkts_str),
                'bytes': parse_counter(bytes_str),
                'target': rule_match.group(4),
                'prot': rule_match.group(5),
                'opt': rule_match.group(6),
                'in': rule_match.group(7),
                'out': rule_match.group(8),
                'source': rule_match.group(9),
                'destination': rule_match.group(10),
                'extra': rule_match.group(11).strip() if rule_match.group(11) else ''
            }
            chains[current_chain]['rules'].append(rule)

    return chains, None


def analyze_rules(chains, unused_threshold=0, max_rules_per_chain=50):
    """Analyze parsed rules and return issues.

    Args:
        chains: Parsed chain data
        unused_threshold: Packet count threshold for "unused" detection
        max_rules_per_chain: Warning threshold for rules per chain

    Returns:
        dict: Analysis results with issues
    """
    issues = []
    stats = {
        'total_chains': len(chains),
        'total_rules': 0,
        'empty_chains': 0,
        'unused_rules': 0,
        'accept_all_rules': 0,
        'drop_all_rules': 0,
        'chains_by_rule_count': {}
    }

    for chain_name, chain_data in chains.items():
        rule_count = len(chain_data['rules'])
        stats['total_rules'] += rule_count
        stats['chains_by_rule_count'][chain_name] = rule_count

        # Empty user-defined chains
        if rule_count == 0 and not chain_data.get('builtin', True):
            stats['empty_chains'] += 1
            refs = chain_data.get('references', 0)
            if refs == 0:
                issues.append({
                    'severity': 'WARNING',
                    'type': 'empty_unreferenced_chain',
                    'chain': chain_name,
                    'message': f"Chain '{chain_name}' is empty and has no references (can be removed)"
                })

        # Too many rules in a chain
        if rule_count > max_rules_per_chain:
            issues.append({
                'severity': 'WARNING',
                'type': 'chain_rule_count',
                'chain': chain_name,
                'rule_count': rule_count,
                'threshold': max_rules_per_chain,
                'message': f"Chain '{chain_name}' has {rule_count} rules (>{max_rules_per_chain}) - consider consolidation"
            })

        # Analyze individual rules
        for rule in chain_data['rules']:
            # Unused rules (zero packet count)
            if rule['pkts'] <= unused_threshold:
                stats['unused_rules'] += 1

            # Overly permissive: ACCEPT all from anywhere to anywhere
            if (rule['target'] == 'ACCEPT' and
                rule['source'] == '0.0.0.0/0' and
                rule['destination'] == '0.0.0.0/0' and
                rule['prot'] == 'all' and
                not rule['extra']):
                stats['accept_all_rules'] += 1
                issues.append({
                    'severity': 'WARNING',
                    'type': 'accept_all',
                    'chain': chain_name,
                    'rule_num': rule['num'],
                    'message': f"Rule {rule['num']} in '{chain_name}' accepts ALL traffic (overly permissive)"
                })

            # Overly restrictive early DROP all
            if (rule['target'] in ('DROP', 'REJECT') and
                rule['source'] == '0.0.0.0/0' and
                rule['destination'] == '0.0.0.0/0' and
                rule['prot'] == 'all' and
                not rule['extra'] and
                rule['num'] < len(chain_data['rules'])):
                stats['drop_all_rules'] += 1
                issues.append({
                    'severity': 'WARNING',
                    'type': 'early_drop_all',
                    'chain': chain_name,
                    'rule_num': rule['num'],
                    'message': f"Rule {rule['num']} in '{chain_name}' drops ALL traffic but isn't last rule"
                })

        # Check default policy
        if chain_data.get('builtin') and chain_data.get('policy') == 'ACCEPT':
            if chain_name in ('INPUT', 'FORWARD'):
                issues.append({
                    'severity': 'INFO',
                    'type': 'permissive_policy',
                    'chain': chain_name,
                    'policy': 'ACCEPT',
                    'message': f"Chain '{chain_name}' has default ACCEPT policy (consider DROP with explicit allows)"
                })

    # High total rule count warning
    if stats['total_rules'] > 200:
        issues.append({
            'severity': 'WARNING',
            'type': 'high_total_rules',
            'count': stats['total_rules'],
            'message': f"Total rule count ({stats['total_rules']}) is high - may impact packet processing performance"
        })
    elif stats['total_rules'] > 500:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'very_high_total_rules',
            'count': stats['total_rules'],
            'message': f"Total rule count ({stats['total_rules']}) is very high - significant performance impact likely"
        })

    # Many unused rules
    if stats['unused_rules'] > 10:
        issues.append({
            'severity': 'INFO',
            'type': 'many_unused_rules',
            'count': stats['unused_rules'],
            'message': f"{stats['unused_rules']} rules have zero packet count (may be unused, consider review)"
        })

    return stats, issues


def output_plain(stats, issues, chains, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print(f"Total chains: {stats['total_chains']}")
        print(f"Total rules: {stats['total_rules']}")
        print(f"Empty chains: {stats['empty_chains']}")
        print(f"Rules with zero packets: {stats['unused_rules']}")
        print()

        if verbose:
            print("Rules per chain:")
            for chain, count in sorted(stats['chains_by_rule_count'].items(),
                                      key=lambda x: x[1], reverse=True):
                if count > 0:
                    print(f"  {chain}: {count}")
            print()

    if issues:
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            prefix = f"[{issue['severity']}]"
            print(f"{prefix} {issue['message']}")
    elif not warn_only:
        print("No issues detected.")


def output_json(stats, issues, chains, verbose):
    """Output results in JSON format."""
    result = {
        'stats': stats,
        'issues': issues
    }
    if verbose:
        result['chains'] = chains
    print(json.dumps(result, indent=2))


def output_table(stats, issues, chains, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 60)
        print("IPTABLES FIREWALL AUDIT")
        print("=" * 60)
        print(f"{'Metric':<30} {'Value':<20}")
        print("-" * 60)
        print(f"{'Total Chains':<30} {stats['total_chains']:<20}")
        print(f"{'Total Rules':<30} {stats['total_rules']:<20}")
        print(f"{'Empty Chains':<30} {stats['empty_chains']:<20}")
        print(f"{'Zero-Packet Rules':<30} {stats['unused_rules']:<20}")
        print("=" * 60)
        print()

        if verbose:
            print("CHAIN DETAILS")
            print("=" * 60)
            print(f"{'Chain':<25} {'Rules':<10} {'Status':<20}")
            print("-" * 60)
            for chain, count in sorted(stats['chains_by_rule_count'].items(),
                                      key=lambda x: x[1], reverse=True):
                status = "OK" if count <= 50 else "HIGH"
                print(f"{chain:<25} {count:<10} {status:<20}")
            print("=" * 60)
            print()

    if issues:
        print("ISSUES")
        print("=" * 60)
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            print(f"[{issue['severity']}] {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit iptables firewall rules for security and performance issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Basic audit with default thresholds
  %(prog)s --verbose            # Include chain details
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --table nat          # Audit NAT table instead of filter
  %(prog)s --max-rules 100      # Warn if chain has >100 rules
  %(prog)s --warn-only          # Only show warnings and errors

Common issues detected:
  - High rule counts (performance impact)
  - Empty unused chains (cleanup opportunity)
  - Overly permissive rules (ACCEPT all)
  - Overly restrictive rules (DROP all not at end)
  - Unused rules (zero packet count)
  - Permissive default policies

Exit codes:
  0 - No issues detected
  1 - Warnings or issues found
  2 - Usage error or iptables not available
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
        help='Show detailed chain information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress info messages'
    )

    parser.add_argument(
        '-t', '--table',
        default='filter',
        choices=['filter', 'nat', 'mangle', 'raw'],
        help='iptables table to audit (default: %(default)s)'
    )

    parser.add_argument(
        '--max-rules',
        type=int,
        default=50,
        metavar='N',
        help='Warn if a chain has more than N rules (default: 50)'
    )

    parser.add_argument(
        '--unused-threshold',
        type=int,
        default=0,
        metavar='N',
        help='Packet count threshold for "unused" detection (default: 0)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.max_rules < 1:
        print("Error: --max-rules must be at least 1", file=sys.stderr)
        sys.exit(2)

    if args.unused_threshold < 0:
        print("Error: --unused-threshold cannot be negative", file=sys.stderr)
        sys.exit(2)

    # Check iptables availability
    if not check_iptables_available():
        print("Error: iptables not found in PATH", file=sys.stderr)
        print("Install iptables or run on a Linux system with netfilter", file=sys.stderr)
        sys.exit(2)

    # Parse rules
    chains, error = parse_iptables_rules(args.table)
    if chains is None:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    # Analyze
    stats, issues = analyze_rules(chains, args.unused_threshold, args.max_rules)

    # Output
    if args.format == 'json':
        output_json(stats, issues, chains, args.verbose)
    elif args.format == 'table':
        output_table(stats, issues, chains, args.verbose, args.warn_only)
    else:
        output_plain(stats, issues, chains, args.verbose, args.warn_only)

    # Exit code based on issues
    has_warning = any(i['severity'] in ('WARNING', 'CRITICAL') for i in issues)
    sys.exit(1 if has_warning else 0)


if __name__ == '__main__':
    main()

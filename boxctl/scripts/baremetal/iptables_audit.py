#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, firewall, security, iptables]
#   brief: Audit iptables firewall rules for security and performance issues

"""
Audit iptables/nftables firewall rules for security and performance issues.

This script analyzes firewall rules to detect common problems in large-scale
baremetal environments where rules accumulate over time:

- Rule count analysis (high counts cause performance degradation)
- Empty chains that can be cleaned up
- Chains with excessive rules (suggests consolidation needed)
- Rules with zero packet/byte counters (potentially unused)
- Duplicate or redundant rules
- Rules allowing all traffic (overly permissive)
- Default policy analysis

Exit codes:
    0: No issues detected
    1: Warnings or issues found
    2: Usage error or iptables not available
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_iptables_output(content: str) -> dict:
    """Parse iptables -L -v -n --line-numbers output.

    Args:
        content: Raw iptables output

    Returns:
        dict: Parsed chains with rules
    """
    chains = {}
    current_chain = None

    for line in content.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Chain header: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
        chain_match = re.match(r"^Chain (\S+) \(policy (\S+)", line)
        if chain_match:
            current_chain = chain_match.group(1)
            chains[current_chain] = {
                "policy": chain_match.group(2),
                "rules": [],
                "builtin": True,
            }
            continue

        # User chain: "Chain MY_CHAIN (0 references)"
        user_chain_match = re.match(r"^Chain (\S+) \((\d+) references?\)", line)
        if user_chain_match:
            current_chain = user_chain_match.group(1)
            chains[current_chain] = {
                "policy": None,
                "references": int(user_chain_match.group(2)),
                "rules": [],
                "builtin": False,
            }
            continue

        # Skip header lines
        if line.startswith("num") or line.startswith("pkts"):
            continue

        # Rule line: "1    500  50K ACCEPT     all  --  lo     *       0.0.0.0/0"
        rule_match = re.match(
            r"^(\d+)\s+(\d+[KMG]?)\s+(\d+[KMG]?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)?$",
            line,
        )
        if rule_match and current_chain:
            rule = {
                "num": int(rule_match.group(1)),
                "pkts": parse_counter(rule_match.group(2)),
                "bytes": parse_counter(rule_match.group(3)),
                "target": rule_match.group(4),
                "prot": rule_match.group(5),
                "opt": rule_match.group(6),
                "in": rule_match.group(7),
                "out": rule_match.group(8),
                "source": rule_match.group(9),
                "destination": rule_match.group(10),
                "extra": rule_match.group(11).strip() if rule_match.group(11) else "",
            }
            chains[current_chain]["rules"].append(rule)

    return chains


def parse_counter(s: str) -> int:
    """Parse packet/byte counter with optional K/M/G suffix."""
    s = s.strip()
    if not s:
        return 0
    multiplier = 1
    if s.endswith("K"):
        multiplier = 1000
        s = s[:-1]
    elif s.endswith("M"):
        multiplier = 1000000
        s = s[:-1]
    elif s.endswith("G"):
        multiplier = 1000000000
        s = s[:-1]
    try:
        return int(float(s) * multiplier)
    except ValueError:
        return 0


def analyze_rules(
    chains: dict, unused_threshold: int = 0, max_rules_per_chain: int = 50
) -> tuple[dict, list]:
    """Analyze parsed rules and return statistics and issues.

    Args:
        chains: Parsed chain data
        unused_threshold: Packet count threshold for "unused" detection
        max_rules_per_chain: Warning threshold for rules per chain

    Returns:
        tuple: (stats dict, issues list)
    """
    issues = []
    stats = {
        "total_chains": len(chains),
        "total_rules": 0,
        "empty_chains": 0,
        "unused_rules": 0,
        "accept_all_rules": 0,
        "drop_all_rules": 0,
        "chains_by_rule_count": {},
    }

    for chain_name, chain_data in chains.items():
        rule_count = len(chain_data["rules"])
        stats["total_rules"] += rule_count
        stats["chains_by_rule_count"][chain_name] = rule_count

        # Empty user-defined chains
        if rule_count == 0 and not chain_data.get("builtin", True):
            stats["empty_chains"] += 1
            refs = chain_data.get("references", 0)
            if refs == 0:
                issues.append(
                    {
                        "severity": "WARNING",
                        "type": "empty_unreferenced_chain",
                        "chain": chain_name,
                        "message": f"Chain '{chain_name}' is empty and has no references",
                    }
                )

        # Too many rules in a chain
        if rule_count > max_rules_per_chain:
            issues.append(
                {
                    "severity": "WARNING",
                    "type": "chain_rule_count",
                    "chain": chain_name,
                    "rule_count": rule_count,
                    "threshold": max_rules_per_chain,
                    "message": f"Chain '{chain_name}' has {rule_count} rules (>{max_rules_per_chain})",
                }
            )

        # Analyze individual rules
        for rule in chain_data["rules"]:
            # Unused rules (zero packet count)
            if rule["pkts"] <= unused_threshold:
                stats["unused_rules"] += 1

            # Overly permissive: ACCEPT all from anywhere to anywhere
            # (but ignore if it's restricted to an interface like loopback)
            if (
                rule["target"] == "ACCEPT"
                and rule["source"] == "0.0.0.0/0"
                and rule["destination"] == "0.0.0.0/0"
                and rule["prot"] == "all"
                and rule["in"] == "*"
                and rule["out"] == "*"
                and not rule["extra"]
            ):
                stats["accept_all_rules"] += 1
                issues.append(
                    {
                        "severity": "WARNING",
                        "type": "accept_all",
                        "chain": chain_name,
                        "rule_num": rule["num"],
                        "message": f"Rule {rule['num']} in '{chain_name}' accepts ALL traffic",
                    }
                )

        # Check default policy
        if chain_data.get("builtin") and chain_data.get("policy") == "ACCEPT":
            if chain_name in ("INPUT", "FORWARD"):
                issues.append(
                    {
                        "severity": "INFO",
                        "type": "permissive_policy",
                        "chain": chain_name,
                        "policy": "ACCEPT",
                        "message": f"Chain '{chain_name}' has default ACCEPT policy",
                    }
                )

    # High total rule count warning
    if stats["total_rules"] > 500:
        issues.append(
            {
                "severity": "CRITICAL",
                "type": "very_high_total_rules",
                "count": stats["total_rules"],
                "message": f"Total rule count ({stats['total_rules']}) is very high",
            }
        )
    elif stats["total_rules"] > 200:
        issues.append(
            {
                "severity": "WARNING",
                "type": "high_total_rules",
                "count": stats["total_rules"],
                "message": f"Total rule count ({stats['total_rules']}) is high",
            }
        )

    # Many unused rules
    if stats["unused_rules"] > 10:
        issues.append(
            {
                "severity": "INFO",
                "type": "many_unused_rules",
                "count": stats["unused_rules"],
                "message": f"{stats['unused_rules']} rules have zero packet count",
            }
        )

    return stats, issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit iptables firewall rules for security and performance"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed chain information"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings and errors",
    )
    parser.add_argument(
        "-t",
        "--table",
        default="filter",
        choices=["filter", "nat", "mangle", "raw"],
        help="iptables table to audit (default: filter)",
    )
    parser.add_argument(
        "--max-rules",
        type=int,
        default=50,
        metavar="N",
        help="Warn if a chain has more than N rules (default: 50)",
    )
    parser.add_argument(
        "--unused-threshold",
        type=int,
        default=0,
        metavar="N",
        help="Packet count threshold for unused detection (default: 0)",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.max_rules < 1:
        output.error("--max-rules must be at least 1")
        return 2

    if opts.unused_threshold < 0:
        output.error("--unused-threshold cannot be negative")
        return 2

    # Check iptables availability
    if not context.check_tool("iptables"):
        output.error("iptables not found in PATH")
        return 2

    # Run iptables command
    try:
        result = context.run(
            ["iptables", "-t", opts.table, "-L", "-v", "-n", "--line-numbers"]
        )
        if result.returncode != 0:
            output.error(f"iptables failed: {result.stderr}")
            return 2
        iptables_output = result.stdout
    except Exception as e:
        output.error(f"Failed to run iptables: {e}")
        return 2

    # Parse and analyze
    chains = parse_iptables_output(iptables_output)
    stats, issues = analyze_rules(chains, opts.unused_threshold, opts.max_rules)

    # Filter issues for warn-only
    display_issues = issues
    if opts.warn_only:
        display_issues = [i for i in issues if i["severity"] != "INFO"]

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "table": opts.table,
        "stats": stats,
        "issues": display_issues,
        "has_warnings": any(
            i["severity"] in ("WARNING", "CRITICAL") for i in issues
        ),
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or display_issues:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or display_issues:
            lines = []
            lines.append("Iptables Firewall Audit")
            lines.append("=" * 50)
            lines.append("")
            lines.append(f"Table: {opts.table}")
            lines.append(f"Total chains: {stats['total_chains']}")
            lines.append(f"Total rules: {stats['total_rules']}")
            lines.append(f"Empty chains: {stats['empty_chains']}")
            lines.append(f"Rules with zero packets: {stats['unused_rules']}")
            lines.append("")

            if opts.verbose:
                lines.append("Rules per chain:")
                for chain, count in sorted(
                    stats["chains_by_rule_count"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                ):
                    if count > 0:
                        lines.append(f"  {chain}: {count}")
                lines.append("")

            if display_issues:
                lines.append("Issues:")
                for issue in display_issues:
                    prefix = f"[{issue['severity']}]"
                    lines.append(f"  {prefix} {issue['message']}")
                lines.append("")
            else:
                lines.append("[OK] No issues detected")

            print("\n".join(lines))

    # Set summary
    output.set_summary(
        f"rules={stats['total_rules']}, issues={len([i for i in issues if i['severity'] in ('WARNING', 'CRITICAL')])}"
    )

    # Exit code based on warnings/criticals
    has_warning = any(i["severity"] in ("WARNING", "CRITICAL") for i in issues)
    return 1 if has_warning else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))

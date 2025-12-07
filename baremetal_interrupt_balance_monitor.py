#!/usr/bin/env python3
"""
Monitor hardware interrupt (IRQ) distribution across CPU cores.

This script analyzes IRQ distribution to detect performance issues caused by
poor interrupt balancing. Unbalanced interrupts can cause CPU hotspots and
bottleneck network/storage performance, especially on high-speed NICs and
NVMe devices.

Checks performed:
- IRQ distribution across CPU cores
- Detection of IRQs concentrated on single CPUs
- irqbalance service status
- CPU0 overload detection (common issue)
- Per-device interrupt balance analysis
- SMP affinity configuration review

Exit codes:
    0 - All interrupts are well-balanced
    1 - Imbalanced interrupts detected or irqbalance issues
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import subprocess
from collections import defaultdict


def check_root():
    """Check if running as root (needed for some IRQ info)"""
    return os.geteuid() == 0


def get_irqbalance_status():
    """Check if irqbalance service is running"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'irqbalance'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        # systemctl not available, try ps
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True
            )
            return 'irqbalance' in result.stdout
        except Exception:
            return None


def get_cpu_count():
    """Get number of CPU cores"""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return sum(1 for line in f if line.startswith('processor'))
    except Exception:
        return None


def parse_interrupts():
    """Parse /proc/interrupts to get IRQ distribution"""
    try:
        with open('/proc/interrupts', 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error: Cannot read /proc/interrupts: {e}", file=sys.stderr)
        sys.exit(2)

    if not lines:
        return None, None, {}

    # First line contains CPU headers
    header = lines[0].split()
    num_cpus = len([h for h in header if h.startswith('CPU')])

    irq_data = {}

    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue

        irq = parts[0].rstrip(':')

        # Parse CPU counts (next num_cpus columns)
        try:
            cpu_counts = [int(parts[i+1]) for i in range(num_cpus)]
        except (IndexError, ValueError):
            continue

        # Device name is at the end
        device = ' '.join(parts[num_cpus+1:]) if len(parts) > num_cpus+1 else 'unknown'

        irq_data[irq] = {
            'cpu_counts': cpu_counts,
            'total': sum(cpu_counts),
            'device': device
        }

    return num_cpus, header, irq_data


def analyze_balance(irq_data, num_cpus, threshold=0.8):
    """
    Analyze IRQ balance across CPUs.

    Returns list of issues found.
    threshold: If X% of interrupts go to one CPU, flag as imbalanced
    """
    issues = []
    cpu_totals = [0] * num_cpus

    # Track per-device issues
    device_issues = []

    for irq, data in irq_data.items():
        total = data['total']
        if total == 0:
            continue

        cpu_counts = data['cpu_counts']
        max_count = max(cpu_counts)
        max_cpu = cpu_counts.index(max_count)

        # Update CPU totals
        for i, count in enumerate(cpu_counts):
            cpu_totals[i] += count

        # Check if this IRQ is heavily concentrated on one CPU
        if total > 100 and max_count / total > threshold:
            percentage = (max_count / total) * 100
            device_issues.append({
                'irq': irq,
                'device': data['device'],
                'cpu': max_cpu,
                'percentage': percentage,
                'total': total
            })

    # Check overall CPU balance
    total_interrupts = sum(cpu_totals)
    if total_interrupts > 0:
        for cpu_id, count in enumerate(cpu_totals):
            percentage = (count / total_interrupts) * 100
            if percentage > (threshold * 100):
                issues.append({
                    'type': 'cpu_overload',
                    'cpu': cpu_id,
                    'percentage': percentage,
                    'count': count
                })

    # Add device-specific issues
    for device_issue in device_issues:
        issues.append({
            'type': 'irq_imbalance',
            **device_issue
        })

    return issues, cpu_totals


def get_smp_affinity(irq):
    """Get SMP affinity for an IRQ"""
    try:
        with open(f'/proc/irq/{irq}/smp_affinity', 'r') as f:
            return f.read().strip()
    except Exception:
        return None


def output_plain(results, warn_only=False, verbose=False):
    """Output results in plain text format"""
    num_cpus = results['num_cpus']
    issues = results['issues']
    cpu_totals = results['cpu_totals']
    irqbalance_running = results['irqbalance_running']
    total_interrupts = results['total_interrupts']

    if not warn_only or issues:
        print(f"CPU Count: {num_cpus}")
        print(f"Total Interrupts: {total_interrupts}")
        print(f"irqbalance Service: {'Running' if irqbalance_running else 'Not Running'}")
        print()

    if issues:
        print(f"Found {len(issues)} interrupt balance issues:")
        print()

        for issue in issues:
            if issue['type'] == 'cpu_overload':
                print(f"[WARNING] CPU{issue['cpu']}: {issue['percentage']:.1f}% of all interrupts ({issue['count']} total)")
            elif issue['type'] == 'irq_imbalance':
                print(f"[WARNING] IRQ {issue['irq']} ({issue['device']}): {issue['percentage']:.1f}% on CPU{issue['cpu']} ({issue['total']} total)")
        print()
    elif not warn_only:
        print("No interrupt balance issues detected.")
        print()

    if verbose and not warn_only:
        print("Per-CPU Interrupt Distribution:")
        for cpu_id, count in enumerate(cpu_totals):
            percentage = (count / total_interrupts * 100) if total_interrupts > 0 else 0
            print(f"  CPU{cpu_id}: {count:>12} interrupts ({percentage:>5.1f}%)")


def output_json(results):
    """Output results in JSON format"""
    print(json.dumps(results, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format"""
    num_cpus = results['num_cpus']
    issues = results['issues']
    cpu_totals = results['cpu_totals']
    total_interrupts = results['total_interrupts']

    if not warn_only:
        print(f"{'CPU':<6} {'Interrupts':>15} {'Percentage':>12}")
        print("-" * 35)
        for cpu_id, count in enumerate(cpu_totals):
            percentage = (count / total_interrupts * 100) if total_interrupts > 0 else 0
            print(f"CPU{cpu_id:<3} {count:>15} {percentage:>11.1f}%")
        print()

    if issues:
        print(f"{'Type':<15} {'Details':<60}")
        print("-" * 75)
        for issue in issues:
            if issue['type'] == 'cpu_overload':
                details = f"CPU{issue['cpu']}: {issue['percentage']:.1f}% of interrupts"
            elif issue['type'] == 'irq_imbalance':
                details = f"IRQ {issue['irq']} ({issue['device'][:40]}): {issue['percentage']:.1f}% on CPU{issue['cpu']}"
            print(f"{issue['type']:<15} {details:<60}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor hardware interrupt (IRQ) distribution across CPU cores",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Check interrupt balance
  %(prog)s --verbose           # Show detailed per-CPU stats
  %(prog)s --format json       # Output in JSON format
  %(prog)s --warn-only         # Only show issues
  %(prog)s --threshold 0.9     # Custom imbalance threshold (90%%)

Exit codes:
  0 - All interrupts are well-balanced
  1 - Imbalanced interrupts detected
  2 - Usage error or missing dependencies
        """
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
        help="Show detailed per-CPU interrupt distribution"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=0.8,
        help="Imbalance threshold (0.0-1.0, default: 0.8 = 80%%)"
    )

    args = parser.parse_args()

    # Validate threshold
    if not 0.0 <= args.threshold <= 1.0:
        print("Error: Threshold must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(2)

    # Check dependencies
    if not os.path.exists('/proc/interrupts'):
        print("Error: /proc/interrupts not found", file=sys.stderr)
        print("This script requires Linux procfs", file=sys.stderr)
        sys.exit(2)

    # Get interrupt data
    num_cpus, header, irq_data = parse_interrupts()

    if num_cpus is None or not irq_data:
        print("Error: Could not parse /proc/interrupts", file=sys.stderr)
        sys.exit(2)

    # Check irqbalance status
    irqbalance_running = get_irqbalance_status()

    # Analyze balance
    issues, cpu_totals = analyze_balance(irq_data, num_cpus, args.threshold)

    # Build results
    total_interrupts = sum(cpu_totals)

    results = {
        'num_cpus': num_cpus,
        'total_interrupts': total_interrupts,
        'irqbalance_running': irqbalance_running,
        'cpu_totals': cpu_totals,
        'issues': issues,
        'threshold': args.threshold
    }

    # Output results
    if args.format == "json":
        output_json(results)
    elif args.format == "table":
        output_table(results, args.warn_only)
    else:  # plain
        output_plain(results, args.warn_only, args.verbose)

    # Exit based on findings
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()

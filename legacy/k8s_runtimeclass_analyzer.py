#!/usr/bin/env python3
"""
Analyze Kubernetes RuntimeClass usage across workloads.

RuntimeClasses define different container runtimes (runc, kata, gVisor, etc.)
that can provide varying levels of isolation. This script helps operators
understand runtime distribution and identify potential security posture gaps.

Features:
- List all defined RuntimeClasses with their handlers
- Show which pods/namespaces use which runtimes
- Identify workloads running with the default runtime (no explicit RuntimeClass)
- Detect references to non-existent RuntimeClasses
- Provide isolation level summary across the cluster

Useful for:
- Security audits requiring workload isolation verification
- Migration planning when introducing new runtimes (kata, gVisor)
- Compliance reporting on isolation boundaries
- Capacity planning for runtime-specific node pools

Exit codes:
    0 - Analysis complete, no issues detected
    1 - Issues detected (missing RuntimeClasses, warnings)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional


def run_kubectl(args: List[str], timeout: int = 30) -> Optional[str]:
    """Execute kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: kubectl command timed out", file=sys.stderr)
        return None


def get_runtimeclasses() -> Dict[str, Dict[str, Any]]:
    """Get all RuntimeClasses in the cluster."""
    output = run_kubectl(['get', 'runtimeclasses', '-o', 'json'])
    if output is None:
        return {}

    try:
        data = json.loads(output)
        runtimeclasses = {}
        for rc in data.get('items', []):
            name = rc.get('metadata', {}).get('name', 'unknown')
            handler = rc.get('handler', name)
            scheduling = rc.get('scheduling', {})
            overhead = rc.get('overhead', {})

            runtimeclasses[name] = {
                'handler': handler,
                'node_selector': scheduling.get('nodeSelector', {}),
                'tolerations': scheduling.get('tolerations', []),
                'pod_overhead_cpu': overhead.get('podFixed', {}).get('cpu'),
                'pod_overhead_memory': overhead.get('podFixed', {}).get('memory'),
            }
        return runtimeclasses
    except json.JSONDecodeError:
        return {}


def get_pods(namespace: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all pods with their RuntimeClass information."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    if output is None:
        return []

    try:
        data = json.loads(output)
        pods = []
        for pod in data.get('items', []):
            metadata = pod.get('metadata', {})
            spec = pod.get('spec', {})

            pods.append({
                'name': metadata.get('name', 'unknown'),
                'namespace': metadata.get('namespace', 'default'),
                'runtime_class': spec.get('runtimeClassName'),
                'node': spec.get('nodeName'),
                'phase': pod.get('status', {}).get('phase', 'Unknown'),
                'owner_kind': get_owner_kind(metadata.get('ownerReferences', [])),
            })
        return pods
    except json.JSONDecodeError:
        return []


def get_owner_kind(owner_refs: List[Dict[str, Any]]) -> str:
    """Get the kind of the controller owning this pod."""
    if not owner_refs:
        return 'None'
    # Return first owner's kind (usually the direct controller)
    return owner_refs[0].get('kind', 'Unknown')


def analyze_runtime_usage(pods: List[Dict[str, Any]],
                          runtimeclasses: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze runtime class usage patterns across pods."""
    analysis = {
        'total_pods': len(pods),
        'pods_with_runtime': 0,
        'pods_without_runtime': 0,
        'by_runtime': defaultdict(list),
        'by_namespace': defaultdict(lambda: defaultdict(int)),
        'missing_runtimeclasses': [],
        'issues': [],
    }

    seen_missing = set()

    for pod in pods:
        runtime = pod['runtime_class']
        ns = pod['namespace']

        if runtime:
            analysis['pods_with_runtime'] += 1
            analysis['by_runtime'][runtime].append(pod)
            analysis['by_namespace'][ns][runtime] += 1

            # Check if RuntimeClass exists
            if runtime not in runtimeclasses and runtime not in seen_missing:
                seen_missing.add(runtime)
                analysis['missing_runtimeclasses'].append(runtime)
                analysis['issues'].append({
                    'severity': 'WARNING',
                    'message': f"RuntimeClass '{runtime}' referenced but not defined",
                    'affected_pods': [p['namespace'] + '/' + p['name']
                                      for p in pods if p['runtime_class'] == runtime][:5]
                })
        else:
            analysis['pods_without_runtime'] += 1
            analysis['by_runtime']['<default>'].append(pod)
            analysis['by_namespace'][ns]['<default>'] += 1

    # Check for namespaces with mixed runtimes (potential security boundary issue)
    for ns, runtimes in analysis['by_namespace'].items():
        if len(runtimes) > 1 and '<default>' in runtimes:
            isolation_runtimes = [r for r in runtimes if r != '<default>']
            if isolation_runtimes:
                analysis['issues'].append({
                    'severity': 'INFO',
                    'message': f"Namespace '{ns}' has mixed runtime isolation",
                    'detail': f"Some pods use {isolation_runtimes}, others use default runtime"
                })

    return analysis


def get_isolation_level(runtime: str, runtimeclasses: Dict[str, Dict[str, Any]]) -> str:
    """Determine isolation level based on runtime handler."""
    if runtime == '<default>' or runtime is None:
        return 'standard'

    if runtime not in runtimeclasses:
        return 'unknown'

    handler = runtimeclasses[runtime]['handler'].lower()

    # Categorize based on known runtime handlers
    if any(x in handler for x in ['kata', 'firecracker', 'qemu']):
        return 'vm-isolated'
    elif any(x in handler for x in ['gvisor', 'runsc']):
        return 'sandboxed'
    elif any(x in handler for x in ['youki', 'crun', 'runc']):
        return 'standard'
    else:
        return 'custom'


def format_plain(analysis: Dict[str, Any],
                 runtimeclasses: Dict[str, Dict[str, Any]],
                 verbose: bool, warn_only: bool) -> str:
    """Format output as plain text."""
    lines = []

    if not warn_only:
        lines.append("RuntimeClass Analysis")
        lines.append("=" * 60)
        lines.append(f"Total pods: {analysis['total_pods']}")
        lines.append(f"Pods with explicit RuntimeClass: {analysis['pods_with_runtime']}")
        lines.append(f"Pods using default runtime: {analysis['pods_without_runtime']}")
        lines.append("")

        # List defined RuntimeClasses
        if runtimeclasses:
            lines.append("Defined RuntimeClasses:")
            lines.append("-" * 60)
            for name, rc in sorted(runtimeclasses.items()):
                isolation = get_isolation_level(name, runtimeclasses)
                lines.append(f"  {name}")
                lines.append(f"    Handler: {rc['handler']}")
                lines.append(f"    Isolation: {isolation}")
                if rc['pod_overhead_memory']:
                    lines.append(f"    Overhead: {rc['pod_overhead_memory']} memory, "
                                 f"{rc['pod_overhead_cpu'] or 'none'} CPU")
                if rc['node_selector']:
                    lines.append(f"    Node selector: {rc['node_selector']}")
            lines.append("")

        # Usage by runtime
        lines.append("Usage by RuntimeClass:")
        lines.append("-" * 60)
        for runtime, pods in sorted(analysis['by_runtime'].items(),
                                    key=lambda x: -len(x[1])):
            isolation = get_isolation_level(runtime, runtimeclasses)
            lines.append(f"  {runtime}: {len(pods)} pods [{isolation}]")
            if verbose:
                # Show namespace breakdown
                ns_counts = defaultdict(int)
                for pod in pods:
                    ns_counts[pod['namespace']] += 1
                for ns, count in sorted(ns_counts.items(), key=lambda x: -x[1])[:5]:
                    lines.append(f"    {ns}: {count}")
                if len(ns_counts) > 5:
                    lines.append(f"    ... and {len(ns_counts) - 5} more namespaces")
        lines.append("")

    # Issues
    if analysis['issues']:
        if not warn_only:
            lines.append("Issues Detected:")
            lines.append("-" * 60)

        for issue in analysis['issues']:
            lines.append(f"[{issue['severity']}] {issue['message']}")
            if verbose:
                if 'affected_pods' in issue:
                    for pod in issue['affected_pods'][:3]:
                        lines.append(f"  - {pod}")
                    if len(issue['affected_pods']) > 3:
                        lines.append(f"  ... and {len(issue['affected_pods']) - 3} more")
                if 'detail' in issue:
                    lines.append(f"  {issue['detail']}")
        lines.append("")

    if not analysis['issues'] and not warn_only:
        lines.append("No issues detected.")

    return "\n".join(lines)


def format_json(analysis: Dict[str, Any],
                runtimeclasses: Dict[str, Dict[str, Any]]) -> str:
    """Format output as JSON."""
    output = {
        'summary': {
            'total_pods': analysis['total_pods'],
            'pods_with_runtime': analysis['pods_with_runtime'],
            'pods_without_runtime': analysis['pods_without_runtime'],
            'defined_runtimeclasses': len(runtimeclasses),
            'issue_count': len(analysis['issues']),
        },
        'runtimeclasses': {
            name: {
                **rc,
                'pod_count': len(analysis['by_runtime'].get(name, [])),
                'isolation_level': get_isolation_level(name, runtimeclasses),
            }
            for name, rc in runtimeclasses.items()
        },
        'usage_by_runtime': {
            runtime: {
                'count': len(pods),
                'isolation_level': get_isolation_level(runtime, runtimeclasses),
                'namespaces': list(set(p['namespace'] for p in pods)),
            }
            for runtime, pods in analysis['by_runtime'].items()
        },
        'issues': analysis['issues'],
    }
    return json.dumps(output, indent=2)


def format_table(analysis: Dict[str, Any],
                 runtimeclasses: Dict[str, Dict[str, Any]],
                 verbose: bool, warn_only: bool) -> str:
    """Format output as ASCII table."""
    lines = []

    if not warn_only:
        lines.append("=" * 70)
        lines.append(f"{'KUBERNETES RUNTIMECLASS ANALYSIS':^70}")
        lines.append("=" * 70)
        lines.append("")

        # Summary
        lines.append(f"{'Metric':<35} {'Value':<35}")
        lines.append("-" * 70)
        lines.append(f"{'Total Pods':<35} {analysis['total_pods']:<35}")
        lines.append(f"{'With Explicit RuntimeClass':<35} {analysis['pods_with_runtime']:<35}")
        lines.append(f"{'Using Default Runtime':<35} {analysis['pods_without_runtime']:<35}")
        lines.append(f"{'Defined RuntimeClasses':<35} {len(runtimeclasses):<35}")
        lines.append("")

        # RuntimeClasses table
        if runtimeclasses:
            lines.append("-" * 70)
            lines.append(f"{'RuntimeClass':<20} {'Handler':<20} {'Isolation':<15} {'Pods':<10}")
            lines.append("-" * 70)
            for name, rc in sorted(runtimeclasses.items()):
                isolation = get_isolation_level(name, runtimeclasses)
                pod_count = len(analysis['by_runtime'].get(name, []))
                lines.append(f"{name:<20} {rc['handler']:<20} {isolation:<15} {pod_count:<10}")

            # Add default runtime row
            default_count = len(analysis['by_runtime'].get('<default>', []))
            lines.append(f"{'<default>':<20} {'runc':<20} {'standard':<15} {default_count:<10}")
            lines.append("")

    # Issues table
    if analysis['issues']:
        if not warn_only:
            lines.append("-" * 70)
            lines.append("ISSUES")
            lines.append("-" * 70)

        lines.append(f"{'Severity':<10} {'Message':<60}")
        lines.append("-" * 70)
        for issue in analysis['issues']:
            msg = issue['message'][:58] + '..' if len(issue['message']) > 58 else issue['message']
            lines.append(f"{issue['severity']:<10} {msg:<60}")
        lines.append("")

    if not analysis['issues'] and not warn_only:
        lines.append("-" * 70)
        lines.append(f"{'NO ISSUES DETECTED':^70}")
        lines.append("-" * 70)

    return "\n".join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes RuntimeClass usage across workloads',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Analyze all pods across cluster
  %(prog)s -n production        # Analyze pods in production namespace
  %(prog)s --format json        # JSON output for automation
  %(prog)s --verbose            # Show detailed per-namespace breakdown
  %(prog)s --warn-only          # Only show issues

RuntimeClass Isolation Levels:
  vm-isolated  - Full VM isolation (kata, firecracker)
  sandboxed    - Kernel syscall filtering (gVisor)
  standard     - Standard container isolation (runc, crun)
  custom       - Custom/unknown runtime handler

Exit codes:
  0 - No issues detected
  1 - Issues detected (missing RuntimeClasses, warnings)
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to analyze (default: all namespaces)'
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
        help='Show detailed breakdown including per-namespace usage'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    args = parser.parse_args()

    # Get RuntimeClasses
    runtimeclasses = get_runtimeclasses()

    # Get pods
    pods = get_pods(args.namespace)

    if not pods:
        if args.namespace:
            print(f"No pods found in namespace '{args.namespace}'", file=sys.stderr)
        else:
            print("No pods found in cluster", file=sys.stderr)
        sys.exit(0)

    # Analyze
    analysis = analyze_runtime_usage(pods, runtimeclasses)

    # Format output
    if args.format == 'json':
        print(format_json(analysis, runtimeclasses))
    elif args.format == 'table':
        print(format_table(analysis, runtimeclasses, args.verbose, args.warn_only))
    else:
        print(format_plain(analysis, runtimeclasses, args.verbose, args.warn_only))

    # Exit code based on issues
    has_warnings = any(i['severity'] == 'WARNING' for i in analysis['issues'])
    sys.exit(1 if has_warnings else 0)


if __name__ == "__main__":
    main()

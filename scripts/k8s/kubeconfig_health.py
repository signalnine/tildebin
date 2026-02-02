#!/usr/bin/env python3
# boxctl:
#   category: k8s/config
#   tags: [kubeconfig, kubernetes, config, certificates, connectivity]
#   requires: [kubectl]
#   privilege: user
#   brief: Validate kubeconfig files and cluster connectivity
#   related: [node_health]

"""
Kubernetes kubeconfig health checker - Validate configs and connectivity.

Validates kubeconfig files and cluster connectivity:
- Certificate validity and expiration dates
- API server reachability and response time
- Authentication validity
- Context and cluster configuration
- Multiple kubeconfig file support

Exit codes:
    0 - All kubeconfig checks passed
    1 - Issues detected (expired certs, unreachable clusters, auth failures)
    2 - Usage error or missing dependencies
"""

import argparse
import base64
import json
import os
import tempfile
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_kubeconfig(kubeconfig_path: str, context: Context) -> tuple:
    """Parse kubeconfig file and return its contents."""
    try:
        result = context.run(
            [
                "kubectl",
                "config",
                "view",
                "--raw",
                "-o",
                "json",
                "--kubeconfig",
                kubeconfig_path,
            ],
            timeout=10,
        )

        if result.returncode != 0:
            return None, f"Failed to parse kubeconfig: {result.stderr}"

        return json.loads(result.stdout), None
    except json.JSONDecodeError as e:
        return None, f"Invalid kubeconfig JSON: {e}"
    except Exception as e:
        return None, str(e)


def get_certificate_expiry(cert_data_base64: str, context: Context) -> tuple:
    """Extract expiration date from base64-encoded certificate."""
    try:
        # Decode the certificate
        cert_pem = base64.b64decode(cert_data_base64).decode("utf-8")

        # Write to temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
            f.write(cert_pem)
            temp_path = f.name

        try:
            result = context.run(
                ["openssl", "x509", "-noout", "-enddate", "-in", temp_path],
                timeout=5,
            )

            if result.returncode != 0:
                return None, "Failed to parse certificate"

            # Parse the date string (format: notAfter=Mon DD HH:MM:SS YYYY GMT)
            date_str = result.stdout.strip().replace("notAfter=", "")
            # Parse various openssl date formats
            for fmt in ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"]:
                try:
                    expiry = datetime.strptime(date_str, fmt)
                    # Assume UTC for GMT timezone
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    return expiry, None
                except ValueError:
                    continue

            return None, f"Could not parse date: {date_str}"
        finally:
            os.unlink(temp_path)
    except Exception as e:
        return None, str(e)


def check_api_server_connectivity(
    kubeconfig_path: str, context_name: str, timeout_secs: int, context: Context
) -> tuple:
    """Test API server connectivity and measure response time."""
    import time

    try:
        start_time = time.time()

        result = context.run(
            [
                "kubectl",
                "cluster-info",
                "--kubeconfig",
                kubeconfig_path,
                "--context",
                context_name,
                "--request-timeout",
                f"{timeout_secs}s",
            ],
            timeout=timeout_secs + 2,
        )

        elapsed = time.time() - start_time

        if result.returncode == 0:
            return True, elapsed, None
        else:
            error = result.stderr.strip() or "Unknown error"
            return False, elapsed, error
    except Exception as e:
        return False, 0, str(e)


def check_authentication(
    kubeconfig_path: str, context_name: str, timeout_secs: int, context: Context
) -> tuple:
    """Test authentication by making a simple API call."""
    try:
        result = context.run(
            [
                "kubectl",
                "auth",
                "can-i",
                "get",
                "namespaces",
                "--kubeconfig",
                kubeconfig_path,
                "--context",
                context_name,
                "--request-timeout",
                f"{timeout_secs}s",
            ],
            timeout=timeout_secs + 2,
        )

        # can-i returns 0 for yes, 1 for no, but both mean auth worked
        # auth failure would show up in stderr
        if "error" in result.stderr.lower() or "unauthorized" in result.stderr.lower():
            return False, result.stderr.strip()
        return True, None
    except Exception as e:
        return False, str(e)


def get_cluster_version(
    kubeconfig_path: str, context_name: str, timeout_secs: int, context: Context
) -> tuple:
    """Get Kubernetes cluster version."""
    try:
        result = context.run(
            [
                "kubectl",
                "version",
                "-o",
                "json",
                "--kubeconfig",
                kubeconfig_path,
                "--context",
                context_name,
                "--request-timeout",
                f"{timeout_secs}s",
            ],
            timeout=timeout_secs + 2,
        )

        if result.returncode == 0:
            data = json.loads(result.stdout)
            server_version = data.get("serverVersion", {})
            return server_version.get("gitVersion", "unknown"), None
        return None, result.stderr.strip()
    except Exception as e:
        return None, str(e)


def analyze_kubeconfig(
    kubeconfig_path: str, check_connectivity: bool, timeout_secs: int, context: Context
) -> dict:
    """Analyze a kubeconfig file and return health information."""
    results = {
        "path": kubeconfig_path,
        "exists": context.file_exists(kubeconfig_path),
        "contexts": [],
        "issues": [],
        "warnings": [],
    }

    if not results["exists"]:
        results["issues"].append(f"Kubeconfig file not found: {kubeconfig_path}")
        return results

    # Parse the kubeconfig
    config, error = parse_kubeconfig(kubeconfig_path, context)
    if error:
        results["issues"].append(f"Failed to parse kubeconfig: {error}")
        return results

    # Get contexts, clusters, and users
    contexts = {c["name"]: c.get("context", {}) for c in config.get("contexts", [])}
    clusters = {c["name"]: c.get("cluster", {}) for c in config.get("clusters", [])}
    users = {u["name"]: u.get("user", {}) for u in config.get("users", [])}

    current_context = config.get("current-context", "")

    if not contexts:
        results["issues"].append("No contexts defined in kubeconfig")
        return results

    # Analyze each context
    for context_name, context_data in contexts.items():
        cluster_name = context_data.get("cluster", "")
        user_name = context_data.get("user", "")

        context_result = {
            "name": context_name,
            "is_current": context_name == current_context,
            "cluster": cluster_name,
            "user": user_name,
            "namespace": context_data.get("namespace", "default"),
            "server": None,
            "cert_expiry": None,
            "days_until_expiry": None,
            "connectivity": None,
            "response_time_ms": None,
            "auth_valid": None,
            "cluster_version": None,
            "issues": [],
            "warnings": [],
        }

        # Get cluster info
        cluster_info = clusters.get(cluster_name, {})
        if not cluster_info:
            context_result["issues"].append(
                f"Cluster '{cluster_name}' not found in kubeconfig"
            )
        else:
            context_result["server"] = cluster_info.get("server", "unknown")

            # Check certificate authority
            ca_data = cluster_info.get("certificate-authority-data")
            if ca_data:
                expiry, error = get_certificate_expiry(ca_data, context)
                if expiry:
                    context_result["ca_cert_expiry"] = expiry.isoformat()
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        context_result["issues"].append(
                            f"CA certificate expired {-days_left} days ago"
                        )
                    elif days_left < 7:
                        context_result["issues"].append(
                            f"CA certificate expires in {days_left} days"
                        )
                    elif days_left < 30:
                        context_result["warnings"].append(
                            f"CA certificate expires in {days_left} days"
                        )

        # Get user info and check client certificate
        user_info = users.get(user_name, {})
        if not user_info:
            context_result["issues"].append(
                f"User '{user_name}' not found in kubeconfig"
            )
        else:
            client_cert_data = user_info.get("client-certificate-data")
            if client_cert_data:
                expiry, error = get_certificate_expiry(client_cert_data, context)
                if expiry:
                    context_result["cert_expiry"] = expiry.isoformat()
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    context_result["days_until_expiry"] = days_left

                    if days_left < 0:
                        context_result["issues"].append(
                            f"Client certificate expired {-days_left} days ago"
                        )
                    elif days_left < 7:
                        context_result["issues"].append(
                            f"Client certificate expires in {days_left} days"
                        )
                    elif days_left < 30:
                        context_result["warnings"].append(
                            f"Client certificate expires in {days_left} days"
                        )
                elif error:
                    context_result["warnings"].append(
                        f"Could not check certificate: {error}"
                    )

            # Check for token-based auth
            if user_info.get("token"):
                context_result["auth_type"] = "token"
            elif user_info.get("exec"):
                context_result["auth_type"] = "exec"
            elif client_cert_data:
                context_result["auth_type"] = "certificate"
            else:
                context_result["warnings"].append(
                    "No authentication credentials found"
                )

        # Check connectivity if requested
        if check_connectivity and context_result["server"]:
            # Test API server connectivity
            connected, response_time, error = check_api_server_connectivity(
                kubeconfig_path, context_name, timeout_secs, context
            )
            context_result["connectivity"] = connected
            context_result["response_time_ms"] = round(response_time * 1000, 1)

            if not connected:
                context_result["issues"].append(
                    f"Cannot connect to API server: {error}"
                )
            elif response_time > 2:
                context_result["warnings"].append(
                    f"Slow API response: {response_time:.1f}s"
                )

            # Test authentication
            if connected:
                auth_valid, error = check_authentication(
                    kubeconfig_path, context_name, timeout_secs, context
                )
                context_result["auth_valid"] = auth_valid
                if not auth_valid:
                    context_result["issues"].append(f"Authentication failed: {error}")

                # Get cluster version
                version, error = get_cluster_version(
                    kubeconfig_path, context_name, timeout_secs, context
                )
                if version:
                    context_result["cluster_version"] = version

        results["contexts"].append(context_result)

        # Aggregate issues/warnings
        results["issues"].extend(
            [f"[{context_name}] {i}" for i in context_result["issues"]]
        )
        results["warnings"].extend(
            [f"[{context_name}] {w}" for w in context_result["warnings"]]
        )

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all checks passed, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Check kubeconfig health and cluster connectivity"
    )
    parser.add_argument(
        "--kubeconfig",
        action="append",
        dest="kubeconfigs",
        help="Kubeconfig file(s) to check (default: $KUBECONFIG or ~/.kube/config)",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--no-connectivity",
        action="store_true",
        help="Skip connectivity and authentication checks",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for connectivity checks (default: 5)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show output if issues or warnings are detected",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Determine kubeconfig files to check
    kubeconfigs = opts.kubeconfigs
    if not kubeconfigs:
        # Check KUBECONFIG environment variable
        kubeconfig_env = context.get_env("KUBECONFIG", "")
        if kubeconfig_env:
            kubeconfigs = kubeconfig_env.split(":")
        else:
            # Default location
            kubeconfigs = [os.path.expanduser("~/.kube/config")]

    # Analyze each kubeconfig
    results_list = []
    for kubeconfig_path in kubeconfigs:
        kubeconfig_path = os.path.expanduser(kubeconfig_path)
        results = analyze_kubeconfig(
            kubeconfig_path,
            check_connectivity=not opts.no_connectivity,
            timeout_secs=opts.timeout,
            context=context,
        )
        results_list.append(results)

    # Collect all issues
    all_issues = []
    all_warnings = []
    for results in results_list:
        all_issues.extend(results["issues"])
        all_warnings.extend(results["warnings"])

    # Format output
    if opts.format == "json":
        output_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kubeconfigs": results_list,
            "issues": all_issues,
            "warnings": all_warnings,
            "healthy": len(all_issues) == 0,
        }
        print(json.dumps(output_data, indent=2, default=str))

    elif opts.format == "table":
        print("+" + "-" * 98 + "+")
        print("| Kubeconfig Health Check" + " " * 74 + "|")
        print("+" + "-" * 98 + "+")
        print(
            f"| {'Context':<25} | {'Server':<30} | {'Cert Days':<10} | {'Connect':<8} | {'Auth':<8} |"
        )
        print("+" + "-" * 98 + "+")

        for results in results_list:
            if not results["exists"]:
                print(
                    f"| {results['path']:<25} | {'FILE NOT FOUND':<30} | {'':<10} | {'':<8} | {'':<8} |"
                )
                continue

            for ctx in results["contexts"]:
                name = ctx["name"][:25]
                server = (ctx["server"] or "unknown")[:30]
                days = ctx.get("days_until_expiry")
                days_str = str(days) if days is not None else "N/A"

                if ctx.get("connectivity") is not None:
                    conn = "OK" if ctx["connectivity"] else "FAIL"
                else:
                    conn = "N/A"

                if ctx.get("auth_valid") is not None:
                    auth = "OK" if ctx["auth_valid"] else "FAIL"
                else:
                    auth = "N/A"

                print(
                    f"| {name:<25} | {server:<30} | {days_str:<10} | {conn:<8} | {auth:<8} |"
                )

        print("+" + "-" * 98 + "+")

        # Issues summary
        if all_issues:
            print("| ISSUES:" + " " * 89 + "|")
            for issue in all_issues[:5]:
                issue_text = issue[:95]
                print(f"| - {issue_text:<94} |")
            if len(all_issues) > 5:
                print(
                    f"| ... and {len(all_issues) - 5} more issues" + " " * 77 + "|"
                )
            print("+" + "-" * 98 + "+")
        else:
            print("| Status: All checks passed" + " " * 72 + "|")
            print("+" + "-" * 98 + "+")

    else:  # plain format
        if not opts.warn_only or all_issues or all_warnings:
            print("Kubeconfig Health Check")
            print("=" * 60)
            print()

            for results in results_list:
                print(f"Kubeconfig: {results['path']}")
                print("-" * 60)

                if not results["exists"]:
                    print("  File not found")
                    print()
                    continue

                for ctx in results["contexts"]:
                    current_marker = " (current)" if ctx["is_current"] else ""
                    status = "OK" if not ctx["issues"] else "ISSUES"
                    print(f"  Context: {ctx['name']}{current_marker} [{status}]")
                    print(f"    Server: {ctx['server'] or 'unknown'}")
                    print(f"    Namespace: {ctx['namespace']}")

                    if ctx.get("cluster_version"):
                        print(f"    Cluster Version: {ctx['cluster_version']}")

                    if ctx.get("cert_expiry"):
                        days = ctx.get("days_until_expiry", 0)
                        if days < 0:
                            print(f"    Certificate: EXPIRED ({-days} days ago)")
                        else:
                            print(f"    Certificate: Valid ({days} days remaining)")

                    if ctx.get("connectivity") is not None:
                        status = "Connected" if ctx["connectivity"] else "Failed"
                        response_time = ctx.get("response_time_ms", 0)
                        print(f"    Connectivity: {status} ({response_time}ms)")

                    if ctx.get("auth_valid") is not None:
                        status = "Valid" if ctx["auth_valid"] else "Failed"
                        print(f"    Authentication: {status}")

                    for issue in ctx.get("issues", []):
                        print(f"    ISSUE: {issue}")

                    for warning in ctx.get("warnings", []):
                        print(f"    WARNING: {warning}")

                    print()

            # Summary
            if all_issues:
                print("ISSUES:")
                for issue in all_issues:
                    print(f"  - {issue}")
                print()

            if all_warnings:
                print("WARNINGS:")
                for warning in all_warnings:
                    print(f"  - {warning}")
                print()

            if not all_issues and not all_warnings:
                print("All kubeconfig checks passed")

    output.set_summary(
        f"kubeconfigs={len(results_list)}, issues={len(all_issues)}, warnings={len(all_warnings)}"
    )

    # Return appropriate exit code
    return 1 if all_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))

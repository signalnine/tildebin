#!/usr/bin/env python3
"""
Test runner for tildebin utilities.

This script runs all tests in the tests directory and provides
a summary of results with options for filtering and output formats.
"""

import argparse
import subprocess
import sys
import os
import time
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


def run_test(test_file, verbose=False):
    """
    Run a single test file and return results.

    Returns:
        tuple: (test_name, passed, total, duration, output)
    """
    test_name = test_file.stem.replace('test_', '')
    start_time = time.time()

    try:
        result = subprocess.run(
            [sys.executable, str(test_file)],
            capture_output=True,
            text=True,
            timeout=30
        )
        duration = time.time() - start_time

        # Parse output for test results
        output = result.stdout + result.stderr

        # Look for "Test Results: X/Y tests passed"
        passed = 0
        total = 0
        for line in output.split('\n'):
            if 'Test Results:' in line and 'tests passed' in line:
                # Extract X/Y from "Test Results: X/Y tests passed"
                parts = line.split(':')[1].strip().split('/')
                passed = int(parts[0])
                total = int(parts[1].split()[0])
                break

        return test_name, passed, total, duration, output, result.returncode
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        return test_name, 0, 0, duration, "Test timed out", -1
    except Exception as e:
        duration = time.time() - start_time
        return test_name, 0, 0, duration, str(e), -1


def main():
    parser = argparse.ArgumentParser(
        description="Run tests for tildebin utilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Run all tests
  %(prog)s -v                 # Run with verbose output
  %(prog)s -f ec2             # Run only EC2-related tests
  %(prog)s -f disk raid       # Run disk and raid tests
  %(prog)s --fail-fast        # Stop on first failure
        """
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed test output')
    parser.add_argument('-f', '--filter', nargs='+', metavar='PATTERN',
                        help='Only run tests matching pattern(s)')
    parser.add_argument('--fail-fast', action='store_true',
                        help='Stop on first test failure')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')

    args = parser.parse_args()

    # Disable colors if requested or not a TTY
    if args.no_color or not sys.stdout.isatty():
        Colors.GREEN = Colors.RED = Colors.YELLOW = Colors.BLUE = Colors.BOLD = Colors.NC = ''

    # Find all test files
    tests_dir = Path(__file__).parent
    test_files = sorted(tests_dir.glob('test_*.py'))

    if not test_files:
        print(f"{Colors.RED}No test files found in {tests_dir}{Colors.NC}")
        return 1

    # Filter test files if requested
    if args.filter:
        filtered_files = []
        for test_file in test_files:
            test_name = test_file.stem.replace('test_', '')
            if any(pattern.lower() in test_name.lower() for pattern in args.filter):
                filtered_files.append(test_file)
        test_files = filtered_files

        if not test_files:
            print(f"{Colors.YELLOW}No tests matched filter: {' '.join(args.filter)}{Colors.NC}")
            return 0

    # Run tests
    print(f"{Colors.BOLD}Running {len(test_files)} test suite(s)...{Colors.NC}")
    print("=" * 80)
    print()

    all_results = []
    total_passed = 0
    total_tests = 0
    failed_suites = []

    for test_file in test_files:
        test_name, passed, total, duration, output, returncode = run_test(test_file, args.verbose)

        all_results.append({
            'name': test_name,
            'passed': passed,
            'total': total,
            'duration': duration,
            'output': output,
            'returncode': returncode
        })

        total_passed += passed
        total_tests += total

        # Display results for this test suite
        if returncode == 0:
            status = f"{Colors.GREEN}✓ PASS{Colors.NC}"
        else:
            status = f"{Colors.RED}✗ FAIL{Colors.NC}"
            failed_suites.append(test_name)

        print(f"{status} {test_name:30} {passed}/{total} tests ({duration:.2f}s)")

        if args.verbose or returncode != 0:
            # Show test output
            for line in output.split('\n'):
                if line.strip():
                    print(f"    {line}")
            print()

        if args.fail_fast and returncode != 0:
            print()
            print(f"{Colors.YELLOW}Stopping due to --fail-fast{Colors.NC}")
            break

    # Summary
    print()
    print("=" * 80)
    print(f"{Colors.BOLD}SUMMARY{Colors.NC}")
    print()
    print(f"Test Suites: {len(test_files) - len(failed_suites)}/{len(test_files)} passed")
    print(f"Total Tests: {total_passed}/{total_tests} passed")
    print(f"Duration:    {sum(r['duration'] for r in all_results):.2f}s")

    if failed_suites:
        print()
        print(f"{Colors.RED}Failed Suites:{Colors.NC}")
        for suite in failed_suites:
            print(f"  - {suite}")

    print()

    # Exit code
    if failed_suites:
        return 1
    else:
        print(f"{Colors.GREEN}All tests passed!{Colors.NC}")
        return 0


if __name__ == "__main__":
    sys.exit(main())

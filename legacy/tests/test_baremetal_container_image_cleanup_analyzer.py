#!/usr/bin/env python3
"""
Test script for baremetal_container_image_cleanup_analyzer.py functionality.
Tests argument parsing and output formats without requiring container runtimes.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--help']
    )

    if return_code == 0 and 'container image' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_help_shows_runtimes():
    """Test that help message lists supported runtimes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--help']
    )

    has_docker = 'docker' in stdout.lower()
    has_containerd = 'containerd' in stdout.lower()
    has_podman = 'podman' in stdout.lower()

    if return_code == 0 and has_docker and has_containerd and has_podman:
        print("[PASS] Help shows all runtimes test passed")
        return True
    else:
        print(f"[FAIL] Help shows all runtimes test failed")
        print(f"  docker: {has_docker}, containerd: {has_containerd}, podman: {has_podman}")
        return False


def test_help_shows_cleanup_commands():
    """Test that help message includes cleanup command examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--help']
    )

    has_prune = 'prune' in stdout.lower()

    if return_code == 0 and has_prune:
        print("[PASS] Help shows cleanup commands test passed")
        return True
    else:
        print(f"[FAIL] Help shows cleanup commands test failed")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_runtime():
    """Test that invalid runtime choice is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--runtime', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid runtime test passed")
        return True
    else:
        print("[FAIL] Invalid runtime should fail")
        return False


def test_format_option_plain():
    """Test plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--format', 'plain', '--help']
    )

    if return_code == 0:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_option_json():
    """Test JSON format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--format', 'json', '--help']
    )

    if return_code == 0:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print(f"[FAIL] JSON format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_option_table():
    """Test table format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--format', 'table', '--help']
    )

    if return_code == 0:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_option():
    """Test verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--verbose', '--help']
    )

    if return_code == 0:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_option():
    """Test warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--warn-only', '--help']
    )

    if return_code == 0:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_storage_warn_option():
    """Test storage-warn threshold option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--storage-warn', '90', '--help']
    )

    if return_code == 0:
        print("[PASS] Storage-warn option test passed")
        return True
    else:
        print(f"[FAIL] Storage-warn option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_dangling_warn_option():
    """Test dangling-warn threshold option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--dangling-warn', '20', '--help']
    )

    if return_code == 0:
        print("[PASS] Dangling-warn option test passed")
        return True
    else:
        print(f"[FAIL] Dangling-warn option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_reclaimable_warn_option():
    """Test reclaimable-warn threshold option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--reclaimable-warn', '10', '--help']
    )

    if return_code == 0:
        print("[PASS] Reclaimable-warn option test passed")
        return True
    else:
        print(f"[FAIL] Reclaimable-warn option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_storage_threshold():
    """Test that invalid storage threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--storage-warn', '150']
    )

    if return_code == 2:
        print("[PASS] Invalid storage threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid storage threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_negative_storage_threshold():
    """Test that negative storage threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--storage-warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Negative storage threshold test passed")
        return True
    else:
        print(f"[FAIL] Negative storage threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_negative_dangling_threshold():
    """Test that negative dangling threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--dangling-warn', '-5']
    )

    if return_code == 2:
        print("[PASS] Negative dangling threshold test passed")
        return True
    else:
        print(f"[FAIL] Negative dangling threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_negative_reclaimable_threshold():
    """Test that negative reclaimable threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--reclaimable-warn', '-2']
    )

    if return_code == 2:
        print("[PASS] Negative reclaimable threshold test passed")
        return True
    else:
        print(f"[FAIL] Negative reclaimable threshold test failed")
        print(f"  Return code: {return_code}")
        return False


def test_multiple_runtimes():
    """Test specifying multiple runtimes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py',
         '--runtime', 'docker', '--runtime', 'podman', '--help']
    )

    if return_code == 0:
        print("[PASS] Multiple runtimes option test passed")
        return True
    else:
        print(f"[FAIL] Multiple runtimes option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_execution_with_docker():
    """Test execution with Docker runtime (may or may not be installed)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--runtime', 'docker']
    )

    # Exit codes 0, 1, 2 are all valid depending on Docker availability
    if return_code in [0, 1, 2]:
        print("[PASS] Execution with Docker test passed")
        return True
    else:
        print(f"[FAIL] Execution with Docker test failed")
        print(f"  Return code: {return_code}")
        return False


def test_execution_json_format():
    """Test JSON output format when runtime might not be available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py',
         '--runtime', 'docker', '--format', 'json']
    )

    # If Docker is available, should output valid JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'runtimes' in data and 'summary' in data:
                print("[PASS] JSON format execution test passed")
                return True
            else:
                print("[FAIL] JSON format missing expected keys")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON format not valid")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Docker not available - this is acceptable
        print("[PASS] JSON format execution test passed (runtime unavailable)")
        return True
    else:
        print(f"[FAIL] JSON format execution test failed")
        print(f"  Return code: {return_code}")
        return False


def test_execution_table_format():
    """Test table output format when runtime might not be available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py',
         '--runtime', 'docker', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Should contain table headers
        if 'Runtime' in stdout or 'IMAGE' in stdout or 'Dangling' in stdout:
            print("[PASS] Table format execution test passed")
            return True
        else:
            print("[FAIL] Table format missing headers")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Docker not available - this is acceptable
        print("[PASS] Table format execution test passed (runtime unavailable)")
        return True
    else:
        print(f"[FAIL] Table format execution test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py',
         '--runtime', 'docker', '--format', 'json', '--verbose',
         '--storage-warn', '95', '--dangling-warn', '5', '--reclaimable-warn', '2']
    )

    # Should succeed or fail gracefully
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Return code: {return_code}")
        return False


def test_no_runtime_detection():
    """Test behavior when no runtimes are detected."""
    # This depends on system state - just verify it doesn't crash
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py']
    )

    # Any of 0, 1, 2 is acceptable
    if return_code in [0, 1, 2]:
        print("[PASS] No runtime detection test passed")
        return True
    else:
        print(f"[FAIL] No runtime detection test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_verbose_flag():
    """Test short -v flag for verbose."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '-v', '--help']
    )

    if return_code == 0:
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Short verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_warn_only_flag():
    """Test short -w flag for warn-only."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '-w', '--help']
    )

    if return_code == 0:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_summary_fields():
    """Test that JSON output has expected summary fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py',
         '--runtime', 'docker', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            required_fields = ['total_runtimes', 'total_images', 'total_reclaimable_bytes',
                             'total_dangling_images', 'cleanup_recommended']
            missing = [f for f in required_fields if f not in summary]
            if not missing:
                print("[PASS] JSON summary fields test passed")
                return True
            else:
                print(f"[FAIL] JSON summary missing fields: {missing}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] JSON summary fields test passed (runtime unavailable)")
        return True
    else:
        print(f"[FAIL] JSON summary fields test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_code_meanings():
    """Test that script documents exit codes in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_container_image_cleanup_analyzer.py', '--help']
    )

    has_exit_codes = 'exit code' in stdout.lower() or 'exit codes' in stdout.lower()

    if return_code == 0 and has_exit_codes:
        print("[PASS] Exit code documentation test passed")
        return True
    else:
        print(f"[FAIL] Exit code documentation test failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_container_image_cleanup_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_help_shows_runtimes,
        test_help_shows_cleanup_commands,
        test_invalid_arguments,
        test_invalid_runtime,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_verbose_option,
        test_warn_only_option,
        test_storage_warn_option,
        test_dangling_warn_option,
        test_reclaimable_warn_option,
        test_invalid_storage_threshold,
        test_negative_storage_threshold,
        test_negative_dangling_threshold,
        test_negative_reclaimable_threshold,
        test_multiple_runtimes,
        test_execution_with_docker,
        test_execution_json_format,
        test_execution_table_format,
        test_combined_options,
        test_no_runtime_detection,
        test_short_verbose_flag,
        test_short_warn_only_flag,
        test_json_summary_fields,
        test_exit_code_meanings,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)

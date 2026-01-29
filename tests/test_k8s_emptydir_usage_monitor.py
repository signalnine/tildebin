#!/usr/bin/env python3
"""
Test script for k8s_emptydir_usage_monitor.py functionality.
Tests argument parsing and error handling without requiring kubectl access.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result"""
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
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--help']
    )

    if return_code == 0 and 'emptydir' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--format', 'plain']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_format_option_json():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--format', 'json']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_format_option_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--format', 'table']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_namespace_option():
    """Test that namespace option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '-n', 'default']
    )

    # Should not fail with "unrecognized arguments" error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option not recognized")
        return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--verbose']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        return False


def test_include_system_flag():
    """Test include-system flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--include-system']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Include-system flag test passed")
        return True
    else:
        print("[FAIL] Include-system flag not recognized")
        return False


def test_kubectl_missing_handling():
    """Test that missing kubectl is handled gracefully"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py']
    )

    # Should fail with exit code 2 if kubectl not available, or 0/1 if it works
    if return_code in [0, 1, 2]:
        if return_code == 2 and 'kubectl' in stderr.lower():
            print("[PASS] Kubectl missing handling test passed (kubectl not found)")
        else:
            print("[PASS] Kubectl missing handling test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_short_flags():
    """Test short flag aliases work"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '-f', 'json', '-n', 'test', '-v', '-w']
    )

    # Should not fail due to unrecognized flags
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short flags test passed")
        return True
    else:
        print("[FAIL] Short flags not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py',
         '--format', 'table', '--namespace', 'default', '--verbose',
         '--include-system']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes' in stdout:
        print("[PASS] Help documents exit codes")
        return True
    else:
        print("[FAIL] Help should document exit codes")
        return False


def test_help_contains_examples():
    """Test that help message includes examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--help']
    )

    if return_code == 0 and 'Example' in stdout:
        print("[PASS] Help contains examples")
        return True
    else:
        print("[FAIL] Help should contain examples")
        return False


def test_help_mentions_risks():
    """Test that help mentions the risks addressed"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--help']
    )

    if return_code == 0 and 'risk' in stdout.lower():
        print("[PASS] Help mentions risks")
        return True
    else:
        print("[FAIL] Help should mention risks addressed")
        return False


def test_help_mentions_sizelimit():
    """Test that help mentions sizeLimit"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--help']
    )

    if return_code == 0 and 'sizeLimit' in stdout:
        print("[PASS] Help mentions sizeLimit")
        return True
    else:
        print("[FAIL] Help should mention sizeLimit")
        return False


def test_help_mentions_tmpfs():
    """Test that help mentions tmpfs/memory backing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_emptydir_usage_monitor.py', '--help']
    )

    if return_code == 0 and ('tmpfs' in stdout.lower() or 'memory' in stdout.lower()):
        print("[PASS] Help mentions tmpfs/memory")
        return True
    else:
        print("[FAIL] Help should mention tmpfs/memory backing")
        return False


def test_script_is_executable():
    """Test that the script has proper shebang"""
    try:
        with open('k8s_emptydir_usage_monitor.py', 'r') as f:
            first_line = f.readline()
            if first_line.strip() == '#!/usr/bin/env python3':
                print("[PASS] Script has proper shebang")
                return True
            else:
                print("[FAIL] Script should have #!/usr/bin/env python3 shebang")
                return False
    except Exception as e:
        print(f"[FAIL] Could not read script: {e}")
        return False


def test_script_has_docstring():
    """Test that the script has a module docstring"""
    try:
        with open('k8s_emptydir_usage_monitor.py', 'r') as f:
            content = f.read()
            # Check for triple-quoted docstring after shebang
            if '"""' in content[:500]:
                print("[PASS] Script has docstring")
                return True
            else:
                print("[FAIL] Script should have module docstring")
                return False
    except Exception as e:
        print(f"[FAIL] Could not read script: {e}")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_emptydir_usage_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_namespace_option,
        test_verbose_flag,
        test_warn_only_flag,
        test_include_system_flag,
        test_kubectl_missing_handling,
        test_short_flags,
        test_combined_options,
        test_exit_code_validity,
        test_help_contains_exit_codes,
        test_help_contains_examples,
        test_help_mentions_risks,
        test_help_mentions_sizelimit,
        test_help_mentions_tmpfs,
        test_script_is_executable,
        test_script_has_docstring,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)

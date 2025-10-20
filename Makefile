# Makefile for tildebin utilities
#
# Common tasks for testing and development

.PHONY: test test-verbose test-ec2 test-baremetal clean help

# Default target
help:
	@echo "tildebin - Makefile targets"
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests"
	@echo "  make test-verbose      - Run all tests with verbose output"
	@echo "  make test-ec2          - Run only EC2-related tests"
	@echo "  make test-baremetal    - Run only baremetal-related tests"
	@echo "  make test-filter PATTERN=<pattern>"
	@echo "                         - Run tests matching pattern"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean             - Remove __pycache__ and temporary files"
	@echo "  make check-deps        - Check if required dependencies are installed"
	@echo ""
	@echo "Examples:"
	@echo "  make test"
	@echo "  make test-filter PATTERN=disk"
	@echo "  make test-filter PATTERN='disk raid'"

# Run all tests
test:
	@python3 tests/run_tests.py

# Run tests with verbose output
test-verbose:
	@python3 tests/run_tests.py -v

# Run only EC2-related tests
test-ec2:
	@python3 tests/run_tests.py -f ec2 listec2hosts emptysgs listvolumes terminate stop

# Run only baremetal-related tests
test-baremetal:
	@python3 tests/run_tests.py -f disk raid network system_inventory

# Run tests matching a pattern
test-filter:
	@python3 tests/run_tests.py -f $(PATTERN)

# Run a specific test
test-%:
	@python3 tests/test_$*.py

# Clean up temporary files
clean:
	@echo "Cleaning up temporary files..."
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@find . -type f -name '*.pyo' -delete 2>/dev/null || true
	@find . -type f -name '*~' -delete 2>/dev/null || true
	@echo "Done."

# Check for required dependencies
check-deps:
	@echo "Checking Python dependencies..."
	@python3 -c "import boto3" 2>/dev/null && echo "✓ boto3 installed" || echo "✗ boto3 missing (pip install boto3)"
	@echo ""
	@echo "Checking optional system tools..."
	@which smartctl >/dev/null 2>&1 && echo "✓ smartctl installed" || echo "✗ smartctl missing (for disk_health_check.py)"
	@which mdadm >/dev/null 2>&1 && echo "✓ mdadm installed" || echo "✗ mdadm missing (for software RAID in check_raid.py)"
	@which lspci >/dev/null 2>&1 && echo "✓ lspci installed" || echo "✓ lspci installed"
	@which dmidecode >/dev/null 2>&1 && echo "✓ dmidecode installed" || echo "✗ dmidecode missing (for system_inventory.py)"

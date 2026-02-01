# boxctl Makefile

.PHONY: all setup test test-cov test-verbose lint build clean install help

PYTHON := python3
PYTEST := $(PYTHON) -m pytest
VERSION := $(shell grep -Po '(?<=version = ")[^"]+' pyproject.toml 2>/dev/null || echo "0.1.0")

all: test

help:
	@echo "boxctl development commands:"
	@echo ""
	@echo "  make setup        - Set up development environment"
	@echo "  make test         - Run tests"
	@echo "  make test-cov     - Run tests with coverage report"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make lint         - Run linter (TODO)"
	@echo "  make build        - Build distribution"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make install      - Install to /opt/boxctl"
	@echo ""

setup:
	./scripts/setup-dev.sh

test:
	$(PYTEST) tests/ -v --ignore=tests/integration

test-cov:
	$(PYTEST) tests/ -v --ignore=tests/integration \
		--cov=boxctl --cov-report=term-missing --cov-fail-under=80

test-verbose:
	$(PYTEST) tests/ -vv --ignore=tests/integration

test-integration:
	$(PYTEST) tests/integration/ -v

test-all: test test-integration

lint:
	@echo "Linting not yet implemented"

build:
	./scripts/build.sh

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

install: build
	@echo "Installing boxctl to /opt/boxctl..."
	sudo mkdir -p /opt/boxctl
	sudo tar xzf dist/boxctl-$(VERSION)-linux-*.tar.gz -C /opt/boxctl --strip-components=0
	sudo ln -sf /opt/boxctl/bin/boxctl /usr/local/bin/boxctl
	@echo "Installed! Run 'boxctl --help' to verify."

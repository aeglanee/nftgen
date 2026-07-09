.PHONY: help install lint test fmt clean dev check

PYTHON := python3
VENV := .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

help:
	@echo "nftgen — Makefile targets:"
	@echo "  make install    Install dependencies and set up virtual environment"
	@echo "  make lint       Run linters (trunk check)"
	@echo "  make fmt        Format code (trunk fmt)"
	@echo "  make test       Run test suite (pytest)"
	@echo "  make check      Run lint + test (full validation)"
	@echo "  make dev        Install dependencies (venv setup)"
	@echo "  make clean      Remove build artifacts and caches"
	@echo "  make help       Show this help message"

install: $(VENV)
	@echo "Installing dependencies..."
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -e .
	$(VENV_PIP) install -e ".[test]"
	@echo "✓ Dependencies installed"

$(VENV):
	@echo "Creating virtual environment at $(VENV)..."
	$(PYTHON) -m venv $(VENV)
	@echo "✓ Virtual environment created"

lint:
	@echo "Running linters..."
	trunk check --all

fmt:
	@echo "Formatting code..."
	trunk fmt

test:
	@echo "Running tests..."
	$(VENV_PYTHON) -m pytest -q

check: lint test
	@echo "✓ All checks passed"

dev: install
	@echo "✓ Development environment ready"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".trunk" -exec rm -rf {} +
	@echo "✓ Cleaned"

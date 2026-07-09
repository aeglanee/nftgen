# Dev entry points. Targets prepend .venv/bin — activate the venv only when
# running tools directly.
VENV := .venv
export PATH := $(CURDIR)/$(VENV)/bin:$(PATH)

.DEFAULT_GOAL := help
.PHONY: help install-dev lint lint-trunk format test verify clean

# trunk's bundled TLS doesn't find the NixOS CA store on its own
export SSL_CERT_FILE ?= /etc/ssl/certs/ca-certificates.crt

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "%-14s %s\n", $$1, $$2}'

install-dev: ## Create .venv, install nftgen (editable) + dev tools, wire pre-commit
	python3 -m venv $(VENV)
	pip install -U pip
	pip install -e '.[dev]'
	pre-commit install

lint: ## All linters: ruff, yamllint, markdownlint, whitespace, gitleaks
	ruff check .
	ruff format --check .
	yamllint .
	pre-commit run --all-files markdownlint
	pre-commit run --all-files end-of-file-fixer
	pre-commit run --all-files trailing-whitespace
	pre-commit run --all-files gitleaks

lint-trunk: ## Optional breadth sweep via trunk (requires trunk CLI; not in verify)
	@if command -v trunk >/dev/null 2>&1; then \
		trunk check --all; \
	else \
		echo "trunk is not installed (nixpkgs: trunk-io, unfree). See https://trunk.io"; \
		exit 1; \
	fi

format: ## Auto-fix: ruff + markdownlint
	ruff check --fix .
	ruff format .
	pre-commit run --all-files markdownlint || true

test: ## Run the test suite
	pytest

verify: lint test ## Lint + tests — must be green before every commit

clean: ## Remove build/test artifacts
	rm -rf dist build .pytest_cache

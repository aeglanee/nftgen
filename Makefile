# Dev entry points. Targets prepend .venv/bin — activate the venv only when
# running tools directly.
VENV := .venv
export PATH := $(CURDIR)/$(VENV)/bin:$(PATH)

.DEFAULT_GOAL := help
.PHONY: help install-dev lint format test verify clean

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

format: ## Auto-fix: ruff + markdownlint
	ruff check --fix .
	ruff format .
	pre-commit run --all-files markdownlint || true

test: ## Run the test suite
	pytest

verify: lint test ## Lint + tests — must be green before every commit

clean: ## Remove build/test artifacts
	rm -rf dist build .pytest_cache

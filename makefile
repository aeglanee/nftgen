include tools.mk

export PATH := $(CURDIR)/.venv/bin:$(PATH)

SANDBOX := docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL \
	--security-opt no-new-privileges --user $(shell id -u):$(shell id -g) --env HOME=/tmp --workdir /src
CHECK := $(SANDBOX) --volume "$(CURDIR):/src:ro"
FIX := $(SANDBOX) --volume "$(CURDIR):/src"

GIT_COMMON_DIR := $(shell git rev-parse --path-format=absolute --git-common-dir)
TEXT := $(shell git grep -I --name-only -e '')
YAML := $(filter %.yml %.yaml,$(TEXT))
MARKDOWN := $(filter-out CHANGELOG.md,$(filter %.md,$(TEXT)))

.PHONY: deps lint files actions secrets renovate markdown checkov trivy yaml python links hooks test format verify clean

.venv/bin/pytest: pyproject.toml uv.lock
	uv venv --allow-existing .venv
	uv export --frozen --no-header --no-emit-project --format requirements-txt | uv pip sync --python .venv/bin/python --require-hashes -
	uv pip install --python .venv/bin/python --no-deps -e .
	touch $@

deps: .venv/bin/pytest

lint: files actions secrets renovate markdown checkov trivy yaml python links

files:
	$(CHECK) --volume "$(GIT_COMMON_DIR):$(GIT_COMMON_DIR):ro" $(PRE_COMMIT_HOOKS) check-merge-conflict $(TEXT)
	$(CHECK) $(PRE_COMMIT_HOOKS) check-yaml $(YAML)
	$(FIX) $(PRE_COMMIT_HOOKS) end-of-file-fixer $(TEXT)
	$(FIX) $(PRE_COMMIT_HOOKS) trailing-whitespace-fixer $(TEXT)

actions:
	$(CHECK) $(ACTIONLINT)
	$(CHECK) $(ZIZMOR) .

secrets:
	$(CHECK) $(GITLEAKS) dir --redact --no-banner .

renovate:
	$(CHECK) $(RENOVATE_CONFIG_VALIDATOR) --strict renovate.json

markdown:
	$(CHECK) $(MARKDOWNLINT) $(MARKDOWN)

checkov:
	$(CHECK) $(CHECKOV) --directory . --framework github_actions secrets --skip-path '\.venv' --quiet --compact --skip-download

trivy:
	$(CHECK) $(TRIVY) filesystem --scanners secret,misconfig --severity HIGH,CRITICAL --exit-code 1 \
		--skip-db-update --skip-check-update --offline-scan --skip-dirs .venv --quiet .

yaml:
	$(CHECK) $(YAMLLINT) $(YAML)

python:
	$(CHECK) $(RUFF) check .
	$(CHECK) $(RUFF) format --check .

links:
	$(CHECK) $(LYCHEE) --no-progress --config .lychee.toml $(filter %.md,$(TEXT))

# Runs make lint before every push.
hooks:
	git config core.hooksPath .githooks

test: deps
	pytest

format:
	$(FIX) $(RUFF) check --fix .
	$(FIX) $(RUFF) format .

verify: lint test

clean:
	rm -rf dist build .pytest_cache

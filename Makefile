# Optional convenience targets. Everything here also works without make:
# see CONTRIBUTING.md or run `python scripts/check.py`.

PYTHON ?= python

.PHONY: install lint format typecheck test build audit check

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

typecheck:
	$(PYTHON) -m mypy --strict src/egressveil

test:
	$(PYTHON) -m pytest -q

build:
	$(PYTHON) -m build

audit:
	$(PYTHON) -m pip_audit --skip-editable

check:
	$(PYTHON) scripts/check.py --build

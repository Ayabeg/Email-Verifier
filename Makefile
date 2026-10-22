.PHONY: setup test lint check demo serve

VENV := .venv
PYTHON := $(VENV)/bin/python
CLI := $(VENV)/bin/email-verifier

setup:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest

lint:
	$(VENV)/bin/ruff check .

check: test lint

demo:
	./scripts/demo.sh

serve:
	$(PYTHON) -m email_verifier.web --host 127.0.0.1 --port 8000

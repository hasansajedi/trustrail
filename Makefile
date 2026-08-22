.PHONY: install lint format typecheck test test-unit test-integration test-security test-property ci clean build audit

install:
	pip install -e ".[dev,all]"
	pre-commit install

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

format-check:
	ruff format --check src/ tests/

typecheck:
	mypy src/

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-security:
	pytest tests/security/ -v

test-property:
	pytest tests/property/ -v

test-cov:
	pytest tests/ --cov=trustrail --cov-report=html

ci: format-check lint typecheck test

audit:
	pip-audit

clean:
	rm -rf dist/ build/ .mypy_cache/ .pytest_cache/ .ruff_cache/ htmlcov/ coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

build:
	python -m build

release: ci build
	twine upload dist/*

# Contributing to trustrail

Thank you for your interest in contributing to trustrail!

## Development Setup

```bash
git clone https://github.com/hasansajedi/trustrail.git
cd trustrail
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,all]"
pre-commit install
```

## Running Tests

```bash
make test           # Run all tests
make test-unit      # Unit tests only
make test-security  # Security corpus tests
make lint           # Lint checks
make typecheck      # MyPy type checking
```

## Code Style

- We use `ruff` for formatting and linting
- We use `mypy --strict` for type checking
- All new code must have type annotations
- No `eval`, `exec`, `pickle`, or shell execution

## Pull Request Process

1. Fork the repository and create a feature branch
2. Write tests for your changes
3. Ensure all tests pass: `make ci`
4. Update documentation if needed
5. Submit a pull request

## Security Issues

Please do NOT open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

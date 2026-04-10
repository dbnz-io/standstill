# Contributing to standstill

## Getting started

```bash
git clone https://github.com/dbnz-io/standstill
cd standstill
pip install -e ".[dev]"
```

## Running tests

Tests mock all AWS calls — no real AWS account or credentials required.

```bash
pytest
pytest --cov=standstill --cov-report=term-missing
```

## Linting

```bash
ruff check .
ruff format .
```

## Pull requests

- Open an issue first for any non-trivial change so we can align on approach before you invest time writing code.
- Keep PRs focused. One logical change per PR.
- All tests must pass. Coverage should not decrease.
- Follow the existing code style — Ruff enforces it.

## Adding or updating controls

The control catalog lives in `standstill/data/controls_catalog.yaml`. If Control Tower ships new controls, run:

```bash
standstill catalog build
```

This refreshes the catalog from the live Control Tower API. Commit the updated file.

## Reporting bugs

Use [GitHub Issues](https://github.com/dbnz-io/standstill/issues). Include:

- The command you ran (redact account IDs and ARNs if needed)
- The full error output
- Your AWS region and Control Tower version if known

## Security issues

Do not open a GitHub issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).

# Contributing

## Development setup

```bash
git clone https://github.com/umaryaseen/aws-cost-forensics.git
cd aws-cost-forensics
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Running checks

```bash
ruff check src/ tests/
ruff format src/ tests/
mypy src/
pytest tests/ -m "not integration"
```

## Branches

Never commit to `main` directly. Open a pull request from a feature branch.

## Commit style

Conventional commits: `feat:`, `fix:`, `chore:`, `test:`, `docs:`, `refactor:`.

## Security

Do not commit AWS credentials, session tokens, account IDs, or scan artifacts containing real infrastructure identifiers. See [SECURITY.md](SECURITY.md).

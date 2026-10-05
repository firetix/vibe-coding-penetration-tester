# Contributing

Start with a reproducible authorization case or an onboarding problem.
Useful contributions include framework fixtures, failed controls, and report compatibility fixes.

For the new runner:

```sh
uv sync --extra dev
uv run ruff check vibe_pentest guard_tests examples/fastapi
uv run ruff format --check vibe_pentest guard_tests examples/fastapi
uv run pytest guard_tests -q -o addopts='' -o log_cli=false
uv run --with fastapi --with uvicorn python examples/fastapi/verify.py
uv build
```

Add a broken and a fixed fixture for a new security behavior.
Include an invalid-control case so failures cannot create false reassurance.
Keep model and browser dependencies outside the base package.
Never include real tokens, private records, or unauthorized targets in tests or reports.

Run the legacy suites separately when changing the original scanner.
See [legacy setup](docs/legacy-scanner.md) and [test documentation](tests/README.md).

The repository uses Apache-2.0. Keep contribution examples compatible with that license.

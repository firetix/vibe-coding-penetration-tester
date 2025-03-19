# VibePenTester Test Suite

This directory contains the comprehensive test suite for the VibePenTester project.

## Test Structure

- **Unit Tests**: Located in the `unit/` directory, these tests validate individual components in isolation.
- **Integration Tests**: Located in the `integration/` directory, these tests validate the interactions between components.

## Running Tests

You can run the tests using the provided `run_tests.sh` script in the project root:

```bash
./run_tests.sh
```

Or run specific test categories with pytest directly:

```bash
# Run all tests
pytest

# Run only unit tests
pytest tests/unit

# Run only integration tests
pytest tests/integration

# Run with coverage
pytest --cov=core --cov=agents --cov=tools --cov=utils
```

## Test Configuration

The test suite uses the following configuration:

- `conftest.py`: Contains shared fixtures and test setup
- `pytest.ini`: Contains pytest configuration settings

## Mocks and Fixtures

The test suite uses various mocks and fixtures to simulate the behavior of:

- LLM API responses (OpenAI and Anthropic)
- Browser interactions via Playwright
- Tool function calls and responses
- File system operations
- Network interactions

## Adding New Tests

When adding new tests, follow these guidelines:

1. For unit tests, test a single function or method in isolation
2. For integration tests, test the interaction between multiple components
3. Use appropriate mocks to avoid external dependencies
4. Follow the Arrange-Act-Assert pattern for test structure
5. Add meaningful assertions that validate both the result and the behavior

## Code Coverage

Code coverage reports are generated when running the tests with the `--cov` option.
The coverage reports can be viewed as:

- Terminal output (default)
- HTML report (generated with `--cov-report=html`)
- XML report for CI integration (generated with `--cov-report=xml`)
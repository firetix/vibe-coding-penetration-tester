#!/bin/bash

# Run unit tests with coverage
echo "Running unit tests with coverage..."
python -m pytest tests/unit -v --cov=core --cov=agents --cov=tools --cov=utils --cov-report=term-missing

# Run integration tests
echo -e "\nRunning integration tests..."
python -m pytest tests/integration -v

# Run E2E API critical suite
echo -e "\nRunning E2E API critical tests..."
python -m pytest tests/e2e/api -m e2e_api_critical -v

# Run frontend smoke E2E suite
echo -e "\nRunning frontend smoke E2E tests..."
python -m pytest tests/e2e/frontend -m e2e_frontend_smoke -v

# Generate coverage report
echo -e "\nGenerating coverage report..."
python -m pytest --cov-report=html

echo -e "\nTests completed. View HTML coverage report in htmlcov/index.html"

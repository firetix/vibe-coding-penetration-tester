#!/bin/bash

# Run unit tests with coverage
echo "Running unit tests with coverage..."
python -m pytest tests/unit -v --cov=core --cov=agents --cov=tools --cov=utils --cov-report=term-missing

# Run integration tests
echo -e "\nRunning integration tests..."
python -m pytest tests/integration -v

# Generate coverage report
echo -e "\nGenerating coverage report..."
python -m pytest --cov-report=html

echo -e "\nTests completed. View HTML coverage report in htmlcov/index.html"
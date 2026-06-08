# Use Python 3.10 slim image as base
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install build dependencies and curl for healthcheck
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install the package in editable mode
RUN pip install --no-cache-dir -e ".[dev]"

# Expose the port
EXPOSE 8000

# Run the server with SSE transport
CMD ["mcp-simple-tool", "--transport", "sse", "--port", "8000"] 
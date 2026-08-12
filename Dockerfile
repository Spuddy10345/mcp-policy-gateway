# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

# Set the working directory
WORKDIR /app

# Copy the dependency files
COPY pyproject.toml uv.lock ./
COPY src/ src/
COPY README.md ./

# Install the project and its dependencies into a virtual environment
RUN uv sync --no-dev --frozen

# Create a clean, lightweight runtime image
FROM python:3.12-slim-bookworm

# Add a non-root user for security
RUN groupadd -r gateway && useradd -r -g gateway gateway

# Set the working directory
WORKDIR /app

# Copy the virtual environment and source from the builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src

# Ensure the virtual environment's bin directory is in the PATH
ENV PATH="/app/.venv/bin:$PATH"

# Switch to the non-root user
USER gateway

# Expose the default port for HTTP transport
EXPOSE 8000

# The default command runs the gateway
ENTRYPOINT ["mcp-policy-gateway"]

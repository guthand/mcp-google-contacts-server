FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster dependency management
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml uv.lock requirements.txt ./
COPY mcp_google_contacts_server ./mcp_google_contacts_server/

# Install Python dependencies using uv
RUN uv pip install --system -r requirements.txt

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app

# Create credentials directory with proper permissions
RUN mkdir -p /app/credentials \
    && chown -R app:app /app/credentials \
    && chmod 755 /app/credentials

USER app

# Expose port (use default of 8000 if PORT not set)
EXPOSE 8000
# Expose additional port if PORT environment variable is set to a different value
ARG PORT
EXPOSE ${PORT:-8000}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/ || exit 1

# Set environment variables for configuration
ENV TRANSPORT_MODE=http
ENV STATELESS_MODE=true
ENV PORT=8000

# Run the server with HTTP transport (stateless mode)
CMD ["sh", "-c", "python -m mcp_google_contacts_server.main --transport http --host 0.0.0.0 --port ${PORT}"]

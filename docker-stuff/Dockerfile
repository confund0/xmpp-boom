FROM python:3.11-alpine

# Install build dependencies for slixmpp (needs libxml2)
RUN apk add --no-cache \
    libxml2-dev \
    libxslt-dev \
    gcc \
    musl-dev \
    python3-dev \
    && pip install --no-cache-dir --upgrade pip

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Remove build dependencies to keep image small
RUN apk del gcc musl-dev python3-dev

# Copy application files
COPY alertpusher.py .
COPY xmpp_muc.py .

# Create directories for logs and certs
RUN mkdir -p /app/logs /app/certs

# Run as non-root user
RUN adduser -D -u 1000 alertpusher && \
    chown -R alertpusher:alertpusher /app

USER alertpusher

# Expose HTTP port (default 8080, configurable via config.yaml)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["python", "-u", "alertpusher.py", "-c", "/app/config.yaml"]

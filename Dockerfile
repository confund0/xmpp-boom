# Builder stage
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    libxeddsa-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create virtual environment
RUN python -m venv /app/venv

# Upgrade pip
RUN /app/venv/bin/pip install --no-cache-dir --upgrade pip

# Copy requirements and install dependencies
COPY requirements.txt .
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Final stage - minimal runtime image
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxeddsa2t64 \
    libxml2 \
    libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/venv /app/venv

# Copy application files and certs directory (recursive)
COPY xmpp-boom.py xmpp_muc.py xmpp-boom-omemo.py xmpp_muc_omemo.py config.yaml ./
#COPY certs* ./

# Create directories and user
RUN mkdir -p /app/logs && \
    adduser --disabled-password --uid 1000 --gecos "" alertpusher && \
    chown -R alertpusher:alertpusher /app

USER alertpusher

# Expose HTTP port (default 8080, configurable via config.yaml)
EXPOSE 8111

# Health check !!! DISABLE FROM SWARM !!!
# HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
#     CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application with virtual environment
CMD ["/app/venv/bin/python", "-u", "xmpp-boom-omemo.py", "-c", "/app/config.yaml"]

# PQC-Monitor — Dockerfile
# SPDX-License-Identifier: GPL-3.0-or-later
# AI-assisted development: portions generated with Claude (Anthropic)
#
# Build:  docker build -t pqc-monitor .
# Run:    docker run -p 5000:5000 -v $(pwd)/data:/app/data pqc-monitor
# Seed:   docker run pqc-monitor python3 tests/seed_demo_data.py

FROM python:3.12-slim

LABEL maintainer="PQC-Monitor Contributors"
LABEL description="Post-Quantum Cryptography Readiness Monitor"
LABEL license="GPL-3.0-or-later"

# Install nmap for optional service discovery
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data dirs
RUN mkdir -p data/scans data/trends

# Expose dashboard port
EXPOSE 5000

ENV PYTHONUNBUFFERED=1

# Default: run dashboard
CMD ["python3", "pqc_monitor.py", "dashboard", "--", "--host", "0.0.0.0"]

FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    chromium \
    chromium-driver \
    golang-go \
    cargo \
    rustc \
    nmap \
    dnsutils \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Build Go + Rust binaries
RUN bash setup.sh 2>/dev/null || true

# Create dirs
RUN mkdir -p reports investigations screenshots logs evidence

# Non-root user
RUN useradd -m sentinel && chown -R sentinel:sentinel /app
USER sentinel

ENV PYTHONUNBUFFERED=1
ENV OSINT_LOG_LEVEL=INFO

ENTRYPOINT ["python3", "main.py"]

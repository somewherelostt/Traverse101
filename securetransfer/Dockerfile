# Production server for secure file transfer
FROM python:3.12-slim

WORKDIR /app

# Install dependencies and package
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY setup.py .
COPY securetransfer ./securetransfer
RUN pip install --no-cache-dir -e .

# Create non-root user and writable dirs for received files, logs, and DB
RUN adduser --disabled-password --gecos "" appuser \
    && mkdir -p /app/received /app/logs /app/data \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 9000

# Receive server: bind 0.0.0.0, port 9000; output and logs via env or volumes
CMD ["securetransfer", "receive", "--host", "0.0.0.0", "--port", "9000", "--output-dir", "/app/received"]

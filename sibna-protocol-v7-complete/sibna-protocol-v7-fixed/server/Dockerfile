# Sibna Relay Server Dockerfile

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    pydantic==2.5.3 \
    cryptography==42.0.0 \
    requests==2.31.0

# Copy server code
COPY main.py .

# Create non-root user
RUN useradd -m -s /bin/bash sibna && \
    mkdir -p /data && \
    chown -R sibna:sibna /app /data

USER sibna

ENV SIBNA_DB_PATH=/data/relay.db
ENV LOG_LEVEL=info

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

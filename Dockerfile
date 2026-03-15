FROM python:3.11-slim

# nmap wymagany przez collector (OS fingerprinting, port scan)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap iputils-ping ffmpeg postgresql-client && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium --with-deps

COPY . .

# Domyslny CMD � nadpisywany w docker-compose per serwis
CMD ["uvicorn", "netdoc.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

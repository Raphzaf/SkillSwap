# backend/Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Outils de build (cryptography, motor, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Dépendances
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code
COPY backend/ .

# Port
ENV PORT=8001
EXPOSE 8001

# Uvicorn
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]

# backend/Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# ⬇️ Copie seulement requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ⬇️ Puis copie tout le backend
COPY . .

ENV PORT=8001
EXPOSE 8001

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]

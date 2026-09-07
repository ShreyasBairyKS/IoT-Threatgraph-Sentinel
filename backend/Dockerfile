# Build from the repo root so this can COPY requirements.txt and the
# backend/ package in one context:
#   docker build -f backend/Dockerfile -t threatgraph-backend .
#   docker run -p 8000:8000 threatgraph-backend
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend

EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
